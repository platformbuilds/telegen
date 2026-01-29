// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// MySQL/MariaDB Client/Server Protocol Tracer
// Traces MySQL queries via mysql client library uprobes

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/tp_info.h>
#include <pid/pid_helpers.h>

// ============================================================================
// MySQL Protocol Constants
// ============================================================================

// Command types (COM_*)
#define COM_SLEEP              0x00
#define COM_QUIT               0x01
#define COM_INIT_DB            0x02
#define COM_QUERY              0x03
#define COM_FIELD_LIST         0x04
#define COM_CREATE_DB          0x05
#define COM_DROP_DB            0x06
#define COM_REFRESH            0x07
#define COM_SHUTDOWN           0x08
#define COM_STATISTICS         0x09
#define COM_PROCESS_INFO       0x0a
#define COM_CONNECT            0x0b
#define COM_PROCESS_KILL       0x0c
#define COM_DEBUG              0x0d
#define COM_PING               0x0e
#define COM_TIME               0x0f
#define COM_DELAYED_INSERT     0x10
#define COM_CHANGE_USER        0x11
#define COM_BINLOG_DUMP        0x12
#define COM_TABLE_DUMP         0x13
#define COM_CONNECT_OUT        0x14
#define COM_REGISTER_SLAVE     0x15
#define COM_STMT_PREPARE       0x16
#define COM_STMT_EXECUTE       0x17
#define COM_STMT_SEND_LONG_DATA 0x18
#define COM_STMT_CLOSE         0x19
#define COM_STMT_RESET         0x1a
#define COM_SET_OPTION         0x1b
#define COM_STMT_FETCH         0x1c
#define COM_DAEMON             0x1d
#define COM_BINLOG_DUMP_GTID   0x1e
#define COM_RESET_CONNECTION   0x1f

// Response packet types
#define MYSQL_OK_PACKET        0x00
#define MYSQL_EOF_PACKET       0xFE
#define MYSQL_ERR_PACKET       0xFF

// Server status flags
#define SERVER_STATUS_IN_TRANS         0x0001
#define SERVER_STATUS_AUTOCOMMIT       0x0002
#define SERVER_MORE_RESULTS_EXISTS     0x0008
#define SERVER_STATUS_NO_GOOD_INDEX    0x0010
#define SERVER_STATUS_NO_INDEX         0x0020
#define SERVER_STATUS_CURSOR_EXISTS    0x0040
#define SERVER_STATUS_LAST_ROW_SENT    0x0080
#define SERVER_STATUS_DB_DROPPED       0x0100
#define SERVER_STATUS_NO_BACKSLASH     0x0200
#define SERVER_STATUS_METADATA_CHANGED 0x0400
#define SERVER_QUERY_WAS_SLOW          0x0800
#define SERVER_PS_OUT_PARAMS           0x1000

// ============================================================================
// Query Types
// ============================================================================

#define QUERY_TYPE_UNKNOWN     0
#define QUERY_TYPE_SELECT      1
#define QUERY_TYPE_INSERT      2
#define QUERY_TYPE_UPDATE      3
#define QUERY_TYPE_DELETE      4
#define QUERY_TYPE_DDL         5
#define QUERY_TYPE_TRANSACTION 6
#define QUERY_TYPE_OTHER       7

// ============================================================================
// Buffer Sizes
// ============================================================================

#define MYSQL_QUERY_MAX_LEN    2048
#define MYSQL_DATABASE_MAX_LEN 64
#define MYSQL_USER_MAX_LEN     64
#define MYSQL_SQL_STATE_LEN    6
#define MYSQL_ERROR_MSG_MAX_LEN 256

// ============================================================================
// Event Type for Ring Buffer
// ============================================================================

#define EVENT_TYPE_MYSQL_QUERY 21  // MySQL query event

// ============================================================================
// MySQL Query Event
// ============================================================================

struct mysql_event {
    u8  type;                           // Event type marker
    u8  command;                        // MySQL command type (COM_*)
    u8  query_type;                     // Query classification
    u8  flags;                          // Flags
    u16 server_status;                  // Server status flags
    u16 error_code;                     // MySQL error code
    
    u64 timestamp;                      // Event timestamp (ns)
    u64 latency_ns;                     // Query latency (ns)
    
    pid_info pid;                       // Process info
    
    // Connection info
    connection_info_t conn;
    u32 connection_id;                  // MySQL connection ID
    s32 fd;
    
    // Query info
    u32 query_len;
    u32 _pad;
    char query[MYSQL_QUERY_MAX_LEN];
    
    // Prepared statement info
    u32 stmt_id;                        // Statement ID
    u16 num_params;                     // Number of parameters
    u16 num_columns;                    // Number of columns
    
    // Results
    u64 affected_rows;
    u64 last_insert_id;
    u32 warning_count;
    u32 rows_returned;
    
    // Error info
    char sql_state[MYSQL_SQL_STATE_LEN];
    u8  _pad2[2];
    char error_message[MYSQL_ERROR_MSG_MAX_LEN];
    
    // Connection metadata
    char database[MYSQL_DATABASE_MAX_LEN];
    char user[MYSQL_USER_MAX_LEN];
    
    // Trace context
    tp_info_t tp;
};

// ============================================================================
// Query State Tracking
// ============================================================================

struct mysql_query_state {
    u64 start_time;
    u8  command;
    u8  query_type;
    u8  is_prepared;
    u8  _pad;
    u32 query_len;
    u32 stmt_id;
    char query[MYSQL_QUERY_MAX_LEN];
};

// ============================================================================
// Prepared Statement Cache
// ============================================================================

struct mysql_stmt_info {
    u32 stmt_id;
    u8  query_type;
    u8  _pad[3];
    u32 query_len;
    char query[MYSQL_QUERY_MAX_LEN];
};

// ============================================================================
// BPF Maps
// ============================================================================

// Track active queries by pid_tgid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct mysql_query_state));
    __uint(max_entries, 10000);
} mysql_queries SEC(".maps");

// Cache prepared statements by (pid_tgid << 32 | stmt_id)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct mysql_stmt_info));
    __uint(max_entries, 50000);
} mysql_stmts SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);  // 64MB
} mysql_events SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// Classify query type from SQL text
static __always_inline u8 mysql_classify_query(const char *query) {
    // Skip leading whitespace
    int i = 0;
    #pragma unroll
    for (; i < 10 && (query[i] == ' ' || query[i] == '\t' || query[i] == '\n'); i++);
    
    // Check first 3 characters (lowercase)
    char c1 = query[i] | 0x20;
    char c2 = query[i+1] | 0x20;
    char c3 = query[i+2] | 0x20;
    
    if (c1 == 's' && c2 == 'e' && c3 == 'l') return QUERY_TYPE_SELECT;
    if (c1 == 'i' && c2 == 'n' && c3 == 's') return QUERY_TYPE_INSERT;
    if (c1 == 'u' && c2 == 'p' && c3 == 'd') return QUERY_TYPE_UPDATE;
    if (c1 == 'd' && c2 == 'e' && c3 == 'l') return QUERY_TYPE_DELETE;
    if (c1 == 'b' && c2 == 'e' && c3 == 'g') return QUERY_TYPE_TRANSACTION;
    if (c1 == 's' && c2 == 't' && c3 == 'a') return QUERY_TYPE_TRANSACTION;  // START
    if (c1 == 'c' && c2 == 'o' && c3 == 'm') return QUERY_TYPE_TRANSACTION;
    if (c1 == 'r' && c2 == 'o' && c3 == 'l') return QUERY_TYPE_TRANSACTION;
    if (c1 == 'c' && c2 == 'r' && c3 == 'e') return QUERY_TYPE_DDL;
    if (c1 == 'a' && c2 == 'l' && c3 == 't') return QUERY_TYPE_DDL;
    if (c1 == 'd' && c2 == 'r' && c3 == 'o') return QUERY_TYPE_DDL;
    if (c1 == 's' && c2 == 'h' && c3 == 'o') return QUERY_TYPE_OTHER;  // SHOW
    if (c1 == 's' && c2 == 'e' && c3 == 't') return QUERY_TYPE_OTHER;  // SET
    if (c1 == 'u' && c2 == 's' && c3 == 'e') return QUERY_TYPE_OTHER;  // USE
    
    return QUERY_TYPE_OTHER;
}

// Emit a MySQL event to the ring buffer
static __always_inline int mysql_emit_event(struct mysql_query_state *state, int has_error, u16 error_code) {
    struct mysql_event *event = bpf_ringbuf_reserve(&mysql_events, sizeof(*event), 0);
    if (!event) {
        return -1;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event->type = EVENT_TYPE_MYSQL_QUERY;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->command = state->command;
    event->query_type = state->query_type;
    event->query_len = state->query_len;
    event->stmt_id = state->stmt_id;
    
    // Copy query
    __builtin_memcpy(event->query, state->query, sizeof(event->query));
    
    // Set process info
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    // Flags
    if (state->is_prepared) {
        event->flags |= 0x01;  // Prepared statement flag
    }
    if (has_error) {
        event->flags |= 0x02;  // Error flag
        event->error_code = error_code;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// MySQL Client Library Probes
// ============================================================================

// mysql_real_query - Execute a SQL query
SEC("uprobe/mysql_real_query")
int trace_mysql_real_query(struct pt_regs *ctx) {
    void *mysql = (void *)PT_REGS_PARM1(ctx);
    const char *query = (const char *)PT_REGS_PARM2(ctx);
    unsigned long length = PT_REGS_PARM3(ctx);
    
    if (!query || length == 0) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.command = COM_QUERY;
    state.is_prepared = 0;
    
    // Clamp length to buffer size
    u32 copy_len = length;
    if (copy_len > sizeof(state.query) - 1) {
        copy_len = sizeof(state.query) - 1;
    }
    
    bpf_probe_read_user(state.query, copy_len, query);
    state.query_len = copy_len;
    state.query_type = mysql_classify_query(state.query);
    
    bpf_map_update_elem(&mysql_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// mysql_real_query return probe
SEC("uretprobe/mysql_real_query")
int trace_mysql_real_query_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state *state = bpf_map_lookup_elem(&mysql_queries, &pid_tgid);
    if (!state) return 0;
    
    mysql_emit_event(state, (ret != 0), 0);
    
    bpf_map_delete_elem(&mysql_queries, &pid_tgid);
    return 0;
}

// mysql_query - Simple query interface
SEC("uprobe/mysql_query")
int trace_mysql_query(struct pt_regs *ctx) {
    void *mysql = (void *)PT_REGS_PARM1(ctx);
    const char *query = (const char *)PT_REGS_PARM2(ctx);
    
    if (!query) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.command = COM_QUERY;
    state.is_prepared = 0;
    
    int ret = bpf_probe_read_user_str(state.query, sizeof(state.query), query);
    if (ret > 0) {
        state.query_len = ret - 1;
    }
    state.query_type = mysql_classify_query(state.query);
    
    bpf_map_update_elem(&mysql_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// mysql_query return probe
SEC("uretprobe/mysql_query")
int trace_mysql_query_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state *state = bpf_map_lookup_elem(&mysql_queries, &pid_tgid);
    if (!state) return 0;
    
    mysql_emit_event(state, (ret != 0), 0);
    
    bpf_map_delete_elem(&mysql_queries, &pid_tgid);
    return 0;
}

// mysql_stmt_prepare - Prepare a statement
SEC("uprobe/mysql_stmt_prepare")
int trace_mysql_stmt_prepare(struct pt_regs *ctx) {
    void *stmt = (void *)PT_REGS_PARM1(ctx);
    const char *query = (const char *)PT_REGS_PARM2(ctx);
    unsigned long length = PT_REGS_PARM3(ctx);
    
    if (!query || length == 0) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.command = COM_STMT_PREPARE;
    state.is_prepared = 1;
    
    u32 copy_len = length;
    if (copy_len > sizeof(state.query) - 1) {
        copy_len = sizeof(state.query) - 1;
    }
    
    bpf_probe_read_user(state.query, copy_len, query);
    state.query_len = copy_len;
    state.query_type = mysql_classify_query(state.query);
    
    bpf_map_update_elem(&mysql_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// mysql_stmt_prepare return - Cache the prepared statement
SEC("uretprobe/mysql_stmt_prepare")
int trace_mysql_stmt_prepare_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state *state = bpf_map_lookup_elem(&mysql_queries, &pid_tgid);
    if (!state) return 0;
    
    // Emit prepare event
    mysql_emit_event(state, (ret != 0), 0);
    
    // Cache statement for later execute calls
    // Note: In real implementation, we'd extract stmt_id from MYSQL_STMT structure
    
    bpf_map_delete_elem(&mysql_queries, &pid_tgid);
    return 0;
}

// mysql_stmt_execute - Execute a prepared statement
SEC("uprobe/mysql_stmt_execute")
int trace_mysql_stmt_execute(struct pt_regs *ctx) {
    void *stmt = (void *)PT_REGS_PARM1(ctx);
    
    if (!stmt) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.command = COM_STMT_EXECUTE;
    state.is_prepared = 1;
    
    // Try to read stmt_id from MYSQL_STMT structure
    // The offset varies by MySQL version, this is approximate
    // bpf_probe_read_user(&state.stmt_id, sizeof(state.stmt_id), stmt + 0x10);
    
    bpf_map_update_elem(&mysql_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// mysql_stmt_execute return
SEC("uretprobe/mysql_stmt_execute")
int trace_mysql_stmt_execute_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state *state = bpf_map_lookup_elem(&mysql_queries, &pid_tgid);
    if (!state) return 0;
    
    // Look up cached statement to get query text
    // u64 stmt_key = (pid_tgid & 0xFFFFFFFF00000000) | state->stmt_id;
    // struct mysql_stmt_info *stmt_info = bpf_map_lookup_elem(&mysql_stmts, &stmt_key);
    // if (stmt_info) {
    //     state->query_type = stmt_info->query_type;
    //     __builtin_memcpy(state->query, stmt_info->query, sizeof(state->query));
    //     state->query_len = stmt_info->query_len;
    // }
    
    mysql_emit_event(state, (ret != 0), 0);
    
    bpf_map_delete_elem(&mysql_queries, &pid_tgid);
    return 0;
}

// mysql_stmt_close - Close a prepared statement
SEC("uprobe/mysql_stmt_close")
int trace_mysql_stmt_close(struct pt_regs *ctx) {
    // Clean up cached statement
    // void *stmt = (void *)PT_REGS_PARM1(ctx);
    // u64 pid_tgid = bpf_get_current_pid_tgid();
    // Read stmt_id and delete from cache
    return 0;
}

// mysql_send_query - Lower level query send
SEC("uprobe/mysql_send_query")
int trace_mysql_send_query(struct pt_regs *ctx) {
    void *mysql = (void *)PT_REGS_PARM1(ctx);
    const char *query = (const char *)PT_REGS_PARM2(ctx);
    unsigned long length = PT_REGS_PARM3(ctx);
    
    if (!query || length == 0) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.command = COM_QUERY;
    state.is_prepared = 0;
    
    u32 copy_len = length;
    if (copy_len > sizeof(state.query) - 1) {
        copy_len = sizeof(state.query) - 1;
    }
    
    bpf_probe_read_user(state.query, copy_len, query);
    state.query_len = copy_len;
    state.query_type = mysql_classify_query(state.query);
    
    bpf_map_update_elem(&mysql_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// mysql_read_query_result - Capture query completion
SEC("uretprobe/mysql_read_query_result")
int trace_mysql_read_query_result_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state *state = bpf_map_lookup_elem(&mysql_queries, &pid_tgid);
    if (!state) return 0;
    
    mysql_emit_event(state, (ret != 0), 0);
    
    bpf_map_delete_elem(&mysql_queries, &pid_tgid);
    return 0;
}

// mysql_store_result - Get result set
SEC("uretprobe/mysql_store_result")
int trace_mysql_store_result_ret(struct pt_regs *ctx) {
    void *result = (void *)PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct mysql_query_state *state = bpf_map_lookup_elem(&mysql_queries, &pid_tgid);
    if (!state) return 0;
    
    int has_error = (result == NULL) ? 1 : 0;
    mysql_emit_event(state, has_error, 0);
    
    bpf_map_delete_elem(&mysql_queries, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
