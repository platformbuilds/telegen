// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// PostgreSQL Wire Protocol v3 Tracer
// Traces PostgreSQL queries via libpq client library uprobes

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/tp_info.h>
#include <pid/pid_helpers.h>

// ============================================================================
// PostgreSQL Protocol Constants
// ============================================================================

// Frontend (client) message types
#define PG_MSG_QUERY        'Q'  // Simple query
#define PG_MSG_PARSE        'P'  // Parse (prepared statement)
#define PG_MSG_BIND         'B'  // Bind parameters
#define PG_MSG_EXECUTE      'E'  // Execute prepared statement
#define PG_MSG_DESCRIBE     'D'  // Describe
#define PG_MSG_CLOSE        'C'  // Close prepared statement/portal
#define PG_MSG_SYNC         'S'  // Sync
#define PG_MSG_TERMINATE    'X'  // Terminate

// Backend (server) message types
#define PG_MSG_CMD_COMPLETE 'C'  // Command complete
#define PG_MSG_DATA_ROW     'D'  // Data row
#define PG_MSG_ERROR        'E'  // Error response
#define PG_MSG_NOTICE       'N'  // Notice response
#define PG_MSG_READY        'Z'  // Ready for query
#define PG_MSG_PARSE_COMPLETE '1' // Parse complete
#define PG_MSG_BIND_COMPLETE  '2' // Bind complete
#define PG_MSG_ROW_DESC     'T'  // Row description

// Transaction status indicators
#define PG_TXN_IDLE     'I'  // Idle (not in transaction)
#define PG_TXN_IN_TXN   'T'  // In transaction block
#define PG_TXN_FAILED   'E'  // In failed transaction block

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

#define PG_QUERY_MAX_LEN       2048
#define PG_STMT_NAME_MAX_LEN   64
#define PG_DATABASE_MAX_LEN    64
#define PG_USER_MAX_LEN        64
#define PG_APP_NAME_MAX_LEN    64
#define PG_ERROR_CODE_MAX_LEN  6
#define PG_ERROR_MSG_MAX_LEN   256
#define PG_ERROR_DETAIL_MAX_LEN 256

// ============================================================================
// Event Type for Ring Buffer
// ============================================================================

#define EVENT_TYPE_PG_QUERY    20  // PostgreSQL query event

// ============================================================================
// PostgreSQL Query Event
// ============================================================================

struct pg_event {
    u8  type;                           // Event type marker
    u8  msg_type;                       // PostgreSQL message type
    u8  query_type;                     // Query classification
    u8  txn_status;                     // Transaction status
    u8  flags;                          // Flags (prepared, error, etc.)
    u8  _pad[3];
    
    u64 timestamp;                      // Event timestamp (ns)
    u64 latency_ns;                     // Query latency (ns)
    
    pid_info pid;                       // Process info
    
    // Connection info
    connection_info_t conn;
    s32 fd;
    u32 _pad2;
    
    // Query info
    u32 query_len;
    u32 rows_affected;
    u32 rows_returned;
    u32 _pad3;
    u64 bytes_sent;
    u64 bytes_received;
    
    char query[PG_QUERY_MAX_LEN];
    char stmt_name[PG_STMT_NAME_MAX_LEN];
    
    // Error info
    char error_code[PG_ERROR_CODE_MAX_LEN];    // SQLSTATE (e.g., "42P01")
    u8  _pad4[2];
    char error_message[PG_ERROR_MSG_MAX_LEN];
    
    // Extended info
    char database[PG_DATABASE_MAX_LEN];
    char user[PG_USER_MAX_LEN];
    char application_name[PG_APP_NAME_MAX_LEN];
    
    // Trace context
    tp_info_t tp;
};

// ============================================================================
// Query State Tracking
// ============================================================================

struct pg_query_state {
    u64 start_time;
    u8  msg_type;
    u8  query_type;
    u8  is_prepared;
    u8  _pad;
    u32 query_len;
    char query[PG_QUERY_MAX_LEN];
    char stmt_name[PG_STMT_NAME_MAX_LEN];
    u32 rows_returned;
    u64 bytes_received;
};

// ============================================================================
// Connection Metadata
// ============================================================================

struct pg_conn_info {
    char database[PG_DATABASE_MAX_LEN];
    char user[PG_USER_MAX_LEN];
    char application_name[PG_APP_NAME_MAX_LEN];
    u32 backend_pid;
    u8  ssl_enabled;
    u8  txn_status;
    u8  _pad[2];
};

// ============================================================================
// BPF Maps
// ============================================================================

// Track active queries by pid_tgid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct pg_query_state));
    __uint(max_entries, 10000);
} pg_queries SEC(".maps");

// Track connection metadata by fd
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(s32));
    __uint(value_size, sizeof(struct pg_conn_info));
    __uint(max_entries, 10000);
} pg_connections SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);  // 64MB
} pg_events SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// Classify query type from SQL text
static __always_inline u8 pg_classify_query(const char *query) {
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
    if (c1 == 'c' && c2 == 'o' && c3 == 'm') return QUERY_TYPE_TRANSACTION;
    if (c1 == 'r' && c2 == 'o' && c3 == 'l') return QUERY_TYPE_TRANSACTION;
    if (c1 == 'c' && c2 == 'r' && c3 == 'e') return QUERY_TYPE_DDL;
    if (c1 == 'a' && c2 == 'l' && c3 == 't') return QUERY_TYPE_DDL;
    if (c1 == 'd' && c2 == 'r' && c3 == 'o') return QUERY_TYPE_DDL;
    if (c1 == 'w' && c2 == 'i' && c3 == 't') return QUERY_TYPE_SELECT;  // WITH (CTE)
    
    return QUERY_TYPE_OTHER;
}

// Emit a PostgreSQL event to the ring buffer
static __always_inline int pg_emit_event(struct pg_query_state *state, int has_error) {
    struct pg_event *event = bpf_ringbuf_reserve(&pg_events, sizeof(*event), 0);
    if (!event) {
        return -1;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event->type = EVENT_TYPE_PG_QUERY;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->msg_type = state->msg_type;
    event->query_type = state->query_type;
    event->query_len = state->query_len;
    event->rows_returned = state->rows_returned;
    
    // Copy query and statement name
    __builtin_memcpy(event->query, state->query, sizeof(event->query));
    __builtin_memcpy(event->stmt_name, state->stmt_name, sizeof(event->stmt_name));
    
    // Set process info
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    // Flags
    if (state->is_prepared) {
        event->flags |= 0x01;  // Prepared statement flag
    }
    if (has_error) {
        event->flags |= 0x02;  // Error flag
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// libpq Function Probes
// ============================================================================

// PQsendQuery - Send a simple query
SEC("uprobe/PQsendQuery")
int trace_pq_send_query(struct pt_regs *ctx) {
    void *conn = (void *)PT_REGS_PARM1(ctx);
    const char *query = (const char *)PT_REGS_PARM2(ctx);
    
    if (!query) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct pg_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.msg_type = PG_MSG_QUERY;
    state.is_prepared = 0;
    
    // Read query string
    int ret = bpf_probe_read_user_str(state.query, sizeof(state.query), query);
    if (ret > 0) {
        state.query_len = ret - 1;  // Exclude null terminator
    }
    state.query_type = pg_classify_query(state.query);
    
    bpf_map_update_elem(&pg_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// PQsendQueryParams - Send parameterized query
SEC("uprobe/PQsendQueryParams")
int trace_pq_send_query_params(struct pt_regs *ctx) {
    void *conn = (void *)PT_REGS_PARM1(ctx);
    const char *query = (const char *)PT_REGS_PARM2(ctx);
    // int nParams = PT_REGS_PARM3(ctx);
    
    if (!query) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct pg_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.msg_type = PG_MSG_QUERY;
    state.is_prepared = 0;
    
    int ret = bpf_probe_read_user_str(state.query, sizeof(state.query), query);
    if (ret > 0) {
        state.query_len = ret - 1;
    }
    state.query_type = pg_classify_query(state.query);
    
    bpf_map_update_elem(&pg_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// PQprepare - Prepare a statement
SEC("uprobe/PQprepare")
int trace_pq_prepare(struct pt_regs *ctx) {
    void *conn = (void *)PT_REGS_PARM1(ctx);
    const char *stmt_name = (const char *)PT_REGS_PARM2(ctx);
    const char *query = (const char *)PT_REGS_PARM3(ctx);
    
    if (!query) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct pg_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.msg_type = PG_MSG_PARSE;
    state.is_prepared = 1;
    
    if (stmt_name) {
        bpf_probe_read_user_str(state.stmt_name, sizeof(state.stmt_name), stmt_name);
    }
    
    int ret = bpf_probe_read_user_str(state.query, sizeof(state.query), query);
    if (ret > 0) {
        state.query_len = ret - 1;
    }
    state.query_type = pg_classify_query(state.query);
    
    bpf_map_update_elem(&pg_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// PQexecPrepared - Execute a prepared statement
SEC("uprobe/PQexecPrepared")
int trace_pq_exec_prepared(struct pt_regs *ctx) {
    void *conn = (void *)PT_REGS_PARM1(ctx);
    const char *stmt_name = (const char *)PT_REGS_PARM2(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct pg_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.msg_type = PG_MSG_EXECUTE;
    state.is_prepared = 1;
    
    if (stmt_name) {
        bpf_probe_read_user_str(state.stmt_name, sizeof(state.stmt_name), stmt_name);
    }
    
    bpf_map_update_elem(&pg_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// PQsendPrepare - Async prepare
SEC("uprobe/PQsendPrepare")
int trace_pq_send_prepare(struct pt_regs *ctx) {
    void *conn = (void *)PT_REGS_PARM1(ctx);
    const char *stmt_name = (const char *)PT_REGS_PARM2(ctx);
    const char *query = (const char *)PT_REGS_PARM3(ctx);
    
    if (!query) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct pg_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.msg_type = PG_MSG_PARSE;
    state.is_prepared = 1;
    
    if (stmt_name) {
        bpf_probe_read_user_str(state.stmt_name, sizeof(state.stmt_name), stmt_name);
    }
    
    int ret = bpf_probe_read_user_str(state.query, sizeof(state.query), query);
    if (ret > 0) {
        state.query_len = ret - 1;
    }
    state.query_type = pg_classify_query(state.query);
    
    bpf_map_update_elem(&pg_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// PQexec - Synchronous query execution (entry)
SEC("uprobe/PQexec")
int trace_pq_exec(struct pt_regs *ctx) {
    void *conn = (void *)PT_REGS_PARM1(ctx);
    const char *query = (const char *)PT_REGS_PARM2(ctx);
    
    if (!query) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct pg_query_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.msg_type = PG_MSG_QUERY;
    state.is_prepared = 0;
    
    int ret = bpf_probe_read_user_str(state.query, sizeof(state.query), query);
    if (ret > 0) {
        state.query_len = ret - 1;
    }
    state.query_type = pg_classify_query(state.query);
    
    bpf_map_update_elem(&pg_queries, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// PQexec return probe - Capture completion
SEC("uretprobe/PQexec")
int trace_pq_exec_ret(struct pt_regs *ctx) {
    void *result = (void *)PT_REGS_RC(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct pg_query_state *state = bpf_map_lookup_elem(&pg_queries, &pid_tgid);
    if (!state) return 0;
    
    int has_error = (result == NULL) ? 1 : 0;
    pg_emit_event(state, has_error);
    
    bpf_map_delete_elem(&pg_queries, &pid_tgid);
    return 0;
}

// PQgetResult return probe - Capture async query completion
SEC("uretprobe/PQgetResult")
int trace_pq_get_result_ret(struct pt_regs *ctx) {
    void *result = (void *)PT_REGS_RC(ctx);
    
    // NULL result means no more results
    if (!result) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct pg_query_state *state = bpf_map_lookup_elem(&pg_queries, &pid_tgid);
    if (!state) return 0;
    
    pg_emit_event(state, 0);
    
    bpf_map_delete_elem(&pg_queries, &pid_tgid);
    return 0;
}

// PQclear - Result cleanup (can be used to track query completion)
SEC("uprobe/PQclear")
int trace_pq_clear(struct pt_regs *ctx) {
    // This can be used to ensure we clean up any orphaned state
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pg_queries, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
