// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Oracle TNS/OCI Protocol Tracer
// Traces Oracle queries via OCI (Oracle Call Interface) library uprobes

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/tp_info.h>
#include <pid/pid_helpers.h>

// ============================================================================
// Oracle TNS Protocol Constants
// ============================================================================

// TNS packet types
#define TNS_TYPE_CONNECT    1
#define TNS_TYPE_ACCEPT     2
#define TNS_TYPE_ACK        3
#define TNS_TYPE_REFUSE     4
#define TNS_TYPE_REDIRECT   5
#define TNS_TYPE_DATA       6
#define TNS_TYPE_NULL       7
#define TNS_TYPE_ABORT      9
#define TNS_TYPE_RESEND     11
#define TNS_TYPE_MARKER     12
#define TNS_TYPE_ATTENTION  13
#define TNS_TYPE_CONTROL    14

// TTC (Two-Task Common) function codes
#define TTC_FUNCTION_OPEN            1
#define TTC_FUNCTION_CLOSE           2
#define TTC_FUNCTION_EXECUTE         3
#define TTC_FUNCTION_FETCH           5
#define TTC_FUNCTION_PARSE           14
#define TTC_FUNCTION_DESCRIBE        15
#define TTC_FUNCTION_COMMIT          112
#define TTC_FUNCTION_ROLLBACK        113
#define TTC_FUNCTION_LOB_OPEN        96
#define TTC_FUNCTION_LOB_CLOSE       97

// OCI statement types
#define OCI_STMT_SELECT     1
#define OCI_STMT_UPDATE     2
#define OCI_STMT_DELETE     3
#define OCI_STMT_INSERT     4
#define OCI_STMT_CREATE     5
#define OCI_STMT_DROP       6
#define OCI_STMT_ALTER      7
#define OCI_STMT_BEGIN      8
#define OCI_STMT_DECLARE    9
#define OCI_STMT_CALL       10

// ============================================================================
// Query Types (internal classification)
// ============================================================================

#define QUERY_TYPE_UNKNOWN     0
#define QUERY_TYPE_SELECT      1
#define QUERY_TYPE_INSERT      2
#define QUERY_TYPE_UPDATE      3
#define QUERY_TYPE_DELETE      4
#define QUERY_TYPE_DDL         5
#define QUERY_TYPE_TRANSACTION 6
#define QUERY_TYPE_PLSQL       7
#define QUERY_TYPE_OTHER       8

// ============================================================================
// Buffer Sizes
// ============================================================================

#define ORACLE_SQL_MAX_LEN     2048
#define ORACLE_SCHEMA_MAX_LEN  32
#define ORACLE_SERVICE_MAX_LEN 64
#define ORACLE_USER_MAX_LEN    32
#define ORACLE_ERROR_MSG_MAX_LEN 256

// ============================================================================
// Event Type for Ring Buffer
// ============================================================================

#define EVENT_TYPE_ORACLE_QUERY 22  // Oracle query event

// ============================================================================
// Oracle Query Event
// ============================================================================

struct oracle_event {
    u8  type;                           // Event type marker
    u8  tns_type;                       // TNS packet type
    u8  ttc_function;                   // TTC function code
    u8  statement_type;                 // OCI statement type
    u8  query_type;                     // Query classification
    u8  is_plsql;                       // Is PL/SQL block
    u8  flags;                          // Flags
    u8  _pad;
    
    u64 timestamp;                      // Event timestamp (ns)
    u64 latency_ns;                     // Query latency (ns)
    
    pid_info pid;                       // Process info
    
    // Connection info
    connection_info_t conn;
    
    // SQL info
    u16 cursor_id;                      // Cursor ID
    u16 _pad2;
    u32 sql_id_hash;                    // Hash of SQL_ID
    u32 sql_len;
    u32 _pad3;
    char sql_text[ORACLE_SQL_MAX_LEN];
    
    // Execution statistics
    u64 rows_processed;
    u64 logical_reads;                  // Buffer gets
    u64 physical_reads;                 // Disk reads
    u64 cpu_time_us;                    // CPU time in microseconds
    u64 elapsed_time_us;                // Elapsed time in microseconds
    
    // Error info
    u8  has_error;
    u8  _pad4[3];
    s32 ora_error_code;                 // ORA-XXXXX error code
    char error_message[ORACLE_ERROR_MSG_MAX_LEN];
    
    // Session info
    u32 session_id;                     // V$SESSION.SID
    u32 serial_num;                     // V$SESSION.SERIAL#
    char username[ORACLE_USER_MAX_LEN];
    char schema_name[ORACLE_SCHEMA_MAX_LEN];
    char service_name[ORACLE_SERVICE_MAX_LEN];
    
    // Trace context
    tp_info_t tp;
};

// ============================================================================
// Query State Tracking
// ============================================================================

struct oracle_sql_state {
    u64 start_time;
    u8  ttc_function;
    u8  statement_type;
    u8  is_plsql;
    u8  _pad;
    u16 cursor_id;
    u16 _pad2;
    u32 sql_len;
    char sql_text[ORACLE_SQL_MAX_LEN];
};

// ============================================================================
// Cursor Cache (for tracking prepared cursors)
// ============================================================================

struct oracle_cursor_info {
    u16 cursor_id;
    u8  statement_type;
    u8  query_type;
    u32 sql_len;
    char sql_text[ORACLE_SQL_MAX_LEN];
};

// ============================================================================
// BPF Maps
// ============================================================================

// Track active SQL by pid_tgid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct oracle_sql_state));
    __uint(max_entries, 10000);
} oracle_sqls SEC(".maps");

// Cache cursors by (pid_tgid & 0xFFFFFFFF00000000) | cursor_id
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct oracle_cursor_info));
    __uint(max_entries, 50000);
} oracle_cursors SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);  // 64MB
} oracle_events SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// Classify query type from SQL text
static __always_inline u8 oracle_classify_query(const char *query) {
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
    if (c1 == 'c' && c2 == 'o' && c3 == 'm') return QUERY_TYPE_TRANSACTION;  // COMMIT
    if (c1 == 'r' && c2 == 'o' && c3 == 'l') return QUERY_TYPE_TRANSACTION;  // ROLLBACK
    if (c1 == 'c' && c2 == 'r' && c3 == 'e') return QUERY_TYPE_DDL;          // CREATE
    if (c1 == 'a' && c2 == 'l' && c3 == 't') return QUERY_TYPE_DDL;          // ALTER
    if (c1 == 'd' && c2 == 'r' && c3 == 'o') return QUERY_TYPE_DDL;          // DROP
    if (c1 == 'b' && c2 == 'e' && c3 == 'g') return QUERY_TYPE_PLSQL;        // BEGIN (PL/SQL block)
    if (c1 == 'd' && c2 == 'e' && c3 == 'c') return QUERY_TYPE_PLSQL;        // DECLARE
    if (c1 == 'c' && c2 == 'a' && c3 == 'l') return QUERY_TYPE_PLSQL;        // CALL
    if (c1 == 'm' && c2 == 'e' && c3 == 'r') return QUERY_TYPE_UPDATE;       // MERGE
    
    return QUERY_TYPE_OTHER;
}

// Detect if SQL is PL/SQL
static __always_inline int oracle_is_plsql(const char *query) {
    int i = 0;
    #pragma unroll
    for (; i < 10 && (query[i] == ' ' || query[i] == '\t' || query[i] == '\n'); i++);
    
    char c1 = query[i] | 0x20;
    char c2 = query[i+1] | 0x20;
    char c3 = query[i+2] | 0x20;
    
    // BEGIN or DECLARE indicates PL/SQL
    if (c1 == 'b' && c2 == 'e' && c3 == 'g') return 1;
    if (c1 == 'd' && c2 == 'e' && c3 == 'c') return 1;
    
    return 0;
}

// Emit an Oracle event to the ring buffer
static __always_inline int oracle_emit_event(struct oracle_sql_state *state, int has_error, s32 error_code) {
    struct oracle_event *event = bpf_ringbuf_reserve(&oracle_events, sizeof(*event), 0);
    if (!event) {
        return -1;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event->type = EVENT_TYPE_ORACLE_QUERY;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->ttc_function = state->ttc_function;
    event->statement_type = state->statement_type;
    event->is_plsql = state->is_plsql;
    event->cursor_id = state->cursor_id;
    event->sql_len = state->sql_len;
    
    // Copy SQL
    __builtin_memcpy(event->sql_text, state->sql_text, sizeof(event->sql_text));
    
    // Set process info
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    // Error info
    if (has_error) {
        event->has_error = 1;
        event->ora_error_code = error_code;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// OCI (Oracle Call Interface) Function Probes
// ============================================================================

// OCIStmtPrepare2 - Prepare a statement
SEC("uprobe/OCIStmtPrepare2")
int trace_oci_stmt_prepare2(struct pt_regs *ctx) {
    void *svchp = (void *)PT_REGS_PARM1(ctx);       // Service context handle
    void *stmtp = (void *)PT_REGS_PARM2(ctx);       // Statement handle (out)
    void *errhp = (void *)PT_REGS_PARM3(ctx);       // Error handle
    const char *stmt = (const char *)PT_REGS_PARM4(ctx);  // SQL statement
    u32 stmt_len = PT_REGS_PARM5(ctx);              // Statement length
    
    if (!stmt || stmt_len == 0) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.ttc_function = TTC_FUNCTION_PARSE;
    
    // Clamp length
    u32 copy_len = stmt_len;
    if (copy_len > sizeof(state.sql_text) - 1) {
        copy_len = sizeof(state.sql_text) - 1;
    }
    
    bpf_probe_read_user(state.sql_text, copy_len, stmt);
    state.sql_len = copy_len;
    state.is_plsql = oracle_is_plsql(state.sql_text);
    
    bpf_map_update_elem(&oracle_sqls, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// OCIStmtPrepare (older API)
SEC("uprobe/OCIStmtPrepare")
int trace_oci_stmt_prepare(struct pt_regs *ctx) {
    void *stmtp = (void *)PT_REGS_PARM1(ctx);       // Statement handle
    void *errhp = (void *)PT_REGS_PARM2(ctx);       // Error handle
    const char *stmt = (const char *)PT_REGS_PARM3(ctx);  // SQL statement
    u32 stmt_len = PT_REGS_PARM4(ctx);              // Statement length
    
    if (!stmt || stmt_len == 0) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.ttc_function = TTC_FUNCTION_PARSE;
    
    u32 copy_len = stmt_len;
    if (copy_len > sizeof(state.sql_text) - 1) {
        copy_len = sizeof(state.sql_text) - 1;
    }
    
    bpf_probe_read_user(state.sql_text, copy_len, stmt);
    state.sql_len = copy_len;
    state.is_plsql = oracle_is_plsql(state.sql_text);
    
    bpf_map_update_elem(&oracle_sqls, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// OCIStmtExecute - Execute a prepared statement
SEC("uprobe/OCIStmtExecute")
int trace_oci_stmt_execute(struct pt_regs *ctx) {
    void *svchp = (void *)PT_REGS_PARM1(ctx);       // Service context handle
    void *stmtp = (void *)PT_REGS_PARM2(ctx);       // Statement handle
    void *errhp = (void *)PT_REGS_PARM3(ctx);       // Error handle
    u32 iters = PT_REGS_PARM4(ctx);                 // Number of iterations
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state *state = bpf_map_lookup_elem(&oracle_sqls, &pid_tgid);
    if (state) {
        // Update function and reset start time for execute phase
        state->ttc_function = TTC_FUNCTION_EXECUTE;
        state->start_time = bpf_ktime_get_ns();
    } else {
        // Execute without prior prepare (direct execution)
        struct oracle_sql_state new_state = {};
        new_state.start_time = bpf_ktime_get_ns();
        new_state.ttc_function = TTC_FUNCTION_EXECUTE;
        bpf_map_update_elem(&oracle_sqls, &pid_tgid, &new_state, BPF_ANY);
    }
    
    return 0;
}

// OCIStmtExecute return
SEC("uretprobe/OCIStmtExecute")
int trace_oci_stmt_execute_ret(struct pt_regs *ctx) {
    s32 ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state *state = bpf_map_lookup_elem(&oracle_sqls, &pid_tgid);
    if (!state) return 0;
    
    // OCI_SUCCESS = 0, OCI_SUCCESS_WITH_INFO = 1
    int has_error = (ret != 0 && ret != 1) ? 1 : 0;
    s32 error_code = has_error ? ret : 0;
    
    oracle_emit_event(state, has_error, error_code);
    
    bpf_map_delete_elem(&oracle_sqls, &pid_tgid);
    return 0;
}

// OCIStmtFetch2 - Fetch rows from result set
SEC("uprobe/OCIStmtFetch2")
int trace_oci_stmt_fetch2(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state *state = bpf_map_lookup_elem(&oracle_sqls, &pid_tgid);
    if (state) {
        state->ttc_function = TTC_FUNCTION_FETCH;
    }
    
    return 0;
}

// OCITransCommit - Commit transaction
SEC("uprobe/OCITransCommit")
int trace_oci_trans_commit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.ttc_function = TTC_FUNCTION_COMMIT;
    
    // Set SQL to COMMIT for visibility
    __builtin_memcpy(state.sql_text, "COMMIT", 7);
    state.sql_len = 6;
    
    bpf_map_update_elem(&oracle_sqls, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// OCITransCommit return
SEC("uretprobe/OCITransCommit")
int trace_oci_trans_commit_ret(struct pt_regs *ctx) {
    s32 ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state *state = bpf_map_lookup_elem(&oracle_sqls, &pid_tgid);
    if (!state) return 0;
    
    int has_error = (ret != 0 && ret != 1) ? 1 : 0;
    oracle_emit_event(state, has_error, has_error ? ret : 0);
    
    bpf_map_delete_elem(&oracle_sqls, &pid_tgid);
    return 0;
}

// OCITransRollback - Rollback transaction
SEC("uprobe/OCITransRollback")
int trace_oci_trans_rollback(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.ttc_function = TTC_FUNCTION_ROLLBACK;
    
    __builtin_memcpy(state.sql_text, "ROLLBACK", 9);
    state.sql_len = 8;
    
    bpf_map_update_elem(&oracle_sqls, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// OCITransRollback return
SEC("uretprobe/OCITransRollback")
int trace_oci_trans_rollback_ret(struct pt_regs *ctx) {
    s32 ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct oracle_sql_state *state = bpf_map_lookup_elem(&oracle_sqls, &pid_tgid);
    if (!state) return 0;
    
    int has_error = (ret != 0 && ret != 1) ? 1 : 0;
    oracle_emit_event(state, has_error, has_error ? ret : 0);
    
    bpf_map_delete_elem(&oracle_sqls, &pid_tgid);
    return 0;
}

// OCIStmtRelease - Release a statement
SEC("uprobe/OCIStmtRelease")
int trace_oci_stmt_release(struct pt_regs *ctx) {
    // Clean up any state
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&oracle_sqls, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
