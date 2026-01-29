// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Redis RESP Protocol Tracer
// Traces Redis commands via hiredis/redis client library uprobes

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/tp_info.h>
#include <pid/pid_helpers.h>

// ============================================================================
// Redis RESP Protocol Constants
// ============================================================================

// RESP data types
#define RESP_SIMPLE_STRING  '+'
#define RESP_ERROR          '-'
#define RESP_INTEGER        ':'
#define RESP_BULK_STRING    '$'
#define RESP_ARRAY          '*'
// RESP3 additions
#define RESP_NULL           '_'
#define RESP_BOOLEAN        '#'
#define RESP_DOUBLE         ','
#define RESP_BIG_NUMBER     '('
#define RESP_BULK_ERROR     '!'
#define RESP_VERBATIM       '='
#define RESP_MAP            '%'
#define RESP_SET            '~'
#define RESP_ATTRIBUTE      '|'
#define RESP_PUSH           '>'

// Command categories
#define REDIS_CMD_STRING    1   // GET, SET, APPEND, etc.
#define REDIS_CMD_LIST      2   // LPUSH, RPOP, etc.
#define REDIS_CMD_SET       3   // SADD, SMEMBERS, etc.
#define REDIS_CMD_HASH      4   // HGET, HSET, etc.
#define REDIS_CMD_ZSET      5   // ZADD, ZRANGE, etc.
#define REDIS_CMD_KEY       6   // DEL, EXISTS, EXPIRE, etc.
#define REDIS_CMD_PUBSUB    7   // PUBLISH, SUBSCRIBE, etc.
#define REDIS_CMD_TX        8   // MULTI, EXEC, etc.
#define REDIS_CMD_SCRIPT    9   // EVAL, EVALSHA, etc.
#define REDIS_CMD_CLUSTER   10  // CLUSTER commands
#define REDIS_CMD_SERVER    11  // INFO, CONFIG, etc.
#define REDIS_CMD_OTHER     12

// ============================================================================
// Buffer Sizes
// ============================================================================

#define REDIS_CMD_MAX_LEN       32
#define REDIS_KEY_MAX_LEN       256
#define REDIS_ARGS_MAX_LEN      512
#define REDIS_ERROR_MAX_LEN     256

// ============================================================================
// Event Type for Ring Buffer
// ============================================================================

#define EVENT_TYPE_REDIS_CMD    40  // Redis command event

// ============================================================================
// Redis Command Event
// ============================================================================

struct redis_event {
    u8  type;                           // Event type marker
    u8  cmd_category;                   // Command category
    u8  resp_type;                      // Response RESP type
    u8  flags;                          // Flags
    s32 error_code;                     // Redis error code (if any)
    
    u64 timestamp;                      // Event timestamp (ns)
    u64 latency_ns;                     // Command latency (ns)
    
    pid_info pid;                       // Process info
    
    // Connection info
    connection_info_t conn;
    s32 db_index;                       // Redis database index
    s32 _pad;
    
    // Command info
    char command[REDIS_CMD_MAX_LEN];    // Command name (GET, SET, etc.)
    char key[REDIS_KEY_MAX_LEN];        // Primary key
    char args[REDIS_ARGS_MAX_LEN];      // Additional args (truncated)
    u32 cmd_len;
    u32 key_len;
    u32 args_len;
    u32 key_count;                      // Number of keys in command
    
    // Response info
    s64 response_int;                   // Integer response (if applicable)
    u32 response_size;                  // Response size in bytes
    u32 array_length;                   // Array length (if array response)
    
    // Error info
    u8  has_error;
    u8  _pad2[3];
    char error_message[REDIS_ERROR_MAX_LEN];
    
    // Trace context
    tp_info_t tp;
};

// ============================================================================
// Command State Tracking
// ============================================================================

struct redis_cmd_state {
    u64 start_time;
    u8  cmd_category;
    u8  _pad[3];
    u32 cmd_len;
    u32 key_len;
    u32 args_len;
    char command[REDIS_CMD_MAX_LEN];
    char key[REDIS_KEY_MAX_LEN];
    char args[REDIS_ARGS_MAX_LEN];
    s32 db_index;
    u32 key_count;
};

// ============================================================================
// BPF Maps
// ============================================================================

// Track active commands by pid_tgid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct redis_cmd_state));
    __uint(max_entries, 10000);
} redis_cmds SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024);  // 32MB
} redis_events SEC(".maps");

// Hot key tracking (key hash -> access count)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));        // Key hash
    __uint(value_size, sizeof(u64));      // Access count
    __uint(max_entries, 100000);
} redis_hot_keys SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// Simple hash function for keys
static __always_inline u64 redis_hash_key(const char *key, u32 len) {
    u64 hash = 5381;
    u32 i;
    
    #pragma unroll
    for (i = 0; i < 32 && i < len; i++) {
        char c = key[i];
        if (c == 0) break;
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

// Classify command category from command name
static __always_inline u8 redis_classify_cmd(const char *cmd) {
    char c1 = cmd[0] | 0x20;
    char c2 = cmd[1] | 0x20;
    char c3 = cmd[2] | 0x20;
    
    // String commands: GET, SET, MGET, MSET, APPEND, INCR, DECR
    if (c1 == 'g' && c2 == 'e' && c3 == 't') return REDIS_CMD_STRING;
    if (c1 == 's' && c2 == 'e' && c3 == 't') return REDIS_CMD_STRING;
    if (c1 == 'm' && c2 == 'g' && c3 == 'e') return REDIS_CMD_STRING;
    if (c1 == 'm' && c2 == 's' && c3 == 'e') return REDIS_CMD_STRING;
    if (c1 == 'a' && c2 == 'p' && c3 == 'p') return REDIS_CMD_STRING;
    if (c1 == 'i' && c2 == 'n' && c3 == 'c') return REDIS_CMD_STRING;
    if (c1 == 'd' && c2 == 'e' && c3 == 'c') return REDIS_CMD_STRING;
    
    // List commands: LPUSH, RPUSH, LPOP, RPOP, LRANGE, LLEN
    if (c1 == 'l' && c2 == 'p') return REDIS_CMD_LIST;
    if (c1 == 'r' && c2 == 'p') return REDIS_CMD_LIST;
    if (c1 == 'l' && c2 == 'r') return REDIS_CMD_LIST;
    if (c1 == 'l' && c2 == 'l') return REDIS_CMD_LIST;
    if (c1 == 'l' && c2 == 'i') return REDIS_CMD_LIST;
    if (c1 == 'b' && c2 == 'l') return REDIS_CMD_LIST;
    if (c1 == 'b' && c2 == 'r') return REDIS_CMD_LIST;
    
    // Set commands: SADD, SREM, SMEMBERS, SISMEMBER
    if (c1 == 's' && c2 == 'a' && c3 == 'd') return REDIS_CMD_SET;
    if (c1 == 's' && c2 == 'r' && c3 == 'e') return REDIS_CMD_SET;
    if (c1 == 's' && c2 == 'm' && c3 == 'e') return REDIS_CMD_SET;
    if (c1 == 's' && c2 == 'i' && c3 == 's') return REDIS_CMD_SET;
    if (c1 == 's' && c2 == 'c' && c3 == 'a') return REDIS_CMD_SET;
    if (c1 == 's' && c2 == 'p' && c3 == 'o') return REDIS_CMD_SET;
    
    // Hash commands: HGET, HSET, HMGET, HMSET, HDEL, HGETALL
    if (c1 == 'h' && c2 == 'g') return REDIS_CMD_HASH;
    if (c1 == 'h' && c2 == 's') return REDIS_CMD_HASH;
    if (c1 == 'h' && c2 == 'm') return REDIS_CMD_HASH;
    if (c1 == 'h' && c2 == 'd') return REDIS_CMD_HASH;
    if (c1 == 'h' && c2 == 'i') return REDIS_CMD_HASH;
    if (c1 == 'h' && c2 == 'l') return REDIS_CMD_HASH;
    if (c1 == 'h' && c2 == 'k') return REDIS_CMD_HASH;
    if (c1 == 'h' && c2 == 'v') return REDIS_CMD_HASH;
    
    // Sorted set commands: ZADD, ZRANGE, ZSCORE, ZRANK
    if (c1 == 'z') return REDIS_CMD_ZSET;
    
    // Key commands: DEL, EXISTS, EXPIRE, TTL, KEYS, SCAN
    if (c1 == 'd' && c2 == 'e' && c3 == 'l') return REDIS_CMD_KEY;
    if (c1 == 'e' && c2 == 'x' && c3 == 'i') return REDIS_CMD_KEY;
    if (c1 == 'e' && c2 == 'x' && c3 == 'p') return REDIS_CMD_KEY;
    if (c1 == 't' && c2 == 't' && c3 == 'l') return REDIS_CMD_KEY;
    if (c1 == 'k' && c2 == 'e' && c3 == 'y') return REDIS_CMD_KEY;
    if (c1 == 's' && c2 == 'c' && c3 == 'a') return REDIS_CMD_KEY;
    if (c1 == 't' && c2 == 'y' && c3 == 'p') return REDIS_CMD_KEY;
    
    // Pub/Sub: PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PSUBSCRIBE
    if (c1 == 'p' && c2 == 'u' && c3 == 'b') return REDIS_CMD_PUBSUB;
    if (c1 == 's' && c2 == 'u' && c3 == 'b') return REDIS_CMD_PUBSUB;
    if (c1 == 'u' && c2 == 'n' && c3 == 's') return REDIS_CMD_PUBSUB;
    if (c1 == 'p' && c2 == 's' && c3 == 'u') return REDIS_CMD_PUBSUB;
    
    // Transaction: MULTI, EXEC, DISCARD, WATCH
    if (c1 == 'm' && c2 == 'u' && c3 == 'l') return REDIS_CMD_TX;
    if (c1 == 'e' && c2 == 'x' && c3 == 'e') return REDIS_CMD_TX;
    if (c1 == 'd' && c2 == 'i' && c3 == 's') return REDIS_CMD_TX;
    if (c1 == 'w' && c2 == 'a' && c3 == 't') return REDIS_CMD_TX;
    
    // Script: EVAL, EVALSHA, SCRIPT
    if (c1 == 'e' && c2 == 'v' && c3 == 'a') return REDIS_CMD_SCRIPT;
    if (c1 == 's' && c2 == 'c' && c3 == 'r') return REDIS_CMD_SCRIPT;
    
    // Cluster
    if (c1 == 'c' && c2 == 'l' && c3 == 'u') return REDIS_CMD_CLUSTER;
    
    // Server: INFO, CONFIG, CLIENT, DEBUG
    if (c1 == 'i' && c2 == 'n' && c3 == 'f') return REDIS_CMD_SERVER;
    if (c1 == 'c' && c2 == 'o' && c3 == 'n') return REDIS_CMD_SERVER;
    if (c1 == 'c' && c2 == 'l' && c3 == 'i') return REDIS_CMD_SERVER;
    if (c1 == 'd' && c2 == 'e' && c3 == 'b') return REDIS_CMD_SERVER;
    if (c1 == 'p' && c2 == 'i' && c3 == 'n') return REDIS_CMD_SERVER;
    
    return REDIS_CMD_OTHER;
}

// Emit event to ring buffer
static __always_inline int redis_emit_event(struct redis_cmd_state *state, int has_error) {
    struct redis_event *event = bpf_ringbuf_reserve(&redis_events, sizeof(*event), 0);
    if (!event) {
        return -1;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event->type = EVENT_TYPE_REDIS_CMD;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->cmd_category = state->cmd_category;
    event->db_index = state->db_index;
    event->key_count = state->key_count;
    
    event->cmd_len = state->cmd_len;
    event->key_len = state->key_len;
    event->args_len = state->args_len;
    
    __builtin_memcpy(event->command, state->command, sizeof(event->command));
    __builtin_memcpy(event->key, state->key, sizeof(event->key));
    __builtin_memcpy(event->args, state->args, sizeof(event->args));
    
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    if (has_error) {
        event->has_error = 1;
    }
    
    // Update hot key tracking
    if (state->key_len > 0) {
        u64 key_hash = redis_hash_key(state->key, state->key_len);
        u64 *count = bpf_map_lookup_elem(&redis_hot_keys, &key_hash);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            u64 one = 1;
            bpf_map_update_elem(&redis_hot_keys, &key_hash, &one, BPF_ANY);
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// hiredis Library Probes
// ============================================================================

// redisCommand - Execute a command (printf-style)
SEC("uprobe/redisCommand")
int trace_redis_command(struct pt_regs *ctx) {
    void *context = (void *)PT_REGS_PARM1(ctx);
    const char *format = (const char *)PT_REGS_PARM2(ctx);
    
    if (!format) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct redis_cmd_state state = {};
    state.start_time = bpf_ktime_get_ns();
    
    // Read format string (contains command pattern)
    int ret = bpf_probe_read_user_str(state.command, sizeof(state.command), format);
    if (ret > 0) {
        state.cmd_len = ret - 1;
    }
    
    // Parse command name (first word)
    #pragma unroll
    for (int i = 0; i < 31; i++) {
        if (state.command[i] == ' ' || state.command[i] == 0) {
            state.command[i] = 0;
            state.cmd_len = i;
            break;
        }
    }
    
    state.cmd_category = redis_classify_cmd(state.command);
    
    bpf_map_update_elem(&redis_cmds, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// redisCommand return
SEC("uretprobe/redisCommand")
int trace_redis_command_ret(struct pt_regs *ctx) {
    void *reply = (void *)PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct redis_cmd_state *state = bpf_map_lookup_elem(&redis_cmds, &pid_tgid);
    if (!state) return 0;
    
    int has_error = (reply == NULL) ? 1 : 0;
    redis_emit_event(state, has_error);
    
    bpf_map_delete_elem(&redis_cmds, &pid_tgid);
    return 0;
}

// redisCommandArgv - Execute command with argv array
SEC("uprobe/redisCommandArgv")
int trace_redis_command_argv(struct pt_regs *ctx) {
    void *context = (void *)PT_REGS_PARM1(ctx);
    int argc = PT_REGS_PARM2(ctx);
    const char **argv = (const char **)PT_REGS_PARM3(ctx);
    // const size_t *argvlen = (const size_t *)PT_REGS_PARM4(ctx);
    
    if (!argv || argc < 1) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct redis_cmd_state state = {};
    state.start_time = bpf_ktime_get_ns();
    
    // Read command (first argv)
    const char *cmd_ptr = NULL;
    bpf_probe_read_user(&cmd_ptr, sizeof(cmd_ptr), argv);
    if (cmd_ptr) {
        int ret = bpf_probe_read_user_str(state.command, sizeof(state.command), cmd_ptr);
        if (ret > 0) {
            state.cmd_len = ret - 1;
        }
    }
    
    // Read key (second argv, if present)
    if (argc >= 2) {
        const char *key_ptr = NULL;
        bpf_probe_read_user(&key_ptr, sizeof(key_ptr), argv + 1);
        if (key_ptr) {
            int ret = bpf_probe_read_user_str(state.key, sizeof(state.key), key_ptr);
            if (ret > 0) {
                state.key_len = ret - 1;
            }
        }
        state.key_count = 1;  // At least one key
    }
    
    state.cmd_category = redis_classify_cmd(state.command);
    
    bpf_map_update_elem(&redis_cmds, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// redisCommandArgv return
SEC("uretprobe/redisCommandArgv")
int trace_redis_command_argv_ret(struct pt_regs *ctx) {
    void *reply = (void *)PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct redis_cmd_state *state = bpf_map_lookup_elem(&redis_cmds, &pid_tgid);
    if (!state) return 0;
    
    int has_error = (reply == NULL) ? 1 : 0;
    redis_emit_event(state, has_error);
    
    bpf_map_delete_elem(&redis_cmds, &pid_tgid);
    return 0;
}

// redisAppendCommand - Pipeline: append command
SEC("uprobe/redisAppendCommand")
int trace_redis_append_command(struct pt_regs *ctx) {
    void *context = (void *)PT_REGS_PARM1(ctx);
    const char *format = (const char *)PT_REGS_PARM2(ctx);
    
    if (!format) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct redis_cmd_state state = {};
    state.start_time = bpf_ktime_get_ns();
    
    int ret = bpf_probe_read_user_str(state.command, sizeof(state.command), format);
    if (ret > 0) {
        state.cmd_len = ret - 1;
    }
    
    // Parse command name
    #pragma unroll
    for (int i = 0; i < 31; i++) {
        if (state.command[i] == ' ' || state.command[i] == 0) {
            state.command[i] = 0;
            state.cmd_len = i;
            break;
        }
    }
    
    state.cmd_category = redis_classify_cmd(state.command);
    
    bpf_map_update_elem(&redis_cmds, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// redisGetReply - Pipeline: get reply
SEC("uretprobe/redisGetReply")
int trace_redis_get_reply_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct redis_cmd_state *state = bpf_map_lookup_elem(&redis_cmds, &pid_tgid);
    if (!state) return 0;
    
    int has_error = (ret != 0) ? 1 : 0;  // REDIS_OK = 0
    redis_emit_event(state, has_error);
    
    bpf_map_delete_elem(&redis_cmds, &pid_tgid);
    return 0;
}

// redisvCommand - Variadic command
SEC("uprobe/redisvCommand")
int trace_redisv_command(struct pt_regs *ctx) {
    void *context = (void *)PT_REGS_PARM1(ctx);
    const char *format = (const char *)PT_REGS_PARM2(ctx);
    
    if (!format) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct redis_cmd_state state = {};
    state.start_time = bpf_ktime_get_ns();
    
    int ret = bpf_probe_read_user_str(state.command, sizeof(state.command), format);
    if (ret > 0) {
        state.cmd_len = ret - 1;
    }
    
    #pragma unroll
    for (int i = 0; i < 31; i++) {
        if (state.command[i] == ' ' || state.command[i] == 0) {
            state.command[i] = 0;
            state.cmd_len = i;
            break;
        }
    }
    
    state.cmd_category = redis_classify_cmd(state.command);
    
    bpf_map_update_elem(&redis_cmds, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// redisvCommand return
SEC("uretprobe/redisvCommand")
int trace_redisv_command_ret(struct pt_regs *ctx) {
    void *reply = (void *)PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct redis_cmd_state *state = bpf_map_lookup_elem(&redis_cmds, &pid_tgid);
    if (!state) return 0;
    
    int has_error = (reply == NULL) ? 1 : 0;
    redis_emit_event(state, has_error);
    
    bpf_map_delete_elem(&redis_cmds, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
