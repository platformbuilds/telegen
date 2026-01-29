// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Kafka Protocol Tracer
// Traces Kafka produce/consume operations via librdkafka uprobes

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_endian.h>

#include <common/connection_info.h>
#include <common/tp_info.h>
#include <pid/pid_helpers.h>

// ============================================================================
// Kafka Protocol Constants
// ============================================================================

// API Keys (Request types)
#define KAFKA_API_PRODUCE           0
#define KAFKA_API_FETCH             1
#define KAFKA_API_LIST_OFFSETS      2
#define KAFKA_API_METADATA          3
#define KAFKA_API_OFFSET_COMMIT     8
#define KAFKA_API_OFFSET_FETCH      9
#define KAFKA_API_FIND_COORDINATOR  10
#define KAFKA_API_JOIN_GROUP        11
#define KAFKA_API_HEARTBEAT         12
#define KAFKA_API_LEAVE_GROUP       13
#define KAFKA_API_SYNC_GROUP        14
#define KAFKA_API_DESCRIBE_GROUPS   15
#define KAFKA_API_LIST_GROUPS       16
#define KAFKA_API_SASL_HANDSHAKE    17
#define KAFKA_API_API_VERSIONS      18

// Operation types
#define KAFKA_OP_PRODUCE    1
#define KAFKA_OP_FETCH      2
#define KAFKA_OP_METADATA   3
#define KAFKA_OP_COMMIT     4
#define KAFKA_OP_OTHER      5

// ============================================================================
// Buffer Sizes
// ============================================================================

#define KAFKA_TOPIC_MAX_LEN     256
#define KAFKA_GROUP_MAX_LEN     256
#define KAFKA_CLIENT_ID_MAX_LEN 64
#define KAFKA_KEY_MAX_LEN       256
#define KAFKA_HEADER_MAX_COUNT  8
#define KAFKA_HEADER_KEY_LEN    64
#define KAFKA_HEADER_VAL_LEN    128

// ============================================================================
// Event Type for Ring Buffer
// ============================================================================

#define EVENT_TYPE_KAFKA_PRODUCE 30  // Kafka produce event
#define EVENT_TYPE_KAFKA_FETCH   31  // Kafka fetch event
#define EVENT_TYPE_KAFKA_COMMIT  32  // Kafka offset commit event

// ============================================================================
// Kafka Header (for trace propagation)
// ============================================================================

struct kafka_header {
    char key[KAFKA_HEADER_KEY_LEN];
    char value[KAFKA_HEADER_VAL_LEN];
    u32 key_len;
    u32 value_len;
};

// ============================================================================
// Kafka Produce Event
// ============================================================================

struct kafka_produce_event {
    u8  type;                           // Event type marker
    u8  api_key;                        // Kafka API key
    u8  flags;                          // Flags
    u8  _pad;
    u16 api_version;                    // API version
    u16 acks;                           // Required acks
    
    u64 timestamp;                      // Event timestamp (ns)
    u64 latency_ns;                     // Operation latency (ns)
    
    pid_info pid;                       // Process info
    
    // Connection info
    connection_info_t conn;
    
    // Topic/partition info
    char topic[KAFKA_TOPIC_MAX_LEN];
    s32 partition;                      // Partition number (-1 for auto)
    u32 _pad2;
    
    // Message info
    s64 offset;                         // Message offset (assigned by broker)
    u32 message_count;                  // Number of messages in batch
    u32 message_size;                   // Total size of messages
    char key[KAFKA_KEY_MAX_LEN];        // Message key (first message in batch)
    u32 key_len;
    u32 _pad3;
    
    // Error info
    u8  has_error;
    u8  _pad4[3];
    s32 error_code;                     // Kafka error code
    
    // Client info
    char client_id[KAFKA_CLIENT_ID_MAX_LEN];
    
    // Trace context (from message headers)
    tp_info_t tp;
};

// ============================================================================
// Kafka Fetch Event
// ============================================================================

struct kafka_fetch_event {
    u8  type;                           // Event type marker
    u8  api_key;                        // Kafka API key
    u8  flags;                          // Flags
    u8  _pad;
    u16 api_version;                    // API version
    u16 _pad2;
    
    u64 timestamp;                      // Event timestamp (ns)
    u64 latency_ns;                     // Operation latency (ns)
    
    pid_info pid;                       // Process info
    
    // Connection info
    connection_info_t conn;
    
    // Topic/partition info
    char topic[KAFKA_TOPIC_MAX_LEN];
    s32 partition;
    u32 _pad3;
    
    // Fetch info
    s64 fetch_offset;                   // Requested offset
    s64 high_watermark;                 // High watermark from broker
    u32 message_count;                  // Messages fetched
    u32 bytes_fetched;                  // Bytes fetched
    
    // Consumer group info
    char group_id[KAFKA_GROUP_MAX_LEN];
    
    // Error info
    u8  has_error;
    u8  _pad4[3];
    s32 error_code;
    
    // Client info
    char client_id[KAFKA_CLIENT_ID_MAX_LEN];
    
    // Trace context
    tp_info_t tp;
};

// ============================================================================
// Kafka Consumer Group Event (Offset Commit)
// ============================================================================

struct kafka_commit_event {
    u8  type;                           // Event type marker
    u8  api_key;                        // Kafka API key
    u8  flags;                          // Flags
    u8  _pad;
    u16 api_version;
    u16 _pad2;
    
    u64 timestamp;                      // Event timestamp (ns)
    u64 latency_ns;                     // Operation latency (ns)
    
    pid_info pid;                       // Process info
    
    // Consumer group info
    char group_id[KAFKA_GROUP_MAX_LEN];
    
    // Topic/partition info
    char topic[KAFKA_TOPIC_MAX_LEN];
    s32 partition;
    u32 _pad3;
    
    // Offset info
    s64 committed_offset;               // Committed offset
    s64 consumer_lag;                   // Lag (high_watermark - committed_offset)
    
    // Error info
    u8  has_error;
    u8  _pad4[3];
    s32 error_code;
    
    // Client info
    char client_id[KAFKA_CLIENT_ID_MAX_LEN];
};

// ============================================================================
// Operation State Tracking
// ============================================================================

struct kafka_op_state {
    u64 start_time;
    u8  op_type;
    u8  _pad[3];
    s32 partition;
    char topic[KAFKA_TOPIC_MAX_LEN];
    char group_id[KAFKA_GROUP_MAX_LEN];
    u32 message_count;
    u32 message_size;
    s64 offset;
};

// ============================================================================
// BPF Maps
// ============================================================================

// Track active operations by pid_tgid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct kafka_op_state));
    __uint(max_entries, 10000);
} kafka_ops SEC(".maps");

// Ring buffer for produce events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);  // 64MB
} kafka_produce_events SEC(".maps");

// Ring buffer for fetch events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);  // 64MB
} kafka_fetch_events SEC(".maps");

// Ring buffer for commit events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);  // 16MB
} kafka_commit_events SEC(".maps");

// ============================================================================
// librdkafka Function Probes
// ============================================================================

// rd_kafka_produce - Produce a single message
SEC("uprobe/rd_kafka_produce")
int trace_rd_kafka_produce(struct pt_regs *ctx) {
    void *rkt = (void *)PT_REGS_PARM1(ctx);          // Topic handle
    s32 partition = PT_REGS_PARM2(ctx);              // Partition
    s32 msgflags = PT_REGS_PARM3(ctx);               // Message flags
    void *payload = (void *)PT_REGS_PARM4(ctx);      // Payload
    size_t len = PT_REGS_PARM5(ctx);                 // Payload length
    // void *key = PT_REGS_PARM6(ctx);               // Key (6th param)
    // size_t keylen = ...;                           // Key length (7th param)
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.op_type = KAFKA_OP_PRODUCE;
    state.partition = partition;
    state.message_count = 1;
    state.message_size = len;
    
    // Topic name would need to be extracted from rkt structure
    // For now, we'll capture it in the return probe if possible
    
    bpf_map_update_elem(&kafka_ops, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// rd_kafka_produce return
SEC("uretprobe/rd_kafka_produce")
int trace_rd_kafka_produce_ret(struct pt_regs *ctx) {
    s32 ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state *state = bpf_map_lookup_elem(&kafka_ops, &pid_tgid);
    if (!state) return 0;
    
    struct kafka_produce_event *event = bpf_ringbuf_reserve(&kafka_produce_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&kafka_ops, &pid_tgid);
        return 0;
    }
    
    event->type = EVENT_TYPE_KAFKA_PRODUCE;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->api_key = KAFKA_API_PRODUCE;
    event->partition = state->partition;
    event->message_count = state->message_count;
    event->message_size = state->message_size;
    
    __builtin_memcpy(event->topic, state->topic, sizeof(event->topic));
    
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    if (ret == -1) {
        event->has_error = 1;
    }
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&kafka_ops, &pid_tgid);
    
    return 0;
}

// rd_kafka_producev - Variadic produce (modern API)
SEC("uprobe/rd_kafka_producev")
int trace_rd_kafka_producev(struct pt_regs *ctx) {
    void *rk = (void *)PT_REGS_PARM1(ctx);           // Kafka handle
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.op_type = KAFKA_OP_PRODUCE;
    state.message_count = 1;
    
    bpf_map_update_elem(&kafka_ops, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// rd_kafka_producev return
SEC("uretprobe/rd_kafka_producev")
int trace_rd_kafka_producev_ret(struct pt_regs *ctx) {
    s32 ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state *state = bpf_map_lookup_elem(&kafka_ops, &pid_tgid);
    if (!state) return 0;
    
    struct kafka_produce_event *event = bpf_ringbuf_reserve(&kafka_produce_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&kafka_ops, &pid_tgid);
        return 0;
    }
    
    event->type = EVENT_TYPE_KAFKA_PRODUCE;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->api_key = KAFKA_API_PRODUCE;
    event->partition = state->partition;
    event->message_count = state->message_count;
    
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    if (ret != 0) {  // RD_KAFKA_RESP_ERR_NO_ERROR = 0
        event->has_error = 1;
        event->error_code = ret;
    }
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&kafka_ops, &pid_tgid);
    
    return 0;
}

// rd_kafka_consume - Consume a single message
SEC("uprobe/rd_kafka_consume")
int trace_rd_kafka_consume(struct pt_regs *ctx) {
    void *rkt = (void *)PT_REGS_PARM1(ctx);          // Topic handle
    s32 partition = PT_REGS_PARM2(ctx);              // Partition
    s32 timeout_ms = PT_REGS_PARM3(ctx);             // Timeout
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.op_type = KAFKA_OP_FETCH;
    state.partition = partition;
    
    bpf_map_update_elem(&kafka_ops, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// rd_kafka_consume return
SEC("uretprobe/rd_kafka_consume")
int trace_rd_kafka_consume_ret(struct pt_regs *ctx) {
    void *msg = (void *)PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state *state = bpf_map_lookup_elem(&kafka_ops, &pid_tgid);
    if (!state) return 0;
    
    struct kafka_fetch_event *event = bpf_ringbuf_reserve(&kafka_fetch_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&kafka_ops, &pid_tgid);
        return 0;
    }
    
    event->type = EVENT_TYPE_KAFKA_FETCH;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->api_key = KAFKA_API_FETCH;
    event->partition = state->partition;
    
    __builtin_memcpy(event->topic, state->topic, sizeof(event->topic));
    
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    if (msg) {
        event->message_count = 1;
        // Could read offset/length from rd_kafka_message_t structure
    } else {
        event->has_error = 1;
    }
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&kafka_ops, &pid_tgid);
    
    return 0;
}

// rd_kafka_consumer_poll - Poll for messages (modern consumer API)
SEC("uprobe/rd_kafka_consumer_poll")
int trace_rd_kafka_consumer_poll(struct pt_regs *ctx) {
    void *rk = (void *)PT_REGS_PARM1(ctx);           // Kafka handle
    s32 timeout_ms = PT_REGS_PARM2(ctx);             // Timeout
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.op_type = KAFKA_OP_FETCH;
    
    bpf_map_update_elem(&kafka_ops, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// rd_kafka_consumer_poll return
SEC("uretprobe/rd_kafka_consumer_poll")
int trace_rd_kafka_consumer_poll_ret(struct pt_regs *ctx) {
    void *msg = (void *)PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state *state = bpf_map_lookup_elem(&kafka_ops, &pid_tgid);
    if (!state) return 0;
    
    // Only emit event if we got a message
    if (!msg) {
        bpf_map_delete_elem(&kafka_ops, &pid_tgid);
        return 0;
    }
    
    struct kafka_fetch_event *event = bpf_ringbuf_reserve(&kafka_fetch_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&kafka_ops, &pid_tgid);
        return 0;
    }
    
    event->type = EVENT_TYPE_KAFKA_FETCH;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->api_key = KAFKA_API_FETCH;
    event->message_count = 1;
    
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&kafka_ops, &pid_tgid);
    
    return 0;
}

// rd_kafka_commit - Commit offsets
SEC("uprobe/rd_kafka_commit")
int trace_rd_kafka_commit(struct pt_regs *ctx) {
    void *rk = (void *)PT_REGS_PARM1(ctx);           // Kafka handle
    void *offsets = (void *)PT_REGS_PARM2(ctx);      // Offset list
    s32 async = PT_REGS_PARM3(ctx);                  // Async flag
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.op_type = KAFKA_OP_COMMIT;
    
    bpf_map_update_elem(&kafka_ops, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// rd_kafka_commit return
SEC("uretprobe/rd_kafka_commit")
int trace_rd_kafka_commit_ret(struct pt_regs *ctx) {
    s32 ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state *state = bpf_map_lookup_elem(&kafka_ops, &pid_tgid);
    if (!state) return 0;
    
    struct kafka_commit_event *event = bpf_ringbuf_reserve(&kafka_commit_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&kafka_ops, &pid_tgid);
        return 0;
    }
    
    event->type = EVENT_TYPE_KAFKA_COMMIT;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->api_key = KAFKA_API_OFFSET_COMMIT;
    
    __builtin_memcpy(event->group_id, state->group_id, sizeof(event->group_id));
    
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    if (ret != 0) {
        event->has_error = 1;
        event->error_code = ret;
    }
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&kafka_ops, &pid_tgid);
    
    return 0;
}

// rd_kafka_commit_message - Commit a specific message's offset
SEC("uprobe/rd_kafka_commit_message")
int trace_rd_kafka_commit_message(struct pt_regs *ctx) {
    void *rk = (void *)PT_REGS_PARM1(ctx);           // Kafka handle
    void *rkmessage = (void *)PT_REGS_PARM2(ctx);    // Message
    s32 async = PT_REGS_PARM3(ctx);                  // Async flag
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state state = {};
    state.start_time = bpf_ktime_get_ns();
    state.op_type = KAFKA_OP_COMMIT;
    
    // Could extract offset from rkmessage structure
    
    bpf_map_update_elem(&kafka_ops, &pid_tgid, &state, BPF_ANY);
    return 0;
}

// rd_kafka_commit_message return
SEC("uretprobe/rd_kafka_commit_message")
int trace_rd_kafka_commit_message_ret(struct pt_regs *ctx) {
    s32 ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct kafka_op_state *state = bpf_map_lookup_elem(&kafka_ops, &pid_tgid);
    if (!state) return 0;
    
    struct kafka_commit_event *event = bpf_ringbuf_reserve(&kafka_commit_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&kafka_ops, &pid_tgid);
        return 0;
    }
    
    event->type = EVENT_TYPE_KAFKA_COMMIT;
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - state->start_time;
    event->api_key = KAFKA_API_OFFSET_COMMIT;
    event->committed_offset = state->offset;
    
    event->pid.host_pid = pid_tgid >> 32;
    event->pid.host_tid = pid_tgid & 0xFFFFFFFF;
    
    if (ret != 0) {
        event->has_error = 1;
        event->error_code = ret;
    }
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&kafka_ops, &pid_tgid);
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
