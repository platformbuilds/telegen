// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0
// Task: ML-011 - LLM Request Interceptor eBPF Tracer

//go:build obi_bpf_ignore

#include "../bpfcore/vmlinux.h"
#include "../bpfcore/bpf_helpers.h"
#include "../bpfcore/bpf_tracing.h"
#include "../bpfcore/bpf_core_read.h"
#include "../common/common.h"

#include "llm_tracer.h"

// Force bpf2go to include these types
const llm_event_t *unused_llm_event __attribute__((unused));

// Request tracking structure
struct llm_request {
    u64 start_time;        // Request start timestamp
    u64 first_token_time;  // First token timestamp
    u32 pid;
    u32 tid;
    u32 provider;
    u32 is_streaming;
    u32 chunk_count;
    u8 request_id[36];
    u8 model[LLM_MAX_MODEL_LEN];
    u8 endpoint[LLM_MAX_ENDPOINT_LEN];
};

// Map to track active LLM requests by connection
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // Connection ID (socket or fd)
    __type(value, struct llm_request);
} llm_active_requests SEC(".maps");

// Ring buffer for LLM events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB buffer
} llm_events SEC(".maps");

// Map for known LLM endpoints
struct llm_endpoint_key {
    u8 host[128];
    u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct llm_endpoint_key);
    __type(value, u32);  // Provider type
} llm_endpoints SEC(".maps");

// Token count extraction patterns
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u8[64]);  // Pattern strings
} token_patterns SEC(".maps");

// Helper to detect LLM provider from endpoint
static __always_inline u32 detect_llm_provider(const u8 *host, u16 port) {
    // Check common API endpoints
    // OpenAI: api.openai.com
    // Anthropic: api.anthropic.com
    // Azure: *.openai.azure.com
    // Google: generativelanguage.googleapis.com
    
    // This is a simplified check - real implementation would do full matching
    struct llm_endpoint_key key = {};
    bpf_probe_read_kernel(&key.host, sizeof(key.host), host);
    key.port = port;
    
    u32 *provider = bpf_map_lookup_elem(&llm_endpoints, &key);
    if (provider) {
        return *provider;
    }
    
    return LLM_PROVIDER_UNKNOWN;
}

// Helper to generate a simple request ID
static __always_inline void generate_request_id(u8 *id) {
    u64 ts = bpf_ktime_get_ns();
    u32 random = bpf_get_prandom_u32();
    
    // Simple hex encoding of timestamp and random
    // Real implementation would use proper UUID format
    __builtin_memset(id, 0, 36);
    id[0] = '0' + (ts % 10);
    id[1] = '0' + ((ts / 10) % 10);
    id[2] = '0' + ((ts / 100) % 10);
    id[3] = '0' + ((ts / 1000) % 10);
    // ... simplified for eBPF
}

// Submit an LLM event to the ring buffer
static __always_inline int submit_llm_event(llm_event_t *event) {
    llm_event_t *e = bpf_ringbuf_reserve(&llm_events, sizeof(*event), 0);
    if (!e) {
        return -1;
    }
    
    __builtin_memcpy(e, event, sizeof(*event));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Track HTTP/2 frame for HTTPS LLM API calls
SEC("uprobe/http2_write_frame")
int BPF_UPROBE(http2_write_frame, void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    
    // Create new request tracking entry
    struct llm_request req = {};
    req.start_time = bpf_ktime_get_ns();
    req.pid = pid;
    req.tid = tid;
    generate_request_id(req.request_id);
    
    // Use connection ID as key
    u64 conn_id = pid_tgid;  // Simplified - real would use socket/fd
    bpf_map_update_elem(&llm_active_requests, &conn_id, &req, BPF_ANY);
    
    // Submit request start event
    llm_event_t event = {};
    event.timestamp_ns = req.start_time;
    event.pid = pid;
    event.tid = tid;
    event.event_type = LLM_EVENT_REQUEST_START;
    __builtin_memcpy(event.request_id, req.request_id, 36);
    
    submit_llm_event(&event);
    
    return 0;
}

// Track HTTP response for LLM completions
SEC("uprobe/http_read_response")
int BPF_UPROBE(http_read_response, void *resp) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 conn_id = pid_tgid;
    
    struct llm_request *req = bpf_map_lookup_elem(&llm_active_requests, &conn_id);
    if (!req) {
        return 0;
    }
    
    u64 now = bpf_ktime_get_ns();
    u64 duration = now - req->start_time;
    
    llm_event_t event = {};
    event.timestamp_ns = now;
    event.duration_ns = duration;
    event.pid = req->pid;
    event.tid = req->tid;
    event.event_type = LLM_EVENT_REQUEST_END;
    event.provider = req->provider;
    event.is_streaming = req->is_streaming;
    __builtin_memcpy(event.request_id, req->request_id, 36);
    __builtin_memcpy(event.model, req->model, LLM_MAX_MODEL_LEN);
    
    // Calculate TTFT if streaming
    if (req->is_streaming && req->first_token_time > 0) {
        event.ttft_ns = req->first_token_time - req->start_time;
    }
    
    submit_llm_event(&event);
    
    // Clean up request tracking
    bpf_map_delete_elem(&llm_active_requests, &conn_id);
    
    return 0;
}

// Track streaming chunks (SSE events)
SEC("uprobe/sse_event")
int BPF_UPROBE(sse_event, void *data, int len) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 conn_id = pid_tgid;
    
    struct llm_request *req = bpf_map_lookup_elem(&llm_active_requests, &conn_id);
    if (!req || !req->is_streaming) {
        return 0;
    }
    
    u64 now = bpf_ktime_get_ns();
    
    // Track first token time
    if (req->chunk_count == 0) {
        req->first_token_time = now;
        
        llm_event_t event = {};
        event.timestamp_ns = now;
        event.ttft_ns = now - req->start_time;
        event.pid = req->pid;
        event.tid = req->tid;
        event.event_type = LLM_EVENT_FIRST_TOKEN;
        event.provider = req->provider;
        __builtin_memcpy(event.request_id, req->request_id, 36);
        
        submit_llm_event(&event);
    }
    
    req->chunk_count++;
    
    return 0;
}

// Python OpenAI library instrumentation
SEC("uprobe/python_openai_create")
int BPF_UPROBE(python_openai_create, void *self, void *kwargs) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    
    struct llm_request req = {};
    req.start_time = bpf_ktime_get_ns();
    req.pid = pid;
    req.tid = tid;
    req.provider = LLM_PROVIDER_OPENAI;
    generate_request_id(req.request_id);
    
    u64 conn_id = pid_tgid;
    bpf_map_update_elem(&llm_active_requests, &conn_id, &req, BPF_ANY);
    
    llm_event_t event = {};
    event.timestamp_ns = req.start_time;
    event.pid = pid;
    event.tid = tid;
    event.event_type = LLM_EVENT_REQUEST_START;
    event.provider = LLM_PROVIDER_OPENAI;
    __builtin_memcpy(event.request_id, req.request_id, 36);
    
    submit_llm_event(&event);
    
    return 0;
}

// Python Anthropic library instrumentation  
SEC("uprobe/python_anthropic_create")
int BPF_UPROBE(python_anthropic_create, void *self, void *kwargs) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    
    struct llm_request req = {};
    req.start_time = bpf_ktime_get_ns();
    req.pid = pid;
    req.tid = tid;
    req.provider = LLM_PROVIDER_ANTHROPIC;
    generate_request_id(req.request_id);
    
    u64 conn_id = pid_tgid;
    bpf_map_update_elem(&llm_active_requests, &conn_id, &req, BPF_ANY);
    
    llm_event_t event = {};
    event.timestamp_ns = req.start_time;
    event.pid = pid;
    event.tid = tid;
    event.event_type = LLM_EVENT_REQUEST_START;
    event.provider = LLM_PROVIDER_ANTHROPIC;
    __builtin_memcpy(event.request_id, req.request_id, 36);
    
    submit_llm_event(&event);
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
