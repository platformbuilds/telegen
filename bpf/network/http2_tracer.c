// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Telegen v2.0 - HTTP/2 Frame Tracer
// Trace HTTP/2 frames including gRPC
// Tasks: NET-012, NET-013, NET-014

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_endian.h>

#include <logger/bpf_dbg.h>
#include <pid/pid_helpers.h>

// HTTP/2 Frame Types (NET-012)
#define HTTP2_DATA          0x0
#define HTTP2_HEADERS       0x1
#define HTTP2_PRIORITY      0x2
#define HTTP2_RST_STREAM    0x3
#define HTTP2_SETTINGS      0x4
#define HTTP2_PUSH_PROMISE  0x5
#define HTTP2_PING          0x6
#define HTTP2_GOAWAY        0x7
#define HTTP2_WINDOW_UPDATE 0x8
#define HTTP2_CONTINUATION  0x9

// HTTP/2 Frame Flags
#define HTTP2_FLAG_END_STREAM  0x01
#define HTTP2_FLAG_END_HEADERS 0x04
#define HTTP2_FLAG_PADDED      0x08
#define HTTP2_FLAG_PRIORITY    0x20

// HTTP/2 Error Codes
#define HTTP2_NO_ERROR            0x0
#define HTTP2_PROTOCOL_ERROR      0x1
#define HTTP2_INTERNAL_ERROR      0x2
#define HTTP2_FLOW_CONTROL_ERROR  0x3
#define HTTP2_SETTINGS_TIMEOUT    0x4
#define HTTP2_STREAM_CLOSED       0x5
#define HTTP2_FRAME_SIZE_ERROR    0x6
#define HTTP2_REFUSED_STREAM      0x7
#define HTTP2_CANCEL              0x8
#define HTTP2_COMPRESSION_ERROR   0x9
#define HTTP2_CONNECT_ERROR       0xa
#define HTTP2_ENHANCE_YOUR_CALM   0xb
#define HTTP2_INADEQUATE_SECURITY 0xc
#define HTTP2_HTTP_1_1_REQUIRED   0xd

// HPACK static table indices (NET-013)
#define HPACK_METHOD_GET    2
#define HPACK_METHOD_POST   3
#define HPACK_PATH_ROOT     4
#define HPACK_PATH_INDEX    5
#define HPACK_SCHEME_HTTP   6
#define HPACK_SCHEME_HTTPS  7
#define HPACK_STATUS_200    8
#define HPACK_STATUS_204    9
#define HPACK_STATUS_206    10
#define HPACK_STATUS_304    11
#define HPACK_STATUS_400    12
#define HPACK_STATUS_404    13
#define HPACK_STATUS_500    14
#define HPACK_AUTHORITY     1
#define HPACK_METHOD        2
#define HPACK_PATH          4
#define HPACK_SCHEME        6
#define HPACK_STATUS        8
#define HPACK_CONTENT_TYPE  31

// Max lengths
#define HTTP2_MAX_METHOD_LEN     16
#define HTTP2_MAX_PATH_LEN       256
#define HTTP2_MAX_AUTHORITY_LEN  128
#define HTTP2_MAX_CONTENT_TYPE   64
#define GRPC_MAX_SERVICE_LEN     128
#define GRPC_MAX_METHOD_LEN      64
#define GRPC_MAX_MESSAGE_LEN     256

// HTTP/2 frame header (9 bytes)
struct http2_frame_header {
    __u8  length[3];     // 24-bit length
    __u8  type;
    __u8  flags;
    __u8  stream_id[4];  // 31-bit stream ID (MSB is reserved)
} __attribute__((packed));

// HTTP/2 event structure
struct http2_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    
    // Connection info
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 fd;
    
    // Frame info
    __u8  frame_type;
    __u8  frame_flags;
    __u8  _pad1[2];
    __u32 stream_id;
    __u32 frame_length;
    
    // Parsed headers (for HEADERS frames)
    char method[HTTP2_MAX_METHOD_LEN];
    char path[HTTP2_MAX_PATH_LEN];
    char authority[HTTP2_MAX_AUTHORITY_LEN];
    char content_type[HTTP2_MAX_CONTENT_TYPE];
    __u32 status_code;
    
    // gRPC specific (NET-014)
    __u8  is_grpc;
    __u8  _pad2[3];
    char grpc_service[GRPC_MAX_SERVICE_LEN];
    char grpc_method[GRPC_MAX_METHOD_LEN];
    __s32 grpc_status;
    char grpc_message[GRPC_MAX_MESSAGE_LEN];
    
    // Timing
    __u64 stream_start_ns;
    __u64 first_byte_ns;
    __u64 last_byte_ns;
    
    // Sizes
    __u64 request_bytes;
    __u64 response_bytes;
    
    // Trace context
    __u8 trace_id[16];
    __u8 span_id[8];
    
    // Process info
    char comm[16];
};

// Stream state for tracking in-flight requests
struct stream_state {
    __u64 start_time;
    __u64 first_data_time;
    __u64 request_end_time;
    __u64 request_bytes;
    __u64 response_bytes;
    __u32 status_code;
    __u8  method[HTTP2_MAX_METHOD_LEN];
    __u8  path[HTTP2_MAX_PATH_LEN];
    __u8  authority[HTTP2_MAX_AUTHORITY_LEN];
    __u8  content_type[HTTP2_MAX_CONTENT_TYPE];
    __u8  is_grpc;
    __u8  request_end_stream;
    __u8  response_end_stream;
    __u8  _pad;
    __u8  grpc_service[GRPC_MAX_SERVICE_LEN];
    __u8  grpc_method[GRPC_MAX_METHOD_LEN];
    __u8  trace_id[16];
    __u8  span_id[8];
};

// Stream key
struct stream_key {
    __u32 pid;
    __u32 fd;
    __u32 stream_id;
    __u8  _pad[4];
};

// Connection key
struct conn_key {
    __u32 pid;
    __u32 fd;
};

// Connection state
struct conn_state {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 created_ns;
    __u8  is_client;
    __u8  _pad[7];
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct stream_key));
    __uint(value_size, sizeof(struct stream_state));
    __uint(max_entries, 100000);
} http2_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct conn_key));
    __uint(value_size, sizeof(struct conn_state));
    __uint(max_entries, 50000);
} http2_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024);  // 32MB
} http2_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct http2_event));
    __uint(max_entries, 1);
} http2_event_buffer SEC(".maps");

// Configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 4);
} http2_config SEC(".maps");

#define HTTP2_CONFIG_ENABLED      0
#define HTTP2_CONFIG_CAPTURE_DATA 1
#define HTTP2_CONFIG_GRPC_ONLY    2

// Parse 24-bit big-endian length
static __always_inline __u32 parse_frame_length(const __u8 *len) {
    return ((__u32)len[0] << 16) | ((__u32)len[1] << 8) | (__u32)len[2];
}

// Parse 31-bit big-endian stream ID (ignore reserved bit)
static __always_inline __u32 parse_stream_id(const __u8 *id) {
    return (((__u32)id[0] & 0x7F) << 24) | ((__u32)id[1] << 16) | 
           ((__u32)id[2] << 8) | (__u32)id[3];
}

// Detect gRPC from content-type header (NET-014)
static __always_inline int is_grpc_content_type(const char *content_type, int len) {
    // Check for "application/grpc"
    if (len >= 16) {
        const char expected[] = "application/grpc";
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            if (content_type[i] != expected[i]) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

// Parse gRPC path: /package.Service/Method (NET-014)
static __always_inline void parse_grpc_path(const char *path, int path_len,
                                             char *service, char *method) {
    int start = 0;
    int last_slash = -1;
    
    // Skip leading slash
    if (path_len > 0 && path[0] == '/') {
        start = 1;
    }
    
    // Find the last slash
    #pragma unroll
    for (int i = start; i < path_len && i < HTTP2_MAX_PATH_LEN; i++) {
        if (path[i] == '/') {
            last_slash = i;
        }
        if (path[i] == '\0') {
            break;
        }
    }
    
    if (last_slash > start) {
        // Copy service name
        int service_len = last_slash - start;
        if (service_len >= GRPC_MAX_SERVICE_LEN) {
            service_len = GRPC_MAX_SERVICE_LEN - 1;
        }
        
        #pragma unroll
        for (int i = 0; i < service_len && i < GRPC_MAX_SERVICE_LEN - 1; i++) {
            if (start + i < HTTP2_MAX_PATH_LEN) {
                service[i] = path[start + i];
            }
        }
        
        // Copy method name
        int method_start = last_slash + 1;
        int method_idx = 0;
        #pragma unroll
        for (int i = method_start; i < path_len && method_idx < GRPC_MAX_METHOD_LEN - 1; i++) {
            if (path[i] == '\0') break;
            method[method_idx++] = path[i];
        }
    }
}

// Parse HPACK header (simplified) (NET-013)
// Full HPACK is complex; this handles common static table entries
static __always_inline int parse_hpack_byte(__u8 byte, struct stream_state *state) {
    // Indexed Header Field (starts with 1)
    if (byte & 0x80) {
        __u8 index = byte & 0x7F;
        
        switch (index) {
            case HPACK_METHOD_GET:
                __builtin_memcpy(state->method, "GET", 4);
                break;
            case HPACK_METHOD_POST:
                __builtin_memcpy(state->method, "POST", 5);
                break;
            case HPACK_PATH_ROOT:
                __builtin_memcpy(state->path, "/", 2);
                break;
        }
    }
    
    return 0;
}

// Process HTTP/2 frame
static __always_inline int process_http2_frame(struct pt_regs *ctx,
                                                 const __u8 *data, __u32 len,
                                                 __u32 fd, int direction) {
    if (len < 9) {  // Minimum frame size
        return 0;
    }
    
    // Read frame header
    struct http2_frame_header hdr = {};
    if (bpf_probe_read_user(&hdr, sizeof(hdr), data) < 0) {
        return 0;
    }
    
    __u32 frame_length = parse_frame_length(hdr.length);
    __u32 stream_id = parse_stream_id(hdr.stream_id);
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct stream_key key = {
        .pid = pid,
        .fd = fd,
        .stream_id = stream_id,
    };
    
    __u64 now = bpf_ktime_get_ns();
    
    // Handle different frame types
    switch (hdr.type) {
        case HTTP2_HEADERS: {
            // Create or update stream state
            struct stream_state *state = bpf_map_lookup_elem(&http2_streams, &key);
            if (!state && stream_id != 0) {
                struct stream_state new_state = {};
                new_state.start_time = now;
                bpf_map_update_elem(&http2_streams, &key, &new_state, BPF_ANY);
            }
            
            // Check for END_STREAM flag
            if (hdr.flags & HTTP2_FLAG_END_STREAM) {
                state = bpf_map_lookup_elem(&http2_streams, &key);
                if (state) {
                    if (direction == 0) {  // Request
                        state->request_end_stream = 1;
                        state->request_end_time = now;
                    } else {  // Response
                        state->response_end_stream = 1;
                    }
                }
            }
            break;
        }
        
        case HTTP2_DATA: {
            struct stream_state *state = bpf_map_lookup_elem(&http2_streams, &key);
            if (state) {
                if (state->first_data_time == 0) {
                    state->first_data_time = now;
                }
                
                if (direction == 0) {
                    state->request_bytes += frame_length;
                } else {
                    state->response_bytes += frame_length;
                }
                
                // Check for END_STREAM
                if (hdr.flags & HTTP2_FLAG_END_STREAM) {
                    if (direction == 0) {
                        state->request_end_stream = 1;
                    } else {
                        state->response_end_stream = 1;
                    }
                }
            }
            break;
        }
        
        case HTTP2_RST_STREAM:
        case HTTP2_GOAWAY: {
            // Stream/connection error - emit event and cleanup
            struct stream_state *state = bpf_map_lookup_elem(&http2_streams, &key);
            if (state) {
                // Emit completion event
                __u32 zero = 0;
                struct http2_event *event = bpf_map_lookup_elem(&http2_event_buffer, &zero);
                if (event) {
                    __builtin_memset(event, 0, sizeof(*event));
                    event->timestamp = now;
                    event->pid = pid;
                    event->tid = pid_tgid & 0xFFFFFFFF;
                    event->fd = fd;
                    event->frame_type = hdr.type;
                    event->frame_flags = hdr.flags;
                    event->stream_id = stream_id;
                    event->frame_length = frame_length;
                    event->stream_start_ns = state->start_time;
                    event->first_byte_ns = state->first_data_time;
                    event->last_byte_ns = now;
                    event->request_bytes = state->request_bytes;
                    event->response_bytes = state->response_bytes;
                    event->is_grpc = state->is_grpc;
                    
                    __builtin_memcpy(event->method, state->method, HTTP2_MAX_METHOD_LEN);
                    __builtin_memcpy(event->path, state->path, HTTP2_MAX_PATH_LEN);
                    
                    bpf_get_current_comm(event->comm, sizeof(event->comm));
                    
                    struct http2_event *rb_event = bpf_ringbuf_reserve(&http2_events, 
                                                                        sizeof(*rb_event), 0);
                    if (rb_event) {
                        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
                        bpf_ringbuf_submit(rb_event, 0);
                    }
                }
                
                bpf_map_delete_elem(&http2_streams, &key);
            }
            break;
        }
        
        case HTTP2_WINDOW_UPDATE:
        case HTTP2_PING:
        case HTTP2_SETTINGS:
            // Control frames - no action needed for tracing
            break;
    }
    
    // Check if stream is complete (both sides sent END_STREAM)
    if (stream_id != 0) {
        struct stream_state *state = bpf_map_lookup_elem(&http2_streams, &key);
        if (state && state->request_end_stream && state->response_end_stream) {
            // Emit completion event
            __u32 zero = 0;
            struct http2_event *event = bpf_map_lookup_elem(&http2_event_buffer, &zero);
            if (event) {
                __builtin_memset(event, 0, sizeof(*event));
                event->timestamp = now;
                event->pid = pid;
                event->tid = pid_tgid & 0xFFFFFFFF;
                event->fd = fd;
                event->frame_type = HTTP2_DATA;
                event->stream_id = stream_id;
                event->stream_start_ns = state->start_time;
                event->first_byte_ns = state->first_data_time;
                event->last_byte_ns = now;
                event->request_bytes = state->request_bytes;
                event->response_bytes = state->response_bytes;
                event->is_grpc = state->is_grpc;
                event->status_code = state->status_code;
                
                __builtin_memcpy(event->method, state->method, HTTP2_MAX_METHOD_LEN);
                __builtin_memcpy(event->path, state->path, HTTP2_MAX_PATH_LEN);
                __builtin_memcpy(event->authority, state->authority, HTTP2_MAX_AUTHORITY_LEN);
                __builtin_memcpy(event->grpc_service, state->grpc_service, GRPC_MAX_SERVICE_LEN);
                __builtin_memcpy(event->grpc_method, state->grpc_method, GRPC_MAX_METHOD_LEN);
                __builtin_memcpy(event->trace_id, state->trace_id, 16);
                __builtin_memcpy(event->span_id, state->span_id, 8);
                
                bpf_get_current_comm(event->comm, sizeof(event->comm));
                
                struct http2_event *rb_event = bpf_ringbuf_reserve(&http2_events,
                                                                    sizeof(*rb_event), 0);
                if (rb_event) {
                    __builtin_memcpy(rb_event, event, sizeof(*rb_event));
                    bpf_ringbuf_submit(rb_event, 0);
                }
            }
            
            bpf_map_delete_elem(&http2_streams, &key);
        }
    }
    
    return 0;
}

// Trace SSL_write for encrypted HTTP/2 (client sending)
SEC("uprobe/SSL_write")
int trace_ssl_write(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    
    if (!buf || num < 9) {
        return 0;
    }
    
    // Get FD from SSL context (implementation specific)
    // For now, use a placeholder
    __u32 fd = 0;
    
    process_http2_frame(ctx, buf, num, fd, 0);  // direction = 0 (sending)
    
    return 0;
}

// Trace SSL_read for encrypted HTTP/2 (client receiving)
SEC("uretprobe/SSL_read")
int trace_ssl_read_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    
    if (ret <= 0) {
        return 0;
    }
    
    // Would need to get buffer from entry probe
    // For demonstration, this shows the pattern
    
    return 0;
}

// Trace nghttp2 library (commonly used HTTP/2 implementation)
SEC("uprobe/nghttp2_session_mem_recv")
int trace_nghttp2_recv(struct pt_regs *ctx) {
    void *session = (void *)PT_REGS_PARM1(ctx);
    const __u8 *data = (const __u8 *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    
    if (!data || len < 9) {
        return 0;
    }
    
    // Process the received HTTP/2 frames
    process_http2_frame(ctx, data, len, 0, 1);  // direction = 1 (receiving)
    
    return 0;
}

SEC("uprobe/nghttp2_session_mem_send")
int trace_nghttp2_send(struct pt_regs *ctx) {
    void *session = (void *)PT_REGS_PARM1(ctx);
    
    // nghttp2_session_mem_send returns a pointer to the data to send
    // We'd need the return probe to get the actual data
    
    return 0;
}

// Hook Go's HTTP/2 implementation
SEC("uprobe/go_http2_Framer_WriteHeaders")
int trace_go_http2_write_headers(struct pt_regs *ctx) {
    // Go runtime specific - would need offset table
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
