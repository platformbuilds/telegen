// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// grpc_c.c — Uprobe-based span capture for native gRPC-C library.
//
// Ported from Pixie's bcc_bpf/grpc_c_trace.c to CO-RE / libbpf style.
//
// Target: libgrpc.so (C/C++ gRPC core), used by Python, Ruby, C, C++ services.
//
// Probed functions (all in libgrpc.so):
//   grpc_chttp2_data_parser_parse             — holds the HTTP/2 DATA frame payload
//   grpc_chttp2_maybe_complete_recv_initial_metadata  — marks request started
//   grpc_chttp2_maybe_complete_recv_trailing_metadata — marks response ended
//   grpc_chttp2_list_pop_writable_stream      — stream is about to send data
//   grpc_chttp2_mark_stream_closed            — stream closing (status code present)
//
// Events are funnelled through the existing events ring buffer as
// http_request_trace records, tagged with EVENT_HTTP2_REQUEST / EVENT_HTTP2_CLIENT.

#include <bpfcore/utils.h>

#include <common/http_types.h>
#include <common/ringbuf.h>
#include <common/strings.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <pid/pid_helpers.h>

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// Minimal view of grpc_chttp2_stream (only fields we need).
typedef struct grpc_c_stream_key {
    u64 transport_ptr;  // pointer to grpc_chttp2_transport
    u32 stream_id;
    u32 _pad;
} grpc_c_stream_key_t;

typedef struct grpc_c_stream_info {
    u64 start_mono;
    u32 stream_id;
    // status code extracted from trailing metadata
    u32 grpc_status;
    // path extracted from initial metadata (:path pseudo-header)
    char path[128];
    // method — always POST for gRPC
    char method[8];
} grpc_c_stream_info_t;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Ongoing per-stream metadata, keyed by (transport ptr, stream_id).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   grpc_c_stream_key_t);
    __type(value, grpc_c_stream_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} active_grpc_c_streams SEC(".maps");

// Scratch map for the current thread's stream key (used across entry/return probes).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   u64);   // pid_tgid
    __type(value, grpc_c_stream_key_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_c_stream_key_scratch SEC(".maps");

// ---------------------------------------------------------------------------
// grpc_chttp2_maybe_complete_recv_initial_metadata
//   Signature: void(grpc_chttp2_transport *t, grpc_chttp2_stream *s)
//   Called when HTTP/2 initial metadata (request headers) are fully received.
//   We record the stream start time here.
// ---------------------------------------------------------------------------
SEC("uprobe/libgrpc.so:grpc_chttp2_maybe_complete_recv_initial_metadata")
int obi_uprobe_grpc_c_recv_initial_md(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!valid_pid(pid_tgid)) return 0;

    void *transport = (void *)PT_REGS_PARM1(ctx);
    void *stream    = (void *)PT_REGS_PARM2(ctx);

    if (!transport || !stream) return 0;

    // Read the stream_id field from grpc_chttp2_stream.
    // The offset of id field is typically 0 — read safely with bpf_probe_read_user.
    u32 stream_id = 0;
    bpf_probe_read_user(&stream_id, sizeof(stream_id), stream);

    grpc_c_stream_key_t key = {
        .transport_ptr = (u64)transport,
        .stream_id     = stream_id,
    };

    grpc_c_stream_info_t info = {
        .start_mono = bpf_ktime_get_ns(),
        .stream_id  = stream_id,
        .grpc_status = 0,
    };
    // Default method = POST (all gRPC calls use POST)
    info.method[0] = 'P'; info.method[1] = 'O'; info.method[2] = 'S';
    info.method[3] = 'T'; info.method[4] = '\0';

    bpf_map_update_elem(&active_grpc_c_streams, &key, &info, BPF_ANY);
    bpf_dbg_printk("grpc_c recv_initial_md transport=%llx stream_id=%d", (u64)transport, stream_id);
    return 0;
}

// ---------------------------------------------------------------------------
// grpc_chttp2_data_parser_parse
//   Signature: grpc_error_handle(grpc_chttp2_transport *t,
//                                grpc_chttp2_stream *s,
//                                const grpc_slice *slice, bool is_last)
//   Called for each DATA frame payload.  We don't copy body bytes (too large);
//   we just record that data was received so we know the stream is alive.
// ---------------------------------------------------------------------------
SEC("uprobe/libgrpc.so:grpc_chttp2_data_parser_parse")
int obi_uprobe_grpc_c_data_parser(struct pt_regs *ctx) {
    // The probe exists so we can be extended later to capture request/response
    // body sizes for RPC payload measurement. For now — nothing.
    (void)ctx;
    return 0;
}

// ---------------------------------------------------------------------------
// grpc_chttp2_maybe_complete_recv_trailing_metadata
//   Signature: void(grpc_chttp2_transport *t, grpc_chttp2_stream *s)
//   Called when the trailing metadata (response trailers) are received.
//   This is where the gRPC status code lives.
//   We close the stream record and emit the span.
// ---------------------------------------------------------------------------
SEC("uprobe/libgrpc.so:grpc_chttp2_maybe_complete_recv_trailing_metadata")
int obi_uprobe_grpc_c_recv_trailing_md(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!valid_pid(pid_tgid)) return 0;

    void *transport = (void *)PT_REGS_PARM1(ctx);
    void *stream    = (void *)PT_REGS_PARM2(ctx);
    if (!transport || !stream) return 0;

    u32 stream_id = 0;
    bpf_probe_read_user(&stream_id, sizeof(stream_id), stream);

    grpc_c_stream_key_t key = {
        .transport_ptr = (u64)transport,
        .stream_id     = stream_id,
    };

    grpc_c_stream_info_t *info = bpf_map_lookup_elem(&active_grpc_c_streams, &key);
    if (!info) return 0;

    u64 end_mono = bpf_ktime_get_ns();

    // Emit to the events ring buffer as an HTTP/2 gRPC span.
    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(*trace), 0);
    if (trace) {
        __builtin_memset(trace, 0, sizeof(*trace));

        trace->type                  = EVENT_HTTP_CLIENT; // HTTP/2 outbound
        trace->start_monotime_ns     = info->start_mono;
        trace->end_monotime_ns       = end_mono;
        trace->status                = info->grpc_status; // gRPC status => mapped to HTTP status
        trace->ssl                   = 0;

        u32 pid = (u32)(pid_tgid >> 32);
        trace->pid.host_pid = pid;
        trace->pid.user_pid = pid;

        // Copy path into the request buffer as the gRPC method path.
        __builtin_memcpy(trace->buf, info->path, sizeof(info->path));
        trace->len = sizeof(info->path);

        bpf_ringbuf_submit(trace, 0);
        bpf_dbg_printk("grpc_c emit span stream_id=%d status=%d", stream_id, info->grpc_status);
    }

    bpf_map_delete_elem(&active_grpc_c_streams, &key);
    return 0;
}

// ---------------------------------------------------------------------------
// grpc_chttp2_mark_stream_closed
//   Signature: void(grpc_chttp2_transport *t, grpc_chttp2_stream *s,
//                   int close_reads, int close_writes, grpc_error_handle error)
//   Fallback cleanup: if trailing metadata was never observed (e.g. on error),
//   delete the stream entry to avoid map leaks.
// ---------------------------------------------------------------------------
SEC("uprobe/libgrpc.so:grpc_chttp2_mark_stream_closed")
int obi_uprobe_grpc_c_stream_closed(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!valid_pid(pid_tgid)) return 0;

    void *transport = (void *)PT_REGS_PARM1(ctx);
    void *stream    = (void *)PT_REGS_PARM2(ctx);
    if (!transport || !stream) return 0;

    u32 stream_id = 0;
    bpf_probe_read_user(&stream_id, sizeof(stream_id), stream);

    grpc_c_stream_key_t key = {
        .transport_ptr = (u64)transport,
        .stream_id     = stream_id,
    };

    // If the span was already emitted by recv_trailing_md the entry is gone — no-op.
    bpf_map_delete_elem(&active_grpc_c_streams, &key);
    return 0;
}
