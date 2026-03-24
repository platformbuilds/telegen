// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// go_tls.c — Uprobe-based plaintext capture for Go crypto/tls connections.
//
// Ported from Pixie's bcc_bpf/go_tls_trace.c to CO-RE / libbpf style.
//
// Approach:
//   1. Attach uprobes to crypto/tls.(*Conn).Write and crypto/tls.(*Conn).Read.
//   2. Key events by (tgid, goid) so we handle goroutine-level concurrency.
//   3. At the return probe, copy the plaintext bytes into the existing events ring
//      buffer using the same http_request_trace format that the rest of the
//      kernel-side pipeline uses, so the Go-side consumer can treat them
//      identically to non-TLS traffic.
//
// Symbol names targeted (Go ABI register calling convention, Go >= 1.17):
//   - go:crypto/tls.(*Conn).Write  (client → plaintext out)
//   - go:crypto/tls.(*Conn).Read   (received → plaintext in)

#include <bpfcore/utils.h>

#include <common/http_types.h>
#include <common/ringbuf.h>
#include <common/strings.h>
#include <common/tracing.h>

#include <gotracer/go_byte_arr.h>
#include <gotracer/go_common.h>
#include <gotracer/go_offsets.h>
#include <gotracer/go_str.h>
#include <gotracer/go_stream_key.h>

#include <logger/bpf_dbg.h>

#include <pid/pid_helpers.h>

// -----------------------------------------------------------------------
// Map: per-goroutine state for in-flight TLS Write / Read calls.
// Key: (tgid << 32 | goid) as u64.  Value: pointer to tls.Conn + buf ptr.
// -----------------------------------------------------------------------
typedef struct go_tls_conn_args {
    u64 conn_ptr;     // pointer to *tls.Conn (goroutine-scoped connection)
    u64 buf_ptr;      // pointer to the caller's plaintext slice data
    u64 buf_len;      // declared length of the slice
    u64 start_mono;   // bpf_ktime_get_ns() at entry — for latency
} go_tls_conn_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   go_addr_key_t);         // pid + goroutine address
    __type(value, go_tls_conn_args_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} active_go_tls_write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   go_addr_key_t);
    __type(value, go_tls_conn_args_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} active_go_tls_read_args SEC(".maps");

// -----------------------------------------------------------------------
// Helper: fill a http_request_trace from a TLS plaintext buffer and
// submit it to the existing ring buffer so the Go consumer picks it up.
// -----------------------------------------------------------------------
static __always_inline void submit_go_tls_event(
        struct pt_regs *ctx,
        go_tls_conn_args_t *args,
        u64 pid_tgid,
        int n_bytes,
        u8 direction /* TCP_SEND or TCP_RECV */) {

    if (n_bytes <= 0 || args->buf_ptr == 0) return;

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(*trace), 0);
    if (!trace) return;

    __builtin_memset(trace, 0, sizeof(*trace));

    trace->type      = (direction == TCP_SEND) ? EVENT_HTTP_CLIENT : EVENT_HTTP_REQUEST;
    trace->start_monotime_ns = args->start_mono;
    trace->end_monotime_ns   = bpf_ktime_get_ns();

    // PID info
    u32 pid = (u32)(pid_tgid >> 32);
    trace->pid.host_pid  = pid;
    trace->pid.user_pid  = pid;
    trace->ssl           = 1; // flagged as "was TLS, now plaintext"

    // Copy up to FULL_BUF_SIZE bytes of plaintext.
    u32 copy_len = (u32)n_bytes;
    if (copy_len > FULL_BUF_SIZE) copy_len = FULL_BUF_SIZE;

    if (direction == TCP_SEND) {
        long r = bpf_probe_read_user(trace->buf, copy_len, (void *)args->buf_ptr);
        if (r < 0) {
            bpf_ringbuf_discard(trace, 0);
            return;
        }
        trace->len = copy_len;
    } else {
        long r = bpf_probe_read_user(trace->rbuf, copy_len, (void *)args->buf_ptr);
        if (r < 0) {
            bpf_ringbuf_discard(trace, 0);
            return;
        }
        trace->resp_len = copy_len;
    }

    bpf_ringbuf_submit(trace, 0);
}

// -----------------------------------------------------------------------
// uprobe: crypto/tls.(*Conn).Write(b []byte) (int, error)
//   Go register ABI (>= 1.17):
//     AX  = *tls.Conn receiver
//     BX  = slice data ptr
//     CX  = slice len
//     DX  = slice cap
// -----------------------------------------------------------------------
SEC("uprobe/crypto_tls_Conn_Write")
int obi_uprobe_go_tls_write(struct pt_regs *ctx) {
    u64 goroutine = (u64)GOROUTINE_PTR(ctx);
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 pid       = (u32)(pid_tgid >> 32);

    if (!valid_pid(pid_tgid)) return 0;

    go_tls_conn_args_t args = {
        .conn_ptr   = (u64)GO_PARAM1(ctx),
        .buf_ptr    = (u64)GO_PARAM2(ctx),
        .buf_len    = (u64)GO_PARAM3(ctx),
        .start_mono = bpf_ktime_get_ns(),
    };

    go_addr_key_t key = {};
    go_addr_key_from_id(&key, (void *)goroutine);
    key.pid = pid;

    bpf_map_update_elem(&active_go_tls_write_args, &key, &args, BPF_ANY);

    bpf_dbg_printk("go_tls_write entry conn=%llx buf=%llx len=%lld",
                   args.conn_ptr, args.buf_ptr, args.buf_len);
    return 0;
}

// -----------------------------------------------------------------------
// uretprobe: crypto/tls.(*Conn).Write return
//   Return register AX = n (bytes written), BX = error interface type ptr
// -----------------------------------------------------------------------
SEC("uprobe/crypto_tls_Conn_Write_ret")
int obi_uretprobe_go_tls_write(struct pt_regs *ctx) {
    u64 goroutine = (u64)GOROUTINE_PTR(ctx);
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 pid       = (u32)(pid_tgid >> 32);

    if (!valid_pid(pid_tgid)) return 0;

    go_addr_key_t key = {};
    go_addr_key_from_id(&key, (void *)goroutine);
    key.pid = pid;

    go_tls_conn_args_t *args = bpf_map_lookup_elem(&active_go_tls_write_args, &key);
    if (!args) return 0;

    int n_written = (int)(u64)GO_PARAM1(ctx);
    submit_go_tls_event(ctx, args, pid_tgid, n_written, TCP_SEND);

    bpf_map_delete_elem(&active_go_tls_write_args, &key);
    return 0;
}

// -----------------------------------------------------------------------
// uprobe: crypto/tls.(*Conn).Read(b []byte) (int, error)
// -----------------------------------------------------------------------
SEC("uprobe/crypto_tls_Conn_Read")
int obi_uprobe_go_tls_read(struct pt_regs *ctx) {
    u64 goroutine = (u64)GOROUTINE_PTR(ctx);
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 pid       = (u32)(pid_tgid >> 32);

    if (!valid_pid(pid_tgid)) return 0;

    go_tls_conn_args_t args = {
        .conn_ptr   = (u64)GO_PARAM1(ctx),
        .buf_ptr    = (u64)GO_PARAM2(ctx),
        .buf_len    = (u64)GO_PARAM3(ctx),
        .start_mono = bpf_ktime_get_ns(),
    };

    go_addr_key_t key = {};
    go_addr_key_from_id(&key, (void *)goroutine);
    key.pid = pid;

    bpf_map_update_elem(&active_go_tls_read_args, &key, &args, BPF_ANY);

    bpf_dbg_printk("go_tls_read entry conn=%llx buf=%llx len=%lld",
                   args.conn_ptr, args.buf_ptr, args.buf_len);
    return 0;
}

// -----------------------------------------------------------------------
// uretprobe: crypto/tls.(*Conn).Read return
// -----------------------------------------------------------------------
SEC("uprobe/crypto_tls_Conn_Read_ret")
int obi_uretprobe_go_tls_read(struct pt_regs *ctx) {
    u64 goroutine = (u64)GOROUTINE_PTR(ctx);
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 pid       = (u32)(pid_tgid >> 32);

    if (!valid_pid(pid_tgid)) return 0;

    go_addr_key_t key = {};
    go_addr_key_from_id(&key, (void *)goroutine);
    key.pid = pid;

    go_tls_conn_args_t *args = bpf_map_lookup_elem(&active_go_tls_read_args, &key);
    if (!args) return 0;

    int n_read = (int)(u64)GO_PARAM1(ctx);
    submit_go_tls_event(ctx, args, pid_tgid, n_read, TCP_RECV);

    bpf_map_delete_elem(&active_go_tls_read_args, &key);
    return 0;
}
