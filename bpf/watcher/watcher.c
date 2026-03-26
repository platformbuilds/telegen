// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/sockaddr.h>
#include <common/tcp_info.h>

#include <logger/bpf_dbg.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define WATCH_BIND 0x1

typedef struct watch_info {
    u64 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u64 payload;
} watch_info_t;

const watch_info_t *unused_2 __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} watch_events SEC(".maps");

// ---------------------------------------------------------------------------
// Process lifecycle events — ported from Pixie's proc_exit connector
// (src/stirling/source_connectors/proc_exit/).
// Attaches to sched:sched_process_exit tracepoint; captures exit code, signal,
// and process name so Telegen can emit crash-detection / drain-detection events.
// ---------------------------------------------------------------------------

typedef struct proc_exit_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    // Raw wait-status as encoded by the kernel: low 7 bits = signal (0 = clean exit);
    // bits 8-15 = exit code from userspace.
    u32 exit_code;
    u32 signal_num;
    char comm[16];
} proc_exit_event_t;

const proc_exit_event_t *unused_proc_exit __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 14); // 16 KB
} proc_exit_events SEC(".maps");

SEC("kprobe/sys_bind")
int obi_kprobe_sys_bind(struct pt_regs *ctx) {
    // unwrap the args because it's a sys call
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *addr;
    bpf_probe_read(&addr, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));

    if (!addr) {
        return 0;
    }

    u16 port = get_sockaddr_port_user(addr);

    if (!port) {
        return 0;
    }

    watch_info_t *trace = bpf_ringbuf_reserve(&watch_events, sizeof(watch_info_t), 0);
    if (trace) {
        trace->flags = WATCH_BIND;
        trace->payload = port;
        bpf_dbg_printk("New port bound, payload=%d", trace->payload);

        bpf_ringbuf_submit(trace, 0);
    }

    return 0;
}

// Process exit tracepoint — emits a proc_exit_event_t to proc_exit_events.
// Ported from Pixie's proc_exit connector which attaches to the same tracepoint.
// The sched_process_exit tracepoint fires for every thread group exit (TGID == PID),
// allowing Telegen to detect crashes (non-zero signal_num) and graceful shutdowns.
SEC("tracepoint/sched/sched_process_exit")
int obi_tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    // Only capture the main thread exit (tid == pid), which represents the
    // process-level exit event.  Individual thread exits are not interesting for
    // crash / lifecycle detection.
    if (pid != tid) {
        return 0;
    }

    proc_exit_event_t *ev = bpf_ringbuf_reserve(&proc_exit_events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    ev->timestamp  = bpf_ktime_get_ns();
    ev->pid        = pid;
    ev->tid        = tid;

    // ctx->exit_code encodes the full wait-status:
    //   bits [6:0]  = termination signal (0 → clean exit)
    //   bits [15:8] = exit code (if signal == 0)
    u32 raw = (u32)BPF_CORE_READ(ctx, exit_code);
    ev->signal_num = raw & 0x7F;
    ev->exit_code  = (raw >> 8) & 0xFF;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_dbg_printk("proc_exit pid=%d exit_code=%d signal=%d comm=%s",
                   pid, ev->exit_code, ev->signal_num, ev->comm);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
