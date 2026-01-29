// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// CPU Profiler - perf_event based CPU sampling with user/kernel stack traces
// Task: CP-001, CP-002

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/common.h>
#include <common/map_sizing.h>
#include <pid/pid.h>

#include <logger/bpf_dbg.h>

// Configuration
#define MAX_STACK_DEPTH 127
#define MAX_ENTRIES 65536
#define CPU_PROFILER_VERSION 1

// Stack key structure for aggregation (CP-002)
struct stack_key {
    __u32 pid;
    __u32 tgid;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    char comm[16];
};

// Stack count with timing information
struct stack_count {
    __u64 count;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
};

// CPU sample event for ring buffer
struct cpu_sample_event {
    __u8 type;  // Event type identifier
    __u8 _pad[3];
    __u32 pid;
    __u32 tgid;
    __u32 cpu;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    __u64 timestamp_ns;
    char comm[16];
};

// Configuration from userspace
struct cpu_profiler_config {
    __u32 target_pid;      // 0 = all pids
    __u32 sample_rate_hz;  // Sampling frequency
    __u8 capture_kernel;   // Whether to capture kernel stacks
    __u8 capture_user;     // Whether to capture user stacks
    __u8 _pad[2];
};

// Stack traces map - stores actual stack frames
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} cpu_stacks SEC(".maps");

// Aggregated counts per stack key
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct stack_key);
    __type(value, struct stack_count);
    __uint(max_entries, MAX_ENTRIES);
} cpu_stack_counts SEC(".maps");

// Ring buffer for streaming samples to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB ring buffer
} cpu_profile_events SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cpu_profiler_config);
    __uint(max_entries, 1);
} cpu_profiler_cfg SEC(".maps");

// PID filter map - if non-empty, only profile these PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} cpu_target_pids SEC(".maps");

// Get configuration
static __always_inline struct cpu_profiler_config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&cpu_profiler_cfg, &key);
}

// Check if we should profile this PID
static __always_inline bool should_profile_pid(__u32 pid) {
    // Skip kernel threads
    if (pid == 0) {
        return false;
    }

    // Check if we have a PID filter
    __u8 *exists = bpf_map_lookup_elem(&cpu_target_pids, &pid);
    if (exists) {
        return true;
    }

    // Check if PID filter is empty (profile all)
    struct cpu_profiler_config *cfg = get_config();
    if (cfg && cfg->target_pid == 0) {
        return true;
    }

    return false;
}

// Main CPU profiler entry point - attached to perf_event
SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid;

    // Filter by PID
    if (!should_profile_pid(pid)) {
        return 0;
    }

    struct cpu_profiler_config *cfg = get_config();
    
    // Build stack key for aggregation
    struct stack_key key = {};
    key.pid = pid;
    key.tgid = tgid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    // Capture user stack trace
    if (!cfg || cfg->capture_user) {
        key.user_stack_id = bpf_get_stackid(ctx, &cpu_stacks, BPF_F_USER_STACK);
    } else {
        key.user_stack_id = -1;
    }

    // Capture kernel stack trace
    if (!cfg || cfg->capture_kernel) {
        key.kernel_stack_id = bpf_get_stackid(ctx, &cpu_stacks, 0);
    } else {
        key.kernel_stack_id = -1;
    }

    // Update aggregated count
    struct stack_count *count = bpf_map_lookup_elem(&cpu_stack_counts, &key);
    if (count) {
        __sync_fetch_and_add(&count->count, 1);
        count->last_seen_ns = now;
    } else {
        struct stack_count new_count = {
            .count = 1,
            .first_seen_ns = now,
            .last_seen_ns = now,
        };
        bpf_map_update_elem(&cpu_stack_counts, &key, &new_count, BPF_ANY);
    }

    // Also emit individual sample to ring buffer for real-time streaming
    struct cpu_sample_event *event;
    event = bpf_ringbuf_reserve(&cpu_profile_events, sizeof(*event), 0);
    if (event) {
        event->type = 1;  // CPU sample type
        event->pid = pid;
        event->tgid = tgid;
        event->cpu = bpf_get_smp_processor_id();
        event->user_stack_id = key.user_stack_id;
        event->kernel_stack_id = key.kernel_stack_id;
        event->timestamp_ns = now;
        __builtin_memcpy(event->comm, key.comm, sizeof(event->comm));
        
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = CPU_PROFILER_VERSION;
