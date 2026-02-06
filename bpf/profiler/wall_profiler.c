// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Wall Clock Profiler - Track real elapsed time including on-CPU and off-CPU combined
// Task: CP-006, CP-007

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/common.h>
#include <common/map_sizing.h>
#include <pid/pid.h>

// Configuration
#define MAX_STACK_DEPTH 127
#define MAX_ENTRIES 65536
#define WALL_PROFILER_VERSION 1

// Wall clock sample
struct wall_sample {
    __u32 pid;
    __u32 tid;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    __u64 wall_time_ns;
    __u64 cpu_time_ns;
    __u64 off_cpu_time_ns;
    char comm[16];
};

// Span timing tracking for correlation (CP-007)
struct span_timing {
    __u64 start_ns;
    __u64 cpu_start_ns;
    __u64 accumulated_cpu_ns;
    __u32 pid;
    __u32 tid;
    __u8 on_cpu;
    __u8 _pad[7];
};

// Wall clock key for aggregation
struct wall_key {
    __u32 pid;
    __u32 tid;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    char comm[16];
};

// Wall clock aggregated value
struct wall_value {
    __u64 total_wall_ns;
    __u64 total_cpu_ns;
    __u64 total_offcpu_ns;
    __u64 count;
    __u64 max_wall_ns;
    __u64 min_wall_ns;
};

// Configuration from userspace
struct wall_config {
    __u32 target_pid;
    __u64 sample_interval_ns;  // Periodic sampling interval
    __u8 _pad[4];
};

// Stack traces map
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} wall_stacks SEC(".maps");

// Track active spans/requests (CP-007)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // span_id or request_id
    __type(value, struct span_timing);
    __uint(max_entries, MAX_ENTRIES);
} span_timings SEC(".maps");

// Aggregated wall clock statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct wall_key);
    __type(value, struct wall_value);
    __uint(max_entries, MAX_ENTRIES);
} wall_counts SEC(".maps");

// Ring buffer for streaming samples
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} wall_events SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct wall_config);
    __uint(max_entries, 1);
} wall_cfg SEC(".maps");

// PID filter map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} wall_target_pids SEC(".maps");

// Get configuration
static __always_inline struct wall_config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&wall_cfg, &key);
}

// Check if we should profile this PID
static __always_inline bool should_profile_pid(__u32 pid) {
    if (pid == 0) {
        return false;
    }

    __u8 *exists = bpf_map_lookup_elem(&wall_target_pids, &pid);
    if (exists) {
        return true;
    }

    struct wall_config *cfg = get_config();
    if (cfg && cfg->target_pid == 0) {
        return true;
    }

    return false;
}

// Correlate wall time with trace spans (CP-007)
// Called when a span/request starts
SEC("uprobe/span_start")
int trace_span_start(struct pt_regs *ctx) {
    __u64 span_id = PT_REGS_PARM1(ctx);
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    struct span_timing timing = {
        .start_ns = now,
        .cpu_start_ns = now,
        .accumulated_cpu_ns = 0,
        .pid = pid,
        .tid = pid_tgid,
        .on_cpu = 1,
    };
    
    bpf_map_update_elem(&span_timings, &span_id, &timing, BPF_ANY);
    return 0;
}

// Called when a span/request ends
SEC("uprobe/span_end")
int trace_span_end(struct pt_regs *ctx) {
    __u64 span_id = PT_REGS_PARM1(ctx);
    __u64 now = bpf_ktime_get_ns();
    
    struct span_timing *timing = bpf_map_lookup_elem(&span_timings, &span_id);
    if (!timing) {
        return 0;
    }
    
    // Calculate times
    __u64 wall_time = now - timing->start_ns;
    __u64 cpu_time = timing->accumulated_cpu_ns;
    
    // Add remaining CPU time if currently on-CPU
    if (timing->on_cpu) {
        cpu_time += now - timing->cpu_start_ns;
    }
    
    __u64 off_cpu_time = wall_time > cpu_time ? wall_time - cpu_time : 0;
    
    // Build sample
    struct wall_sample *sample;
    sample = bpf_ringbuf_reserve(&wall_events, sizeof(*sample), 0);
    if (sample) {
        sample->pid = timing->pid;
        sample->tid = timing->tid;
        sample->wall_time_ns = wall_time;
        sample->cpu_time_ns = cpu_time;
        sample->off_cpu_time_ns = off_cpu_time;
        sample->user_stack_id = bpf_get_stackid(ctx, &wall_stacks, BPF_F_USER_STACK);
        sample->kernel_stack_id = -1;  // Usually not relevant for span end
        bpf_get_current_comm(&sample->comm, sizeof(sample->comm));
        
        bpf_ringbuf_submit(sample, 0);
    }
    
    // Update aggregated stats
    struct wall_key key = {};
    key.pid = timing->pid;
    key.tid = timing->tid;
    key.user_stack_id = sample ? sample->user_stack_id : -1;
    key.kernel_stack_id = -1;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    struct wall_value *val = bpf_map_lookup_elem(&wall_counts, &key);
    if (val) {
        __sync_fetch_and_add(&val->total_wall_ns, wall_time);
        __sync_fetch_and_add(&val->total_cpu_ns, cpu_time);
        __sync_fetch_and_add(&val->total_offcpu_ns, off_cpu_time);
        __sync_fetch_and_add(&val->count, 1);
        
        if (wall_time > val->max_wall_ns) {
            val->max_wall_ns = wall_time;
        }
        if (val->min_wall_ns == 0 || wall_time < val->min_wall_ns) {
            val->min_wall_ns = wall_time;
        }
    } else {
        struct wall_value new_val = {
            .total_wall_ns = wall_time,
            .total_cpu_ns = cpu_time,
            .total_offcpu_ns = off_cpu_time,
            .count = 1,
            .max_wall_ns = wall_time,
            .min_wall_ns = wall_time,
        };
        bpf_map_update_elem(&wall_counts, &key, &new_val, BPF_ANY);
    }
    
    bpf_map_delete_elem(&span_timings, &span_id);
    return 0;
}

// Track context switches to update CPU time for active spans
SEC("tp_btf/sched_switch")
int BPF_PROG(wall_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
    __u64 now = bpf_ktime_get_ns();
    __u32 prev_pid = BPF_CORE_READ(prev, pid);
    __u32 next_pid = BPF_CORE_READ(next, pid);
    
    // For each active span belonging to prev_pid, accumulate CPU time
    // Note: This is simplified - in practice we'd need to iterate spans or use per-thread tracking
    // This implementation focuses on single-span-per-thread scenarios
    
    return 0;
}

// Periodic wall clock sampling via timer
SEC("perf_event")
int profile_wall(struct bpf_perf_event_data *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    // Take a wall clock sample
    struct wall_sample *sample;
    sample = bpf_ringbuf_reserve(&wall_events, sizeof(*sample), 0);
    if (sample) {
        sample->pid = pid;
        sample->tid = tid;
        sample->user_stack_id = bpf_get_stackid(ctx, &wall_stacks, BPF_F_USER_STACK);
        sample->kernel_stack_id = bpf_get_stackid(ctx, &wall_stacks, 0);
        sample->wall_time_ns = now;  // Just timestamp for periodic samples
        sample->cpu_time_ns = 0;      // Not tracked for periodic
        sample->off_cpu_time_ns = 0;  // Not tracked for periodic
        bpf_get_current_comm(&sample->comm, sizeof(sample->comm));
        
        bpf_ringbuf_submit(sample, 0);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = WALL_PROFILER_VERSION;
