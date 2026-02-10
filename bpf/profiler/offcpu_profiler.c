// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Off-CPU Profiler - sched_switch tracepoint for blocking time analysis
// Task: CP-003, CP-004, CP-005

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
#define MIN_BLOCK_NS 1000000  // 1ms minimum block time to record
#define OFFCPU_PROFILER_VERSION 1

// Block reason classification (CP-004)
#define BLOCK_REASON_UNKNOWN   0
#define BLOCK_REASON_IO        1
#define BLOCK_REASON_LOCK      2
#define BLOCK_REASON_SLEEP     3
#define BLOCK_REASON_NET       4
#define BLOCK_REASON_PAGE      5
#define BLOCK_REASON_FUTEX     6
#define BLOCK_REASON_EPOLL     7
#define BLOCK_REASON_PREEMPTED 8
#define BLOCK_REASON_RUNNABLE  9

// Off-CPU key for aggregation
struct offcpu_key {
    __u32 pid;
    __u32 tgid;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    char comm[16];
    __u8 block_reason;
    __u8 _pad[3];
};

// Off-CPU aggregated statistics (CP-005)
struct offcpu_value {
    __u64 total_time_ns;
    __u64 count;
    __u64 max_time_ns;
    __u64 min_time_ns;
    __u64 sum_squared_ns;  // For std deviation calculation
};

// Off-CPU sample event for ring buffer
struct offcpu_event {
    __u8 type;  // Event type identifier
    __u8 block_reason;
    __u8 _pad[2];
    __u32 pid;
    __u32 tgid;
    __u32 waker_pid;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    __u64 timestamp_ns;
    __u64 block_time_ns;
    char comm[16];
};

// Track when processes go off-CPU
struct offcpu_start {
    __u64 start_ns;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    __u8 reason;
    __u8 _pad[7];
};

// Configuration from userspace
struct offcpu_config {
    __u32 target_pid;       // 0 = all pids (only when filter_active == 0)
    __u64 min_block_ns;     // Minimum block time to record
    __u8 capture_kernel;    // Whether to capture kernel stacks
    __u8 capture_user;      // Whether to capture user stacks
    __u8 filter_active;     // 1 = only profile PIDs in offcpu_target_pids map
    __u8 _pad[5];
};

// Stack traces map
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} offcpu_stacks SEC(".maps");

// Track when processes go off-CPU
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // pid
    __type(value, struct offcpu_start);
    __uint(max_entries, MAX_ENTRIES);
} offcpu_start_times SEC(".maps");

// Aggregated off-CPU statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct offcpu_key);
    __type(value, struct offcpu_value);
    __uint(max_entries, MAX_ENTRIES);
} offcpu_counts SEC(".maps");

// Ring buffer for streaming samples
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} offcpu_events SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct offcpu_config);
    __uint(max_entries, 1);
} offcpu_cfg SEC(".maps");

// PID filter map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} offcpu_target_pids SEC(".maps");

// Get configuration
static __always_inline struct offcpu_config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&offcpu_cfg, &key);
}

// Check if we should profile this PID
static __always_inline bool should_profile_pid(__u32 pid) {
    if (pid == 0) {
        return false;
    }

    __u8 *exists = bpf_map_lookup_elem(&offcpu_target_pids, &pid);
    if (exists) {
        return true;
    }

    struct offcpu_config *cfg = get_config();
    if (!cfg) {
        return false;
    }

    // If a specific single PID is targeted, only profile that PID
    if (cfg->target_pid != 0) {
        return pid == cfg->target_pid;
    }

    // If userspace has process filters active, only accept PIDs
    // explicitly added to the offcpu_target_pids map
    if (cfg->filter_active) {
        return false;
    }

    // No filters configured — profile everything
    return true;
}

// Classify block reason from task state (CP-004)
static __always_inline __u8 classify_block_reason(long state) {
    // Task state bits from Linux kernel
    // TASK_INTERRUPTIBLE = 0x0001
    // TASK_UNINTERRUPTIBLE = 0x0002
    // __TASK_STOPPED = 0x0004
    // __TASK_TRACED = 0x0008
    // EXIT_DEAD = 0x0010
    // EXIT_ZOMBIE = 0x0020
    // TASK_PARKED = 0x0040
    // TASK_DEAD = 0x0080
    // TASK_WAKEKILL = 0x0100
    // TASK_WAKING = 0x0200
    // TASK_NOLOAD = 0x0400
    // TASK_NEW = 0x0800
    
    if (state == 0) {
        return BLOCK_REASON_RUNNABLE;
    }
    
    // TASK_UNINTERRUPTIBLE typically means I/O wait
    if (state & 0x0002) {
        return BLOCK_REASON_IO;
    }
    
    // TASK_INTERRUPTIBLE can be sleep or waiting for lock
    if (state & 0x0001) {
        return BLOCK_REASON_SLEEP;
    }
    
    return BLOCK_REASON_UNKNOWN;
}

// sched_switch tracepoint - track when tasks go on/off CPU
SEC("tp_btf/sched_switch")
int BPF_PROG(offcpu_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
    __u64 now = bpf_ktime_get_ns();
    __u32 prev_pid = BPF_CORE_READ(prev, pid);
    __u32 next_pid = BPF_CORE_READ(next, pid);

    struct offcpu_config *cfg = get_config();
    __u64 min_block = cfg ? cfg->min_block_ns : MIN_BLOCK_NS;

    // Record when prev goes off-CPU
    if (should_profile_pid(prev_pid)) {
        struct offcpu_start start_info = {};
        start_info.start_ns = now;
        
        // Capture stack at switch-out time
        if (!cfg || cfg->capture_user) {
            start_info.user_stack_id = bpf_get_stackid(ctx, &offcpu_stacks, BPF_F_USER_STACK);
        } else {
            start_info.user_stack_id = -1;
        }
        
        if (!cfg || cfg->capture_kernel) {
            start_info.kernel_stack_id = bpf_get_stackid(ctx, &offcpu_stacks, 0);
        } else {
            start_info.kernel_stack_id = -1;
        }
        
        // Determine block reason from task state
        long state = BPF_CORE_READ(prev, __state);
        start_info.reason = preempt ? BLOCK_REASON_PREEMPTED : classify_block_reason(state);
        
        bpf_map_update_elem(&offcpu_start_times, &prev_pid, &start_info, BPF_ANY);
    }

    // Check if next was off-CPU and record the duration
    if (should_profile_pid(next_pid)) {
        struct offcpu_start *start_info = bpf_map_lookup_elem(&offcpu_start_times, &next_pid);
        if (start_info && start_info->start_ns > 0) {
            __u64 delta = now - start_info->start_ns;
            
            // Only record significant blocks
            if (delta >= min_block) {
                // Build aggregation key
                struct offcpu_key key = {};
                key.pid = next_pid;
                key.tgid = BPF_CORE_READ(next, tgid);
                key.user_stack_id = start_info->user_stack_id;
                key.kernel_stack_id = start_info->kernel_stack_id;
                key.block_reason = start_info->reason;
                BPF_CORE_READ_STR_INTO(&key.comm, next, comm);

                // Update aggregated stats (CP-005)
                struct offcpu_value *val = bpf_map_lookup_elem(&offcpu_counts, &key);
                if (val) {
                    __sync_fetch_and_add(&val->total_time_ns, delta);
                    __sync_fetch_and_add(&val->count, 1);
                    
                    // Update max/min (non-atomic, but close enough for profiling)
                    if (delta > val->max_time_ns) {
                        val->max_time_ns = delta;
                    }
                    if (val->min_time_ns == 0 || delta < val->min_time_ns) {
                        val->min_time_ns = delta;
                    }
                    
                    // Sum of squares for variance calculation
                    __u64 delta_us = delta / 1000;  // Convert to microseconds to avoid overflow
                    __sync_fetch_and_add(&val->sum_squared_ns, delta_us * delta_us);
                } else {
                    struct offcpu_value new_val = {
                        .total_time_ns = delta,
                        .count = 1,
                        .max_time_ns = delta,
                        .min_time_ns = delta,
                        .sum_squared_ns = (delta / 1000) * (delta / 1000),
                    };
                    bpf_map_update_elem(&offcpu_counts, &key, &new_val, BPF_ANY);
                }

                // Emit event to ring buffer
                struct offcpu_event *event;
                event = bpf_ringbuf_reserve(&offcpu_events, sizeof(*event), 0);
                if (event) {
                    event->type = 2;  // Off-CPU sample type
                    event->block_reason = start_info->reason;
                    event->pid = next_pid;
                    event->tgid = key.tgid;
                    event->waker_pid = 0;  // TODO: track waker
                    event->user_stack_id = start_info->user_stack_id;
                    event->kernel_stack_id = start_info->kernel_stack_id;
                    event->timestamp_ns = now;
                    event->block_time_ns = delta;
                    __builtin_memcpy(event->comm, key.comm, sizeof(event->comm));
                    
                    bpf_ringbuf_submit(event, 0);
                }
            }
            
            // Clear the start time
            bpf_map_delete_elem(&offcpu_start_times, &next_pid);
        }
    }

    return 0;
}

// Track futex contention for more accurate block reason
SEC("kprobe/futex_wait")
int BPF_KPROBE(trace_futex_wait) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    struct offcpu_start *start_info = bpf_map_lookup_elem(&offcpu_start_times, &pid);
    if (start_info) {
        start_info->reason = BLOCK_REASON_FUTEX;
    }
    
    return 0;
}

// Track epoll wait for block reason
SEC("kprobe/do_epoll_wait")
int BPF_KPROBE(trace_epoll_wait) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    struct offcpu_start *start_info = bpf_map_lookup_elem(&offcpu_start_times, &pid);
    if (start_info) {
        start_info->reason = BLOCK_REASON_EPOLL;
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = OFFCPU_PROFILER_VERSION;
