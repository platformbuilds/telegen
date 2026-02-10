// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Mutex Contention Profiler - Track pthread_mutex_lock contention via uprobes
// Task: CP-008, CP-009, CP-010

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
#define CONTENTION_THRESHOLD_NS 1000000  // 1ms default threshold
#define MUTEX_PROFILER_VERSION 1

// Mutex event types
#define MUTEX_EVENT_CONTENTION 1
#define MUTEX_EVENT_DEADLOCK   2
#define MUTEX_EVENT_HOLD_LONG  3

// Mutex event for ring buffer
struct mutex_event {
    __u8 type;
    __u8 event_type;  // contention, deadlock, etc.
    __u8 _pad[2];
    __u32 pid;
    __u32 tid;
    __u64 lock_addr;
    __u64 wait_time_ns;
    __u64 hold_time_ns;
    __s32 stack_id;
    __s32 _pad2;
    __u64 timestamp_ns;
    char comm[16];
};

// Lock state tracking (CP-009)
struct lock_state {
    __u64 acquire_start_ns;  // When lock acquisition was attempted
    __u64 acquired_ns;       // When lock was acquired
    __u32 owner_tid;         // Current owner thread ID
    __u32 waiter_count;      // Number of threads waiting
    __s32 owner_stack_id;    // Stack ID when lock was acquired
    __s32 _pad;
};

// Pending lock acquisition (per-thread tracking)
struct pending_lock {
    __u64 lock_addr;
    __u64 start_ns;
    __s32 stack_id;
    __s32 _pad;
};

// Mutex contention key for aggregation
struct mutex_key {
    __u64 lock_addr;
    __s32 stack_id;
    __u32 _pad;
};

// Mutex statistics (CP-010)
struct mutex_stats {
    __u64 total_wait_ns;
    __u64 total_hold_ns;
    __u64 contention_count;
    __u64 acquisition_count;
    __u64 max_wait_ns;
    __u64 max_hold_ns;
    __u64 min_wait_ns;
    __u64 min_hold_ns;
};

// Configuration from userspace
struct mutex_config {
    __u32 target_pid;
    __u64 contention_threshold_ns;  // Minimum wait time to record
    __u64 hold_threshold_ns;        // Warn if held longer than this
    __u8 filter_active;     // 1 = only profile PIDs in mutex_target_pids map
    __u8 _pad[3];
};

// Stack traces map
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} mutex_stacks SEC(".maps");

// Track lock states by lock address (CP-009)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // lock address
    __type(value, struct lock_state);
    __uint(max_entries, MAX_ENTRIES);
} lock_states SEC(".maps");

// Track pending lock acquisitions per thread
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // pid_tgid
    __type(value, struct pending_lock);
    __uint(max_entries, MAX_ENTRIES);
} pending_locks SEC(".maps");

// Aggregated mutex statistics (CP-010)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mutex_key);
    __type(value, struct mutex_stats);
    __uint(max_entries, MAX_ENTRIES);
} mutex_stats_map SEC(".maps");

// Ring buffer for streaming events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mutex_events SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct mutex_config);
    __uint(max_entries, 1);
} mutex_cfg SEC(".maps");

// PID filter map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} mutex_target_pids SEC(".maps");

// Get configuration
static __always_inline struct mutex_config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&mutex_cfg, &key);
}

// Check if we should profile this PID
static __always_inline bool should_profile_pid(__u32 pid) {
    if (pid == 0) {
        return false;
    }

    __u8 *exists = bpf_map_lookup_elem(&mutex_target_pids, &pid);
    if (exists) {
        return true;
    }

    struct mutex_config *cfg = get_config();
    if (!cfg) {
        return false;
    }

    if (cfg->target_pid != 0) {
        return pid == cfg->target_pid;
    }

    if (cfg->filter_active) {
        return false;
    }

    return true;
}

// pthread_mutex_lock entry - record when lock acquisition starts
SEC("uprobe")
int trace_mutex_lock_enter(struct pt_regs *ctx) {
    void *mutex = (void *)PT_REGS_PARM1(ctx);
    __u64 lock_addr = (__u64)mutex;
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    // Check if lock is already held by another thread (contention)
    struct lock_state *state = bpf_map_lookup_elem(&lock_states, &lock_addr);
    if (state && state->owner_tid != 0 && state->owner_tid != tid) {
        // Contention detected - increment waiter count
        __sync_fetch_and_add(&state->waiter_count, 1);
        
        // Record pending lock acquisition
        struct pending_lock pending = {
            .lock_addr = lock_addr,
            .start_ns = now,
            .stack_id = bpf_get_stackid(ctx, &mutex_stacks, BPF_F_USER_STACK),
        };
        bpf_map_update_elem(&pending_locks, &pid_tgid, &pending, BPF_ANY);
    } else {
        // No contention - still record for hold time tracking
        struct pending_lock pending = {
            .lock_addr = lock_addr,
            .start_ns = now,
            .stack_id = bpf_get_stackid(ctx, &mutex_stacks, BPF_F_USER_STACK),
        };
        bpf_map_update_elem(&pending_locks, &pid_tgid, &pending, BPF_ANY);
    }
    
    return 0;
}

// pthread_mutex_lock exit - lock was acquired
SEC("uretprobe")
int trace_mutex_lock_exit(struct pt_regs *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    int ret = PT_REGS_RC(ctx);
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    // Check if lock acquisition succeeded
    if (ret != 0) {
        bpf_map_delete_elem(&pending_locks, &pid_tgid);
        return 0;
    }
    
    struct pending_lock *pending = bpf_map_lookup_elem(&pending_locks, &pid_tgid);
    if (!pending) {
        return 0;
    }
    
    __u64 lock_addr = pending->lock_addr;
    __u64 wait_time = now - pending->start_ns;
    
    struct mutex_config *cfg = get_config();
    __u64 threshold = cfg ? cfg->contention_threshold_ns : CONTENTION_THRESHOLD_NS;
    
    // Check if there was significant contention
    if (wait_time > threshold) {
        // Emit contention event
        struct mutex_event *event;
        event = bpf_ringbuf_reserve(&mutex_events, sizeof(*event), 0);
        if (event) {
            event->type = 3;  // Mutex profiler type
            event->event_type = MUTEX_EVENT_CONTENTION;
            event->pid = pid;
            event->tid = tid;
            event->lock_addr = lock_addr;
            event->wait_time_ns = wait_time;
            event->hold_time_ns = 0;
            event->stack_id = pending->stack_id;
            event->timestamp_ns = now;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            
            bpf_ringbuf_submit(event, 0);
        }
        
        // Update aggregated stats (CP-010)
        struct mutex_key key = {
            .lock_addr = lock_addr,
            .stack_id = pending->stack_id,
        };
        
        struct mutex_stats *stats = bpf_map_lookup_elem(&mutex_stats_map, &key);
        if (stats) {
            __sync_fetch_and_add(&stats->total_wait_ns, wait_time);
            __sync_fetch_and_add(&stats->contention_count, 1);
            __sync_fetch_and_add(&stats->acquisition_count, 1);
            
            if (wait_time > stats->max_wait_ns) {
                stats->max_wait_ns = wait_time;
            }
            if (stats->min_wait_ns == 0 || wait_time < stats->min_wait_ns) {
                stats->min_wait_ns = wait_time;
            }
        } else {
            struct mutex_stats new_stats = {
                .total_wait_ns = wait_time,
                .contention_count = 1,
                .acquisition_count = 1,
                .max_wait_ns = wait_time,
                .min_wait_ns = wait_time,
            };
            bpf_map_update_elem(&mutex_stats_map, &key, &new_stats, BPF_ANY);
        }
    }
    
    // Update lock state - this thread now owns the lock (CP-009)
    struct lock_state new_state = {
        .acquire_start_ns = pending->start_ns,
        .acquired_ns = now,
        .owner_tid = tid,
        .waiter_count = 0,
        .owner_stack_id = pending->stack_id,
    };
    bpf_map_update_elem(&lock_states, &lock_addr, &new_state, BPF_ANY);
    
    bpf_map_delete_elem(&pending_locks, &pid_tgid);
    return 0;
}

// pthread_mutex_unlock - lock is being released
SEC("uprobe")
int trace_mutex_unlock(struct pt_regs *ctx) {
    void *mutex = (void *)PT_REGS_PARM1(ctx);
    __u64 lock_addr = (__u64)mutex;
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    struct lock_state *state = bpf_map_lookup_elem(&lock_states, &lock_addr);
    if (!state || state->owner_tid != tid) {
        return 0;
    }
    
    __u64 hold_time = now - state->acquired_ns;
    
    struct mutex_config *cfg = get_config();
    __u64 hold_threshold = cfg ? cfg->hold_threshold_ns : (10 * CONTENTION_THRESHOLD_NS);  // 10ms default
    
    // Track hold time in stats (CP-010)
    struct mutex_key key = {
        .lock_addr = lock_addr,
        .stack_id = state->owner_stack_id,
    };
    
    struct mutex_stats *stats = bpf_map_lookup_elem(&mutex_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_hold_ns, hold_time);
        
        if (hold_time > stats->max_hold_ns) {
            stats->max_hold_ns = hold_time;
        }
        if (stats->min_hold_ns == 0 || hold_time < stats->min_hold_ns) {
            stats->min_hold_ns = hold_time;
        }
    }
    
    // Emit event if held too long
    if (hold_time > hold_threshold) {
        struct mutex_event *event;
        event = bpf_ringbuf_reserve(&mutex_events, sizeof(*event), 0);
        if (event) {
            event->type = 3;
            event->event_type = MUTEX_EVENT_HOLD_LONG;
            event->pid = pid;
            event->tid = tid;
            event->lock_addr = lock_addr;
            event->wait_time_ns = 0;
            event->hold_time_ns = hold_time;
            event->stack_id = state->owner_stack_id;
            event->timestamp_ns = now;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    // Clear lock state
    bpf_map_delete_elem(&lock_states, &lock_addr);
    
    return 0;
}

// pthread_mutex_trylock - non-blocking lock attempt
SEC("uretprobe/pthread_mutex_trylock")
int trace_mutex_trylock_exit(struct pt_regs *ctx) {
    void *mutex = (void *)PT_REGS_PARM1(ctx);
    __u64 lock_addr = (__u64)mutex;
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    int ret = PT_REGS_RC(ctx);
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    // Only track successful acquisitions
    if (ret == 0) {
        struct lock_state new_state = {
            .acquire_start_ns = now,
            .acquired_ns = now,
            .owner_tid = tid,
            .waiter_count = 0,
            .owner_stack_id = bpf_get_stackid(ctx, &mutex_stacks, BPF_F_USER_STACK),
        };
        bpf_map_update_elem(&lock_states, &lock_addr, &new_state, BPF_ANY);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = MUTEX_PROFILER_VERSION;
