// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Memory Allocation Profiler - Track malloc/free with stack traces via uprobes
// Task: CP-011, CP-012, CP-013

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
#define MAX_LIVE_ALLOCS 262144  // CP-012: max live allocations to track
#define ALLOC_PROFILER_VERSION 1

// Allocation types
#define ALLOC_MALLOC   1
#define ALLOC_CALLOC   2
#define ALLOC_REALLOC  3
#define ALLOC_MMAP     4
#define ALLOC_NEW      5   // C++ new
#define ALLOC_POSIX_MEMALIGN 6

// Free types
#define FREE_FREE     1
#define FREE_MUNMAP   2
#define FREE_DELETE   3  // C++ delete

// Allocation info for tracking live allocations (CP-011, CP-012)
struct alloc_info {
    __u64 size;
    __u64 timestamp_ns;
    __s32 stack_id;
    __u32 pid;
    __u32 tid;
    __u8 alloc_type;
    __u8 _pad[3];
};

// Allocation event for ring buffer
struct alloc_event {
    __u8 type;        // Event type identifier
    __u8 alloc_type;  // malloc, calloc, etc.
    __u8 is_free;     // 1 if this is a free operation
    __u8 _pad;
    __u32 pid;
    __u32 tid;
    __u64 addr;
    __u64 size;
    __u64 timestamp_ns;
    __s32 stack_id;
    __s32 _pad2;
    char comm[16];
};

// Allocation key for aggregation
struct alloc_key {
    __s32 stack_id;
    __u8 alloc_type;
    __u8 _pad[3];
};

// Allocation statistics (aggregated by stack)
struct alloc_stats {
    __u64 total_bytes;
    __u64 alloc_count;
    __u64 free_count;
    __u64 current_bytes;   // Live allocations bytes
    __u64 current_count;   // Live allocation count
    __u64 max_bytes;       // Peak allocation
    __u64 total_lifetime_ns;
};

// Pending allocation (between malloc entry and exit)
struct pending_alloc {
    __u64 size;
    __u64 start_ns;
    __s32 stack_id;
    __u8 alloc_type;
    __u8 _pad[3];
};

// Realloc-specific pending info
struct pending_realloc {
    __u64 old_addr;
    __u64 new_size;
    __u64 start_ns;
    __s32 stack_id;
    __s32 _pad;
};

// Configuration from userspace
struct alloc_config {
    __u32 target_pid;
    __u64 min_size;         // Minimum allocation size to track
    __u64 sample_rate;      // Sample 1 in N allocations (0 = all)
    __u8 track_free;        // Whether to track frees
    __u8 track_calloc;      // Whether to track calloc (CP-013)
    __u8 track_realloc;     // Whether to track realloc (CP-013)
    __u8 track_mmap;        // Whether to track mmap (CP-013)
    __u8 _pad[4];
};

// Stack traces map
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} alloc_stacks SEC(".maps");

// Track pending allocations (malloc enter -> exit)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // pid_tgid
    __type(value, struct pending_alloc);
    __uint(max_entries, MAX_ENTRIES);
} pending_allocs SEC(".maps");

// Track pending reallocs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // pid_tgid
    __type(value, struct pending_realloc);
    __uint(max_entries, MAX_ENTRIES);
} pending_reallocs SEC(".maps");

// Track live allocations for heap profiling (CP-012)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // address
    __type(value, struct alloc_info);
    __uint(max_entries, MAX_LIVE_ALLOCS);
} live_allocs SEC(".maps");

// Aggregated allocation statistics by stack
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct alloc_key);
    __type(value, struct alloc_stats);
    __uint(max_entries, MAX_ENTRIES);
} alloc_stats_map SEC(".maps");

// Ring buffer for streaming events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 512KB for high-volume allocs
} alloc_events SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct alloc_config);
    __uint(max_entries, 1);
} alloc_cfg SEC(".maps");

// PID filter map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} alloc_target_pids SEC(".maps");

// Sample counter for rate limiting
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} alloc_sample_counter SEC(".maps");

// Get configuration
static __always_inline struct alloc_config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&alloc_cfg, &key);
}

// Check if we should profile this PID
static __always_inline bool should_profile_pid(__u32 pid) {
    if (pid == 0) {
        return false;
    }

    __u8 *exists = bpf_map_lookup_elem(&alloc_target_pids, &pid);
    if (exists) {
        return true;
    }

    struct alloc_config *cfg = get_config();
    if (cfg && cfg->target_pid == 0) {
        return true;
    }

    return false;
}

// Check if we should sample this allocation
static __always_inline bool should_sample(void) {
    struct alloc_config *cfg = get_config();
    if (!cfg || cfg->sample_rate == 0) {
        return true;  // Sample all
    }
    
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&alloc_sample_counter, &key);
    if (!counter) {
        return true;
    }
    
    // Read current value first, then increment
    // BPF doesn't allow using XADD return value
    __u64 count = *counter;
    __sync_fetch_and_add(counter, 1);
    return (count % cfg->sample_rate) == 0;
}

// Shared helper for malloc/calloc exit handling
static __always_inline int handle_alloc_exit(struct pt_regs *ctx) {
    void *addr = (void *)PT_REGS_RC(ctx);
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    
    if (!addr) {
        bpf_map_delete_elem(&pending_allocs, &pid_tgid);
        return 0;  // malloc/calloc failed
    }
    
    struct pending_alloc *pending = bpf_map_lookup_elem(&pending_allocs, &pid_tgid);
    if (!pending) {
        return 0;
    }
    
    __u64 addr_key = (__u64)addr;
    
    // Track live allocation (CP-012)
    struct alloc_info info = {
        .size = pending->size,
        .timestamp_ns = now,
        .stack_id = pending->stack_id,
        .pid = pid,
        .tid = tid,
        .alloc_type = pending->alloc_type,
    };
    bpf_map_update_elem(&live_allocs, &addr_key, &info, BPF_ANY);
    
    // Update aggregated stats
    struct alloc_key key = {
        .stack_id = pending->stack_id,
        .alloc_type = pending->alloc_type,
    };
    
    struct alloc_stats *stats = bpf_map_lookup_elem(&alloc_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_bytes, pending->size);
        __sync_fetch_and_add(&stats->alloc_count, 1);
        __sync_fetch_and_add(&stats->current_bytes, pending->size);
        __sync_fetch_and_add(&stats->current_count, 1);
        
        // Update peak (non-atomic, but approximate is fine)
        __u64 current = stats->current_bytes;
        if (current > stats->max_bytes) {
            stats->max_bytes = current;
        }
    } else {
        struct alloc_stats new_stats = {
            .total_bytes = pending->size,
            .alloc_count = 1,
            .current_bytes = pending->size,
            .current_count = 1,
            .max_bytes = pending->size,
        };
        bpf_map_update_elem(&alloc_stats_map, &key, &new_stats, BPF_ANY);
    }
    
    // Emit event to ring buffer
    struct alloc_event *event;
    event = bpf_ringbuf_reserve(&alloc_events, sizeof(*event), 0);
    if (event) {
        event->type = 4;  // Alloc profiler type
        event->alloc_type = pending->alloc_type;
        event->is_free = 0;
        event->pid = pid;
        event->tid = tid;
        event->addr = addr_key;
        event->size = pending->size;
        event->timestamp_ns = now;
        event->stack_id = pending->stack_id;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        
        bpf_ringbuf_submit(event, 0);
    }
    
    bpf_map_delete_elem(&pending_allocs, &pid_tgid);
    return 0;
}

// malloc entry
SEC("uprobe/malloc")
int trace_malloc_enter(struct pt_regs *ctx) {
    __u64 size = PT_REGS_PARM1(ctx);
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    struct alloc_config *cfg = get_config();
    if (cfg && size < cfg->min_size) {
        return 0;
    }
    
    if (!should_sample()) {
        return 0;
    }
    
    struct pending_alloc pending = {
        .size = size,
        .start_ns = now,
        .stack_id = bpf_get_stackid(ctx, &alloc_stacks, BPF_F_USER_STACK),
        .alloc_type = ALLOC_MALLOC,
    };
    
    bpf_map_update_elem(&pending_allocs, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

// malloc exit
SEC("uretprobe/malloc")
int trace_malloc_exit(struct pt_regs *ctx) {
    return handle_alloc_exit(ctx);
}

// free
SEC("uprobe/free")
int trace_free(struct pt_regs *ctx) {
    void *addr = (void *)PT_REGS_PARM1(ctx);
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    
    if (!addr) {
        return 0;
    }
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    __u64 addr_key = (__u64)addr;
    
    // Look up allocation info
    struct alloc_info *info = bpf_map_lookup_elem(&live_allocs, &addr_key);
    if (!info) {
        return 0;  // Unknown allocation (maybe before we started tracking)
    }
    
    __u64 lifetime = now - info->timestamp_ns;
    
    // Update aggregated stats
    struct alloc_key key = {
        .stack_id = info->stack_id,
        .alloc_type = info->alloc_type,
    };
    
    struct alloc_stats *stats = bpf_map_lookup_elem(&alloc_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->free_count, 1);
        __sync_fetch_and_sub(&stats->current_bytes, info->size);
        __sync_fetch_and_sub(&stats->current_count, 1);
        __sync_fetch_and_add(&stats->total_lifetime_ns, lifetime);
    }
    
    struct alloc_config *cfg = get_config();
    if (cfg && cfg->track_free) {
        // Emit free event
        struct alloc_event *event;
        event = bpf_ringbuf_reserve(&alloc_events, sizeof(*event), 0);
        if (event) {
            event->type = 4;
            event->alloc_type = FREE_FREE;
            event->is_free = 1;
            event->pid = pid;
            event->tid = tid;
            event->addr = addr_key;
            event->size = info->size;
            event->timestamp_ns = now;
            event->stack_id = bpf_get_stackid(ctx, &alloc_stacks, BPF_F_USER_STACK);
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    // Remove from live allocations
    bpf_map_delete_elem(&live_allocs, &addr_key);
    return 0;
}

// calloc entry (CP-013)
SEC("uprobe/calloc")
int trace_calloc_enter(struct pt_regs *ctx) {
    __u64 nmemb = PT_REGS_PARM1(ctx);
    __u64 size = PT_REGS_PARM2(ctx);
    __u64 total_size = nmemb * size;
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    struct alloc_config *cfg = get_config();
    if (cfg && !cfg->track_calloc) {
        return 0;
    }
    
    if (cfg && total_size < cfg->min_size) {
        return 0;
    }
    
    if (!should_sample()) {
        return 0;
    }
    
    struct pending_alloc pending = {
        .size = total_size,
        .start_ns = now,
        .stack_id = bpf_get_stackid(ctx, &alloc_stacks, BPF_F_USER_STACK),
        .alloc_type = ALLOC_CALLOC,
    };
    
    bpf_map_update_elem(&pending_allocs, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

// calloc exit - reuse malloc exit logic
SEC("uretprobe/calloc")
int trace_calloc_exit(struct pt_regs *ctx) {
    // Same logic as malloc exit - use shared inline helper
    return handle_alloc_exit(ctx);
}

// realloc entry (CP-013)
SEC("uprobe/realloc")
int trace_realloc_enter(struct pt_regs *ctx) {
    void *old_addr = (void *)PT_REGS_PARM1(ctx);
    __u64 new_size = PT_REGS_PARM2(ctx);
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    struct alloc_config *cfg = get_config();
    if (cfg && !cfg->track_realloc) {
        return 0;
    }
    
    struct pending_realloc pending = {
        .old_addr = (__u64)old_addr,
        .new_size = new_size,
        .start_ns = now,
        .stack_id = bpf_get_stackid(ctx, &alloc_stacks, BPF_F_USER_STACK),
    };
    
    bpf_map_update_elem(&pending_reallocs, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

// realloc exit (CP-013)
SEC("uretprobe/realloc")
int trace_realloc_exit(struct pt_regs *ctx) {
    void *new_addr = (void *)PT_REGS_RC(ctx);
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    
    struct pending_realloc *pending = bpf_map_lookup_elem(&pending_reallocs, &pid_tgid);
    if (!pending) {
        return 0;
    }
    
    // Handle old allocation if it existed
    if (pending->old_addr != 0) {
        struct alloc_info *old_info = bpf_map_lookup_elem(&live_allocs, &pending->old_addr);
        if (old_info) {
            // Update stats for "freed" old allocation
            struct alloc_key old_key = {
                .stack_id = old_info->stack_id,
                .alloc_type = old_info->alloc_type,
            };
            
            struct alloc_stats *stats = bpf_map_lookup_elem(&alloc_stats_map, &old_key);
            if (stats) {
                __sync_fetch_and_sub(&stats->current_bytes, old_info->size);
                __sync_fetch_and_sub(&stats->current_count, 1);
            }
            
            bpf_map_delete_elem(&live_allocs, &pending->old_addr);
        }
    }
    
    // Track new allocation if realloc succeeded
    if (new_addr) {
        __u64 addr_key = (__u64)new_addr;
        
        struct alloc_info info = {
            .size = pending->new_size,
            .timestamp_ns = now,
            .stack_id = pending->stack_id,
            .pid = pid,
            .tid = tid,
            .alloc_type = ALLOC_REALLOC,
        };
        bpf_map_update_elem(&live_allocs, &addr_key, &info, BPF_ANY);
        
        // Update stats
        struct alloc_key key = {
            .stack_id = pending->stack_id,
            .alloc_type = ALLOC_REALLOC,
        };
        
        struct alloc_stats *stats = bpf_map_lookup_elem(&alloc_stats_map, &key);
        if (stats) {
            __sync_fetch_and_add(&stats->total_bytes, pending->new_size);
            __sync_fetch_and_add(&stats->alloc_count, 1);
            __sync_fetch_and_add(&stats->current_bytes, pending->new_size);
            __sync_fetch_and_add(&stats->current_count, 1);
        } else {
            struct alloc_stats new_stats = {
                .total_bytes = pending->new_size,
                .alloc_count = 1,
                .current_bytes = pending->new_size,
                .current_count = 1,
                .max_bytes = pending->new_size,
            };
            bpf_map_update_elem(&alloc_stats_map, &key, &new_stats, BPF_ANY);
        }
    }
    
    bpf_map_delete_elem(&pending_reallocs, &pid_tgid);
    return 0;
}

// mmap entry (CP-013)
SEC("kprobe/do_mmap")
int BPF_KPROBE(trace_mmap_enter, unsigned long addr, unsigned long len) {
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    struct alloc_config *cfg = get_config();
    if (cfg && !cfg->track_mmap) {
        return 0;
    }
    
    if (cfg && len < cfg->min_size) {
        return 0;
    }
    
    struct pending_alloc pending = {
        .size = len,
        .start_ns = now,
        .stack_id = bpf_get_stackid(ctx, &alloc_stacks, BPF_F_USER_STACK),
        .alloc_type = ALLOC_MMAP,
    };
    
    bpf_map_update_elem(&pending_allocs, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

// munmap (CP-013)
SEC("kprobe/do_munmap")
int BPF_KPROBE(trace_munmap, void *addr, unsigned long len) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (!should_profile_pid(pid)) {
        return 0;
    }
    
    __u64 addr_key = (__u64)addr;
    
    struct alloc_info *info = bpf_map_lookup_elem(&live_allocs, &addr_key);
    if (info && info->alloc_type == ALLOC_MMAP) {
        struct alloc_key key = {
            .stack_id = info->stack_id,
            .alloc_type = info->alloc_type,
        };
        
        struct alloc_stats *stats = bpf_map_lookup_elem(&alloc_stats_map, &key);
        if (stats) {
            __sync_fetch_and_add(&stats->free_count, 1);
            __sync_fetch_and_sub(&stats->current_bytes, info->size);
            __sync_fetch_and_sub(&stats->current_count, 1);
        }
        
        bpf_map_delete_elem(&live_allocs, &addr_key);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = ALLOC_PROFILER_VERSION;
