// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0
// Task: ML-014 - CUDA Kernel Tracer eBPF

#include "../bpfcore/vmlinux.h"
#include "../bpfcore/bpf_helpers.h"
#include "../bpfcore/bpf_tracing.h"
#include "../bpfcore/bpf_core_read.h"
#include "../common/common.h"

// CUDA event types
#define CUDA_EVENT_KERNEL_LAUNCH     0
#define CUDA_EVENT_KERNEL_COMPLETE   1
#define CUDA_EVENT_MEMCPY_START      2
#define CUDA_EVENT_MEMCPY_COMPLETE   3
#define CUDA_EVENT_MALLOC            4
#define CUDA_EVENT_FREE              5
#define CUDA_EVENT_SYNC              6
#define CUDA_EVENT_STREAM_CREATE     7
#define CUDA_EVENT_STREAM_DESTROY    8

// Memory copy direction
#define CUDA_MEMCPY_HOST_TO_HOST     0
#define CUDA_MEMCPY_HOST_TO_DEVICE   1
#define CUDA_MEMCPY_DEVICE_TO_HOST   2
#define CUDA_MEMCPY_DEVICE_TO_DEVICE 3
#define CUDA_MEMCPY_DEFAULT          4

#define CUDA_MAX_KERNEL_NAME 128

// CUDA kernel event structure
struct cuda_event {
    u64 timestamp_ns;        // Event timestamp
    u64 duration_ns;         // Duration (for completion events)
    u32 pid;                 // Process ID
    u32 tid;                 // Thread ID
    u32 event_type;          // Event type
    u32 gpu_id;              // GPU device ID
    u64 stream_id;           // CUDA stream ID
    
    // Kernel launch info
    u32 grid_dim_x;
    u32 grid_dim_y;
    u32 grid_dim_z;
    u32 block_dim_x;
    u32 block_dim_y;
    u32 block_dim_z;
    u32 shared_mem_bytes;
    u8 kernel_name[CUDA_MAX_KERNEL_NAME];
    
    // Memory operation info
    u64 src_ptr;
    u64 dst_ptr;
    u64 bytes;
    u32 memcpy_kind;
    
    // Memory allocation info
    u64 alloc_ptr;
    u64 alloc_size;
    
    // Error info
    u32 cuda_error;
};

// Active kernel tracking
struct cuda_kernel_info {
    u64 start_time;
    u32 pid;
    u32 tid;
    u32 gpu_id;
    u64 stream_id;
    u32 grid_dim_x;
    u32 grid_dim_y;
    u32 grid_dim_z;
    u32 block_dim_x;
    u32 block_dim_y;
    u32 block_dim_z;
    u32 shared_mem_bytes;
    u8 kernel_name[CUDA_MAX_KERNEL_NAME];
};

// Active memory operation tracking
struct cuda_memop_info {
    u64 start_time;
    u32 pid;
    u32 tid;
    u64 src_ptr;
    u64 dst_ptr;
    u64 bytes;
    u32 memcpy_kind;
    u64 stream_id;
};

// Map to track active CUDA kernels
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // kernel correlation ID
    __type(value, struct cuda_kernel_info);
} cuda_active_kernels SEC(".maps");

// Map to track active memory operations
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // operation correlation ID
    __type(value, struct cuda_memop_info);
} cuda_active_memops SEC(".maps");

// Ring buffer for CUDA events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);  // 2MB buffer
} cuda_events SEC(".maps");

// Per-process GPU memory tracking
struct cuda_mem_stats {
    u64 total_allocated;
    u64 total_freed;
    u64 peak_usage;
    u64 current_usage;
    u64 alloc_count;
    u64 free_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);  // PID
    __type(value, struct cuda_mem_stats);
} cuda_mem_per_process SEC(".maps");

// Kernel name cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);  // Function pointer
    __type(value, u8[CUDA_MAX_KERNEL_NAME]);
} cuda_kernel_names SEC(".maps");

// Submit a CUDA event to the ring buffer
static __always_inline int submit_cuda_event(struct cuda_event *event) {
    struct cuda_event *e = bpf_ringbuf_reserve(&cuda_events, sizeof(*event), 0);
    if (!e) {
        return -1;
    }
    
    __builtin_memcpy(e, event, sizeof(*event));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Track cudaLaunchKernel calls
SEC("uprobe/cudaLaunchKernel")
int BPF_UPROBE(cudaLaunchKernel, 
               void *func,        // Kernel function pointer
               u32 grid_x, u32 grid_y, u32 grid_z,
               u32 block_x, u32 block_y, u32 block_z,
               void **args,
               u64 shared_mem,
               void *stream) {
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    // Create kernel tracking entry
    struct cuda_kernel_info info = {};
    info.start_time = now;
    info.pid = pid;
    info.tid = tid;
    info.stream_id = (u64)stream;
    info.grid_dim_x = grid_x;
    info.grid_dim_y = grid_y;
    info.grid_dim_z = grid_z;
    info.block_dim_x = block_x;
    info.block_dim_y = block_y;
    info.block_dim_z = block_z;
    info.shared_mem_bytes = (u32)shared_mem;
    
    // Look up kernel name from cache
    u64 func_ptr = (u64)func;
    u8 *name = bpf_map_lookup_elem(&cuda_kernel_names, &func_ptr);
    if (name) {
        __builtin_memcpy(info.kernel_name, name, CUDA_MAX_KERNEL_NAME);
    }
    
    // Store in active kernels map
    u64 kernel_id = (pid_tgid << 16) | (now & 0xFFFF);
    bpf_map_update_elem(&cuda_active_kernels, &kernel_id, &info, BPF_ANY);
    
    // Submit launch event
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_KERNEL_LAUNCH;
    event.stream_id = (u64)stream;
    event.grid_dim_x = grid_x;
    event.grid_dim_y = grid_y;
    event.grid_dim_z = grid_z;
    event.block_dim_x = block_x;
    event.block_dim_y = block_y;
    event.block_dim_z = block_z;
    event.shared_mem_bytes = (u32)shared_mem;
    __builtin_memcpy(event.kernel_name, info.kernel_name, CUDA_MAX_KERNEL_NAME);
    
    submit_cuda_event(&event);
    
    return 0;
}

// Track cudaMemcpy calls
SEC("uprobe/cudaMemcpy")
int BPF_UPROBE(cudaMemcpy, void *dst, void *src, u64 count, u32 kind) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    // Create memop tracking entry
    struct cuda_memop_info info = {};
    info.start_time = now;
    info.pid = pid;
    info.tid = tid;
    info.src_ptr = (u64)src;
    info.dst_ptr = (u64)dst;
    info.bytes = count;
    info.memcpy_kind = kind;
    
    u64 memop_id = (pid_tgid << 16) | (now & 0xFFFF);
    bpf_map_update_elem(&cuda_active_memops, &memop_id, &info, BPF_ANY);
    
    // Submit start event
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_MEMCPY_START;
    event.src_ptr = (u64)src;
    event.dst_ptr = (u64)dst;
    event.bytes = count;
    event.memcpy_kind = kind;
    
    submit_cuda_event(&event);
    
    return 0;
}

// Track cudaMemcpyAsync calls
SEC("uprobe/cudaMemcpyAsync")
int BPF_UPROBE(cudaMemcpyAsync, void *dst, void *src, u64 count, u32 kind, void *stream) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    struct cuda_memop_info info = {};
    info.start_time = now;
    info.pid = pid;
    info.tid = tid;
    info.src_ptr = (u64)src;
    info.dst_ptr = (u64)dst;
    info.bytes = count;
    info.memcpy_kind = kind;
    info.stream_id = (u64)stream;
    
    u64 memop_id = (pid_tgid << 16) | (now & 0xFFFF);
    bpf_map_update_elem(&cuda_active_memops, &memop_id, &info, BPF_ANY);
    
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_MEMCPY_START;
    event.stream_id = (u64)stream;
    event.src_ptr = (u64)src;
    event.dst_ptr = (u64)dst;
    event.bytes = count;
    event.memcpy_kind = kind;
    
    submit_cuda_event(&event);
    
    return 0;
}

// Track cudaMalloc calls
SEC("uprobe/cudaMalloc")
int BPF_UPROBE(cudaMalloc, void **devPtr, u64 size) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_MALLOC;
    event.alloc_size = size;
    
    submit_cuda_event(&event);
    
    // Update memory statistics
    struct cuda_mem_stats *stats = bpf_map_lookup_elem(&cuda_mem_per_process, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->total_allocated, size);
        __sync_fetch_and_add(&stats->current_usage, size);
        __sync_fetch_and_add(&stats->alloc_count, 1);
        
        // Update peak if needed
        if (stats->current_usage > stats->peak_usage) {
            stats->peak_usage = stats->current_usage;
        }
    } else {
        struct cuda_mem_stats new_stats = {};
        new_stats.total_allocated = size;
        new_stats.current_usage = size;
        new_stats.peak_usage = size;
        new_stats.alloc_count = 1;
        bpf_map_update_elem(&cuda_mem_per_process, &pid, &new_stats, BPF_ANY);
    }
    
    return 0;
}

// Track cudaFree calls
SEC("uprobe/cudaFree")
int BPF_UPROBE(cudaFree, void *devPtr) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_FREE;
    event.alloc_ptr = (u64)devPtr;
    
    submit_cuda_event(&event);
    
    // Update memory statistics
    struct cuda_mem_stats *stats = bpf_map_lookup_elem(&cuda_mem_per_process, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->free_count, 1);
        // Note: We don't know the size being freed without tracking allocations
    }
    
    return 0;
}

// Track cudaDeviceSynchronize calls
SEC("uprobe/cudaDeviceSynchronize")
int BPF_UPROBE(cudaDeviceSynchronize) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_SYNC;
    
    submit_cuda_event(&event);
    
    return 0;
}

// Track cudaStreamCreate calls
SEC("uprobe/cudaStreamCreate")
int BPF_UPROBE(cudaStreamCreate, void **pStream) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_STREAM_CREATE;
    
    submit_cuda_event(&event);
    
    return 0;
}

// Track cudaStreamDestroy calls
SEC("uprobe/cudaStreamDestroy")
int BPF_UPROBE(cudaStreamDestroy, void *stream) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_STREAM_DESTROY;
    event.stream_id = (u64)stream;
    
    submit_cuda_event(&event);
    
    return 0;
}

// Return probe for cudaLaunchKernel to capture completion
SEC("uretprobe/cudaLaunchKernel")
int BPF_URETPROBE(cudaLaunchKernel_ret, int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    // Note: This captures the return from the launch, not the actual kernel completion
    // True kernel completion tracking requires CUPTI or synchronization tracking
    
    if (ret != 0) {
        struct cuda_event event = {};
        event.timestamp_ns = now;
        event.pid = pid;
        event.tid = tid;
        event.event_type = CUDA_EVENT_KERNEL_COMPLETE;
        event.cuda_error = ret;
        
        submit_cuda_event(&event);
    }
    
    return 0;
}

// Return probe for cudaMemcpy to capture completion
SEC("uretprobe/cudaMemcpy")
int BPF_URETPROBE(cudaMemcpy_ret, int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u64 now = bpf_ktime_get_ns();
    
    struct cuda_event event = {};
    event.timestamp_ns = now;
    event.pid = pid;
    event.tid = tid;
    event.event_type = CUDA_EVENT_MEMCPY_COMPLETE;
    event.cuda_error = ret;
    
    submit_cuda_event(&event);
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
