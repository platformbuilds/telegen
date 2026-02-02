// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0
// Task: ML-014 - CUDA Tracer Header

#pragma once

#include <pid/pid.h>

// Maximum kernel name length
#define CUDA_MAX_KERNEL_NAME 128

// CUDA event types - must match the constants in cuda_tracer.c
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

// CUDA event structure - serialized to ring buffer
typedef struct cuda_event {
    u64 timestamp_ns;        // Event timestamp
    u64 duration_ns;         // Duration (for completion events)
    u32 pid;                 // Process ID
    u32 tid;                 // Thread ID
    u32 event_type;          // Event type (CUDA_EVENT_*)
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
    u32 _pad;  // Alignment padding
} cuda_event_t;

// Per-process GPU memory statistics
typedef struct cuda_mem_stats {
    u64 total_allocated;
    u64 total_freed;
    u64 peak_usage;
    u64 current_usage;
    u64 alloc_count;
    u64 free_count;
} cuda_mem_stats_t;
