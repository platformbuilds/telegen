// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/scratch_mem.h>

volatile const u32 http_buffer_size = 0;
volatile const u32 mysql_buffer_size = 0;
volatile const u32 postgres_buffer_size = 0;
volatile const u32 kafka_buffer_size = 0;
volatile const u32 mq_buffer_size = 0;

enum {
    // Pessimistic guard for "event header + payload".
    // Keep this larger than k_large_buf_payload_max_size to accommodate struct overhead.
    k_large_buf_max_size = 1 << 14, // 16K
    k_large_buf_max_size_mask = k_large_buf_max_size - 1,

    // Maximum size for a large buffer payload.
    k_large_buf_payload_max_size = 1 << 13, // 8K
    k_large_buf_payload_max_size_mask = k_large_buf_payload_max_size - 1,
};

SCRATCH_MEM_SIZED(http_large_buffers, k_large_buf_max_size);
SCRATCH_MEM_SIZED(mysql_large_buffers, k_large_buf_max_size);
SCRATCH_MEM_SIZED(postgres_large_buffers, k_large_buf_max_size);
SCRATCH_MEM_SIZED(kafka_large_buffers, k_large_buf_max_size);
SCRATCH_MEM_SIZED(mq_large_buffers, k_large_buf_max_size);
