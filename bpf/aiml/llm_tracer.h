// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0
// Task: ML-011 - LLM Tracer Header

#pragma once

#include <pid/pid.h>

// Maximum sizes for captured data
#define LLM_MAX_MODEL_LEN 128
#define LLM_MAX_ENDPOINT_LEN 256
#define LLM_REQUEST_ID_LEN 36

// LLM event types - must match the constants in llm_tracer.c
#define LLM_EVENT_REQUEST_START  0
#define LLM_EVENT_REQUEST_END    1
#define LLM_EVENT_FIRST_TOKEN    2
#define LLM_EVENT_STREAM_CHUNK   3
#define LLM_EVENT_ERROR          4

// LLM provider types
#define LLM_PROVIDER_UNKNOWN     0
#define LLM_PROVIDER_OPENAI      1
#define LLM_PROVIDER_ANTHROPIC   2
#define LLM_PROVIDER_AZURE       3
#define LLM_PROVIDER_GOOGLE      4
#define LLM_PROVIDER_COHERE      5
#define LLM_PROVIDER_MISTRAL     6
#define LLM_PROVIDER_LOCAL       7

// LLM event structure - serialized to ring buffer
typedef struct llm_event {
    u64 timestamp_ns;                     // Event timestamp
    u64 duration_ns;                      // Duration (for end events)
    u64 ttft_ns;                          // Time to first token (for streaming)
    u32 pid;                              // Process ID
    u32 tid;                              // Thread ID
    u32 event_type;                       // Event type (LLM_EVENT_*)
    u32 provider;                         // LLM provider (LLM_PROVIDER_*)
    u32 prompt_tokens;                    // Input token count
    u32 completion_tokens;                // Output token count
    u32 status_code;                      // HTTP status code
    u32 is_streaming;                     // Streaming request flag
    u32 chunk_index;                      // Stream chunk index
    u32 _pad;                             // Alignment padding
    u8 request_id[LLM_REQUEST_ID_LEN];    // Request ID (UUID)
    u8 model[LLM_MAX_MODEL_LEN];          // Model name
    u8 endpoint[LLM_MAX_ENDPOINT_LEN];    // API endpoint
    u8 error_msg[256];                    // Error message
} llm_event_t;
