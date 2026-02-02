// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// Package llmtracer provides eBPF-based LLM API request tracing.
// This file provides stub types for non-Linux platforms where eBPF is not supported.
package llmtracer

import (
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// BpfLlmEventT is the LLM event structure from BPF
// This is a stub for non-Linux platforms
type BpfLlmEventT struct {
	TimestampNs      uint64
	DurationNs       uint64
	TtftNs           uint64
	Pid              uint32
	Tid              uint32
	EventType        uint32
	Provider         uint32
	PromptTokens     uint32
	CompletionTokens uint32
	StatusCode       uint32
	IsStreaming      uint32
	ChunkIndex       uint32
	Pad              uint32
	RequestId        [36]uint8
	Model            [128]uint8
	Endpoint         [256]uint8
	ErrorMsg         [256]uint8
}

// BpfObjects contains the BPF objects
type BpfObjects struct {
	Http2WriteFrame       *ebpf.Program
	HttpReadResponse      *ebpf.Program
	SseEvent              *ebpf.Program
	PythonOpenaiCreate    *ebpf.Program
	PythonAnthropicCreate *ebpf.Program
	LlmEvents             *ebpf.Map
}

// Close closes all BPF objects
func (o *BpfObjects) Close() error {
	return nil
}

// LoadBpf returns an error on non-Linux platforms
func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("LLM tracer is only supported on Linux")
}

var _ io.Closer = (*BpfObjects)(nil)
