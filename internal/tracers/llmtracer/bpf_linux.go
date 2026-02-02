// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package llmtracer provides eBPF-based LLM API request tracing.
// This file provides the BPF types for Linux platforms.
// TODO: Replace with bpf2go generated code once BPF programs are compiled.
package llmtracer

import (
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// BpfLlmEventT is the LLM event structure from BPF
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
	ActiveRequests        *ebpf.Map
}

// Close closes all BPF objects
func (o *BpfObjects) Close() error {
	closers := []io.Closer{
		o.Http2WriteFrame,
		o.HttpReadResponse,
		o.SseEvent,
		o.PythonOpenaiCreate,
		o.PythonAnthropicCreate,
		o.LlmEvents,
		o.ActiveRequests,
	}

	for _, closer := range closers {
		if closer != nil {
			_ = closer.Close()
		}
	}

	return nil
}

// LoadBpf returns the embedded CollectionSpec for the BPF program
// TODO: Replace with actual embedded BPF bytecode once compiled
func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("LLM tracer BPF program not yet compiled - run 'make generate-bpf'")
}

// LoadBpfObjects loads Bpf and converts it into a struct
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

var _ io.Closer = (*BpfObjects)(nil)
