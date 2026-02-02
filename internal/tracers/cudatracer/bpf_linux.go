// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package cudatracer provides eBPF-based CUDA kernel and memory operation tracing.
// This file provides the BPF types for Linux platforms.
// TODO: Replace with bpf2go generated code once BPF programs are compiled.
package cudatracer

import (
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// BpfCudaEventT is the CUDA event structure from BPF
type BpfCudaEventT struct {
	TimestampNs    uint64
	DurationNs     uint64
	Pid            uint32
	Tid            uint32
	EventType      uint32
	GpuId          uint32
	StreamId       uint64
	GridDimX       uint32
	GridDimY       uint32
	GridDimZ       uint32
	BlockDimX      uint32
	BlockDimY      uint32
	BlockDimZ      uint32
	SharedMemBytes uint32
	KernelName     [128]uint8
	SrcPtr         uint64
	DstPtr         uint64
	Bytes          uint64
	MemcpyKind     uint32
	AllocPtr       uint64
	AllocSize      uint64
	CudaError      uint32
	Pad            uint32
}

// BpfCudaMemStatsT is the per-process GPU memory statistics structure from BPF
type BpfCudaMemStatsT struct {
	TotalAllocated uint64
	TotalFreed     uint64
	PeakUsage      uint64
	CurrentUsage   uint64
	AllocCount     uint64
	FreeCount      uint64
}

// BpfObjects contains the BPF objects
type BpfObjects struct {
	CudaLaunchKernel      *ebpf.Program
	CudaLaunchKernelRet   *ebpf.Program
	CudaMemcpy            *ebpf.Program
	CudaMemcpyRet         *ebpf.Program
	CudaMemcpyAsync       *ebpf.Program
	CudaMalloc            *ebpf.Program
	CudaFree              *ebpf.Program
	CudaDeviceSynchronize *ebpf.Program
	CudaStreamCreate      *ebpf.Program
	CudaStreamDestroy     *ebpf.Program
	CudaEvents            *ebpf.Map
	CudaMemStats          *ebpf.Map
}

// Close closes all BPF objects
func (o *BpfObjects) Close() error {
	closers := []io.Closer{
		o.CudaLaunchKernel,
		o.CudaLaunchKernelRet,
		o.CudaMemcpy,
		o.CudaMemcpyRet,
		o.CudaMemcpyAsync,
		o.CudaMalloc,
		o.CudaFree,
		o.CudaDeviceSynchronize,
		o.CudaStreamCreate,
		o.CudaStreamDestroy,
		o.CudaEvents,
		o.CudaMemStats,
	}

	for _, closer := range closers {
		if closer != nil {
			closer.Close()
		}
	}

	return nil
}

// LoadBpf returns the embedded CollectionSpec for the BPF program
// TODO: Replace with actual embedded BPF bytecode once compiled
func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("CUDA tracer BPF program not yet compiled - run 'make generate-bpf'")
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
