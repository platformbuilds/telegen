// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file provides stub types for the Alloc/Memory profiler BPF code.
// These are replaced by bpf2go generated code during Docker build.
// These stubs are replaced by actual generated code from bpf2go during
// `make docker-generate`. The actual generated files are:
//   - allocprofiler_bpfel_x86.go
//   - allocprofiler_bpfel_arm64.go

package profiler

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// Allocation type constants
const (
	AllocMalloc        uint8 = 1
	AllocCalloc        uint8 = 2
	AllocRealloc       uint8 = 3
	AllocMmap          uint8 = 4
	AllocNew           uint8 = 5
	AllocPosixMemalign uint8 = 6
)

// Free type constants
const (
	FreeFree   uint8 = 1
	FreeMunmap uint8 = 2
	FreeDelete uint8 = 3
)

// AllocProfilerInfo matches struct alloc_info in alloc_profiler.c
type AllocProfilerInfo struct {
	Size        uint64
	TimestampNs uint64
	StackId     int32
	Pid         uint32
	Tid         uint32
	AllocType   uint8
	_pad        [3]byte //nolint:unused
}

// AllocProfilerAllocInfo is an alias for bpf2go generated name
type AllocProfilerAllocInfo = AllocProfilerInfo

// AllocProfilerEvent matches struct alloc_event in alloc_profiler.c
type AllocProfilerEvent struct {
	Type        uint8
	AllocType   uint8
	IsFree      uint8
	_pad        uint8 //nolint:unused
	Pid         uint32
	Tid         uint32
	_pad2       [4]byte //nolint:unused // alignment
	Addr        uint64
	Size        uint64
	TimestampNs uint64
	StackId     int32
	_pad3       int32 //nolint:unused
	Comm        [16]int8
}

// AllocProfilerKey matches struct alloc_key in alloc_profiler.c
type AllocProfilerKey struct {
	StackId   int32
	AllocType uint8
	_pad      [3]byte //nolint:unused
}

// AllocProfilerAllocKey is an alias for bpf2go generated name
type AllocProfilerAllocKey = AllocProfilerKey

// AllocProfilerStats matches struct alloc_stats in alloc_profiler.c
type AllocProfilerStats struct {
	TotalBytes      uint64
	AllocCount      uint64
	FreeCount       uint64
	CurrentBytes    uint64
	CurrentCount    uint64
	MaxBytes        uint64
	TotalLifetimeNs uint64
}

// AllocProfilerAllocStats is an alias for bpf2go generated name
type AllocProfilerAllocStats = AllocProfilerStats

// AllocProfilerPending matches struct pending_alloc in alloc_profiler.c
type AllocProfilerPending struct {
	Size      uint64
	StartNs   uint64
	StackId   int32
	AllocType uint8
	_pad      [3]byte //nolint:unused
}

// AllocProfilerPendingRealloc matches struct pending_realloc in alloc_profiler.c
type AllocProfilerPendingRealloc struct {
	OldAddr uint64
	NewSize uint64
	StartNs uint64
	StackId int32
	_pad    int32 //nolint:unused
}

// AllocProfilerConfig matches struct alloc_config in alloc_profiler.c
type AllocProfilerConfig struct {
	TargetPid    uint32
	_pad         [4]byte //nolint:unused
	MinSize      uint64
	SampleRate   uint64
	TrackFree    uint8
	TrackCalloc  uint8
	TrackRealloc uint8
	TrackMmap    uint8
	FilterActive uint8
	_pad2        [3]byte //nolint:unused
}

// AllocProfilerAllocConfig is an alias for bpf2go generated name
type AllocProfilerAllocConfig = AllocProfilerConfig

// AllocProfilerObjects contains all BPF objects after loading
type AllocProfilerObjects struct {
	AllocProfilerPrograms
	AllocProfilerMaps
}

// AllocProfilerMaps contains all BPF maps
type AllocProfilerMaps struct {
	AllocStacks     *ebpf.Map `ebpf:"alloc_stacks"`
	PendingAllocs   *ebpf.Map `ebpf:"pending_allocs"`
	PendingReallocs *ebpf.Map `ebpf:"pending_reallocs"`
	LiveAllocs      *ebpf.Map `ebpf:"live_allocs"`
	AllocStatsMap   *ebpf.Map `ebpf:"alloc_stats_map"`
	AllocEvents     *ebpf.Map `ebpf:"alloc_events"`
	AllocCfg        *ebpf.Map `ebpf:"alloc_cfg"`
	AllocTargetPids *ebpf.Map `ebpf:"alloc_target_pids"`
}

// AllocProfilerPrograms contains all BPF programs
type AllocProfilerPrograms struct {
	TraceMallocEnter  *ebpf.Program `ebpf:"trace_malloc_enter"`
	TraceMallocExit   *ebpf.Program `ebpf:"trace_malloc_exit"`
	TraceFree         *ebpf.Program `ebpf:"trace_free"`
	TraceCallocEnter  *ebpf.Program `ebpf:"trace_calloc_enter"`
	TraceCallocExit   *ebpf.Program `ebpf:"trace_calloc_exit"`
	TraceReallocEnter *ebpf.Program `ebpf:"trace_realloc_enter"`
	TraceReallocExit  *ebpf.Program `ebpf:"trace_realloc_exit"`
	TraceMmap         *ebpf.Program `ebpf:"trace_do_mmap"`
	TraceMunmap       *ebpf.Program `ebpf:"trace_do_munmap"`
}

// Close releases all BPF resources
func (o *AllocProfilerObjects) Close() error {
	if err := o.AllocProfilerMaps.Close(); err != nil {
		return err
	}
	return o.AllocProfilerPrograms.Close()
}

// Close releases all BPF maps
func (m *AllocProfilerMaps) Close() error {
	closers := []interface{ Close() error }{
		m.AllocStacks,
		m.PendingAllocs,
		m.PendingReallocs,
		m.LiveAllocs,
		m.AllocStatsMap,
		m.AllocEvents,
		m.AllocCfg,
		m.AllocTargetPids,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Close releases all BPF programs
func (p *AllocProfilerPrograms) Close() error {
	closers := []interface{ Close() error }{
		p.TraceMallocEnter,
		p.TraceMallocExit,
		p.TraceFree,
		p.TraceCallocEnter,
		p.TraceCallocExit,
		p.TraceReallocEnter,
		p.TraceReallocExit,
		p.TraceMmap,
		p.TraceMunmap,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Placeholder BPF bytes - will be replaced by bpf2go //go:embed
var _AllocProfilerBytes = []byte{}

// LoadAllocProfiler returns the CollectionSpec for the Alloc profiler
// STUB: Returns error until real BPF code is generated
func LoadAllocProfiler() (*ebpf.CollectionSpec, error) {
	if len(_AllocProfilerBytes) == 0 {
		return nil, fmt.Errorf("alloc profiler BPF not compiled - run 'make docker-generate'")
	}
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_AllocProfilerBytes))
}

// LoadAllocProfilerObjects loads BPF objects
// STUB: Returns error until real BPF code is generated
func LoadAllocProfilerObjects(obj *AllocProfilerObjects, opts *ebpf.CollectionOptions) error {
	spec, err := LoadAllocProfiler()
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}
