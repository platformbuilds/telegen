// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file provides stub types for the Off-CPU profiler BPF code.
// These are replaced by bpf2go generated code during Docker build.
// These stubs are replaced by actual generated code from bpf2go during
// `make docker-generate`. The actual generated files are:
//   - offcpuprofiler_bpfel_x86.go
//   - offcpuprofiler_bpfel_arm64.go

package profiler

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// OffcpuProfilerKey matches struct offcpu_key in offcpu_profiler.c
type OffcpuProfilerKey struct {
	Pid           uint32
	Tgid          uint32
	UserStackId   int32
	KernelStackId int32
	Comm          [16]int8
	BlockReason   uint8
	_pad          [3]byte
}

// OffcpuProfilerOffcpuKey is an alias for bpf2go generated name
type OffcpuProfilerOffcpuKey = OffcpuProfilerKey

// OffcpuProfilerValue matches struct offcpu_value in offcpu_profiler.c
type OffcpuProfilerValue struct {
	TotalTimeNs  uint64
	Count        uint64
	MaxTimeNs    uint64
	MinTimeNs    uint64
	SumSquaredNs uint64
}

// OffcpuProfilerOffcpuValue is an alias for bpf2go generated name
type OffcpuProfilerOffcpuValue = OffcpuProfilerValue

// OffcpuProfilerEvent matches struct offcpu_event in offcpu_profiler.c
type OffcpuProfilerEvent struct {
	Type          uint8
	BlockReason   uint8
	_pad          [2]byte
	Pid           uint32
	Tgid          uint32
	WakerPid      uint32
	UserStackId   int32
	KernelStackId int32
	TimestampNs   uint64
	BlockTimeNs   uint64
	Comm          [16]int8
}

// OffcpuProfilerStart matches struct offcpu_start in offcpu_profiler.c
type OffcpuProfilerStart struct {
	StartNs       uint64
	UserStackId   int32
	KernelStackId int32
	Reason        uint8
	_pad          [7]byte
}

// OffcpuProfilerConfig matches struct offcpu_config in offcpu_profiler.c
type OffcpuProfilerConfig struct {
	TargetPid     uint32
	_pad1         [4]byte // alignment
	MinBlockNs    uint64
	CaptureKernel uint8
	CaptureUser   uint8
	_pad2         [6]byte
}

// OffcpuProfilerOffcpuConfig is an alias for bpf2go generated name
type OffcpuProfilerOffcpuConfig = OffcpuProfilerConfig

// OffcpuProfilerObjects contains all BPF objects after loading
type OffcpuProfilerObjects struct {
	OffcpuProfilerPrograms
	OffcpuProfilerMaps
}

// OffcpuProfilerMaps contains all BPF maps
type OffcpuProfilerMaps struct {
	OffcpuStacks     *ebpf.Map `ebpf:"offcpu_stacks"`
	OffcpuStartTimes *ebpf.Map `ebpf:"offcpu_start_times"`
	OffcpuCounts     *ebpf.Map `ebpf:"offcpu_counts"`
	OffcpuEvents     *ebpf.Map `ebpf:"offcpu_events"`
	OffcpuCfg        *ebpf.Map `ebpf:"offcpu_cfg"`
	OffcpuTargetPids *ebpf.Map `ebpf:"offcpu_target_pids"`
}

// OffcpuProfilerPrograms contains all BPF programs
type OffcpuProfilerPrograms struct {
	OffcpuSchedSwitch *ebpf.Program `ebpf:"offcpu_sched_switch"`
	TraceFutexWait    *ebpf.Program `ebpf:"trace_futex_wait"`
	TraceEpollWait    *ebpf.Program `ebpf:"trace_epoll_wait"`
}

// Close releases all BPF resources
func (o *OffcpuProfilerObjects) Close() error {
	if err := o.OffcpuProfilerMaps.Close(); err != nil {
		return err
	}
	return o.OffcpuProfilerPrograms.Close()
}

// Close releases all BPF maps
func (m *OffcpuProfilerMaps) Close() error {
	closers := []interface{ Close() error }{
		m.OffcpuStacks,
		m.OffcpuStartTimes,
		m.OffcpuCounts,
		m.OffcpuEvents,
		m.OffcpuCfg,
		m.OffcpuTargetPids,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Close releases all BPF programs
func (p *OffcpuProfilerPrograms) Close() error {
	closers := []interface{ Close() error }{
		p.OffcpuSchedSwitch,
		p.TraceFutexWait,
		p.TraceEpollWait,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Placeholder BPF bytes - will be replaced by bpf2go //go:embed
var _OffcpuProfilerBytes = []byte{}

// LoadOffcpuProfiler returns the CollectionSpec for the Off-CPU profiler
// STUB: Returns error until real BPF code is generated
func LoadOffcpuProfiler() (*ebpf.CollectionSpec, error) {
	if len(_OffcpuProfilerBytes) == 0 {
		return nil, fmt.Errorf("off-cpu profiler BPF not compiled - run 'make docker-generate'")
	}
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_OffcpuProfilerBytes))
}

// LoadOffcpuProfilerObjects loads BPF objects
// STUB: Returns error until real BPF code is generated
func LoadOffcpuProfilerObjects(obj *OffcpuProfilerObjects, opts *ebpf.CollectionOptions) error {
	spec, err := LoadOffcpuProfiler()
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}
