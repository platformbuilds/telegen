// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file provides stub types for the CPU profiler BPF code.
// These are replaced by bpf2go generated code during Docker build.
// These stubs are replaced by actual generated code from bpf2go during
// `make docker-generate`. The actual generated files are:
//   - cpuprofiler_bpfel_x86.go
//   - cpuprofiler_bpfel_arm64.go
//
// The stubs allow the code to compile without the generated BPF,
// but profiling will not work until the real code is generated.

package profiler

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// CpuProfilerStackKey matches struct stack_key in cpu_profiler.c
type CpuProfilerStackKey struct {
	Pid           uint32
	Tgid          uint32
	UserStackId   int32
	KernelStackId int32
	Comm          [16]int8
}

// CpuProfilerStackCount matches struct stack_count in cpu_profiler.c
type CpuProfilerStackCount struct {
	Count       uint64
	FirstSeenNs uint64
	LastSeenNs  uint64
}

// CpuProfilerSampleEvent matches struct cpu_sample_event in cpu_profiler.c
type CpuProfilerSampleEvent struct {
	Type          uint8
	_pad          [3]byte
	Pid           uint32
	Tgid          uint32
	Cpu           uint32
	UserStackId   int32
	KernelStackId int32
	TimestampNs   uint64
	Comm          [16]int8
}

// CpuProfilerConfig matches struct cpu_profiler_config in cpu_profiler.c
type CpuProfilerConfig struct {
	TargetPid     uint32
	SampleRateHz  uint32
	CaptureKernel uint8
	CaptureUser   uint8
	FilterActive  uint8
	_pad          [1]byte
}

// CpuProfilerCpuProfilerConfig is an alias for bpf2go generated name
type CpuProfilerCpuProfilerConfig = CpuProfilerConfig

// CpuProfilerObjects contains all BPF objects after loading
type CpuProfilerObjects struct {
	CpuProfilerPrograms
	CpuProfilerMaps
}

// CpuProfilerMaps contains all BPF maps
type CpuProfilerMaps struct {
	CpuStacks        *ebpf.Map `ebpf:"cpu_stacks"`
	CpuStackCounts   *ebpf.Map `ebpf:"cpu_stack_counts"`
	CpuProfileEvents *ebpf.Map `ebpf:"cpu_profile_events"`
	CpuProfilerCfg   *ebpf.Map `ebpf:"cpu_profiler_cfg"`
	CpuTargetPids    *ebpf.Map `ebpf:"cpu_target_pids"`
}

// CpuProfilerPrograms contains all BPF programs
type CpuProfilerPrograms struct {
	ProfileCpu *ebpf.Program `ebpf:"profile_cpu"`
}

// Close releases all BPF resources
func (o *CpuProfilerObjects) Close() error {
	if err := o.CpuProfilerMaps.Close(); err != nil {
		return err
	}
	return o.CpuProfilerPrograms.Close()
}

// Close releases all BPF maps
func (m *CpuProfilerMaps) Close() error {
	closers := []interface{ Close() error }{
		m.CpuStacks,
		m.CpuStackCounts,
		m.CpuProfileEvents,
		m.CpuProfilerCfg,
		m.CpuTargetPids,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Close releases all BPF programs
func (p *CpuProfilerPrograms) Close() error {
	if p.ProfileCpu != nil {
		return p.ProfileCpu.Close()
	}
	return nil
}

// Placeholder BPF bytes - will be replaced by bpf2go //go:embed
var _CpuProfilerBytes = []byte{}

// LoadCpuProfiler returns the CollectionSpec for the CPU profiler
// STUB: Returns error until real BPF code is generated
func LoadCpuProfiler() (*ebpf.CollectionSpec, error) {
	if len(_CpuProfilerBytes) == 0 {
		return nil, fmt.Errorf("CPU profiler BPF not generated - run 'make docker-generate' first")
	}
	reader := bytes.NewReader(_CpuProfilerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load CpuProfiler: %w", err)
	}
	return spec, nil
}

// LoadCpuProfilerObjects loads CpuProfiler and converts it into a struct
func LoadCpuProfilerObjects(obj *CpuProfilerObjects, opts *ebpf.CollectionOptions) error {
	spec, err := LoadCpuProfiler()
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}
