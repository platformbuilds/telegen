// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file provides stub types for the Wall clock profiler BPF code.
// These are replaced by bpf2go generated code during Docker build.
// These stubs are replaced by actual generated code from bpf2go during
// `make docker-generate`. The actual generated files are:
//   - wallprofiler_bpfel_x86.go
//   - wallprofiler_bpfel_arm64.go
//
// The stubs allow the code to compile without the generated BPF,
// but profiling will not work until the real code is generated.

package profiler

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// WallProfilerWallKey matches struct wall_key in wall_profiler.c
type WallProfilerWallKey struct {
	Pid           uint32
	Tid           uint32
	UserStackId   int32
	KernelStackId int32
	Comm          [16]int8
}

// WallProfilerWallValue matches struct wall_value in wall_profiler.c
type WallProfilerWallValue struct {
	TotalWallNs   uint64
	TotalCpuNs    uint64
	TotalOffcpuNs uint64
	Count         uint64
}

// WallProfilerWallConfig matches struct wall_config in wall_profiler.c
type WallProfilerWallConfig struct {
	TargetPid        uint32
	_pad             [4]byte //nolint:unused // alignment
	SampleIntervalNs uint64
	FilterActive     uint8
	_pad2            [7]byte //nolint:unused
}

// WallProfilerObjects contains all BPF objects after loading
type WallProfilerObjects struct {
	WallProfilerPrograms
	WallProfilerMaps
}

// WallProfilerMaps contains all BPF maps
type WallProfilerMaps struct {
	WallStacks     *ebpf.Map `ebpf:"wall_stacks"`
	WallCounts     *ebpf.Map `ebpf:"wall_counts"`
	WallEvents     *ebpf.Map `ebpf:"wall_events"`
	WallCfg        *ebpf.Map `ebpf:"wall_cfg"`
	WallTargetPids *ebpf.Map `ebpf:"wall_target_pids"`
}

// WallProfilerPrograms contains all BPF programs
type WallProfilerPrograms struct {
	ProfileWall    *ebpf.Program `ebpf:"profile_wall"`
	WallSchedSwitch *ebpf.Program `ebpf:"wall_sched_switch"`
}

// Close releases all BPF resources
func (o *WallProfilerObjects) Close() error {
	if err := o.WallProfilerMaps.Close(); err != nil {
		return err
	}
	return o.WallProfilerPrograms.Close()
}

// Close releases all BPF maps
func (m *WallProfilerMaps) Close() error {
	closers := []interface{ Close() error }{
		m.WallStacks,
		m.WallCounts,
		m.WallEvents,
		m.WallCfg,
		m.WallTargetPids,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Close releases all BPF programs
func (p *WallProfilerPrograms) Close() error {
	closers := []interface{ Close() error }{
		p.ProfileWall,
		p.WallSchedSwitch,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Placeholder BPF bytes - will be replaced by bpf2go //go:embed
var _WallProfilerBytes = []byte{}

// LoadWallProfiler returns the CollectionSpec for the wall clock profiler
// STUB: Returns error until real BPF code is generated
func LoadWallProfiler() (*ebpf.CollectionSpec, error) {
	if len(_WallProfilerBytes) == 0 {
		return nil, fmt.Errorf("wall profiler BPF not compiled - run 'make docker-generate'")
	}
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_WallProfilerBytes))
}

// LoadWallProfilerObjects loads BPF objects
// STUB: Returns error until real BPF code is generated
func LoadWallProfilerObjects(obj *WallProfilerObjects, opts *ebpf.CollectionOptions) error {
	spec, err := LoadWallProfiler()
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}
