// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file provides stub types for the Mutex profiler BPF code.
// These are replaced by bpf2go generated code during Docker build.
// These stubs are replaced by actual generated code from bpf2go during
// `make docker-generate`. The actual generated files are:
//   - mutexprofiler_bpfel_x86.go
//   - mutexprofiler_bpfel_arm64.go

package profiler

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// Mutex event type constants
const (
	MutexEventContention uint8 = 1
	MutexEventDeadlock   uint8 = 2
	MutexEventHoldLong   uint8 = 3
)

// MutexProfilerEvent matches struct mutex_event in mutex_profiler.c
type MutexProfilerEvent struct {
	Type        uint8
	EventType   uint8
	_pad        [2]byte //nolint:unused
	Pid         uint32
	Tid         uint32
	_pad2       [4]byte //nolint:unused // alignment for lock_addr
	LockAddr    uint64
	WaitTimeNs  uint64
	HoldTimeNs  uint64
	StackId     int32
	_pad3       int32 //nolint:unused
	TimestampNs uint64
	Comm        [16]int8
}

// MutexProfilerLockState matches struct lock_state in mutex_profiler.c
type MutexProfilerLockState struct {
	AcquireStartNs uint64
	AcquiredNs     uint64
	OwnerTid       uint32
	WaiterCount    uint32
	OwnerStackId   int32
	_pad           int32 //nolint:unused // struct alignment padding for BPF compatibility
}

// MutexProfilerPendingLock matches struct pending_lock in mutex_profiler.c
type MutexProfilerPendingLock struct {
	LockAddr uint64
	StartNs  uint64
	StackId  int32
	_pad     int32 //nolint:unused // struct alignment padding for BPF compatibility
}

// MutexProfilerKey matches struct mutex_key in mutex_profiler.c
type MutexProfilerKey struct {
	LockAddr uint64
	StackId  int32
	_pad     uint32 //nolint:unused // struct alignment padding for BPF compatibility
}

// MutexProfilerMutexKey is an alias for bpf2go generated name
type MutexProfilerMutexKey = MutexProfilerKey

// MutexProfilerStats matches struct mutex_stats in mutex_profiler.c
type MutexProfilerStats struct {
	TotalWaitNs      uint64
	TotalHoldNs      uint64
	ContentionCount  uint64
	AcquisitionCount uint64
	MaxWaitNs        uint64
	MaxHoldNs        uint64
	MinWaitNs        uint64
	MinHoldNs        uint64
}

// MutexProfilerMutexStats is an alias for bpf2go generated name
type MutexProfilerMutexStats = MutexProfilerStats

// MutexProfilerConfig matches struct mutex_config in mutex_profiler.c
type MutexProfilerConfig struct {
	TargetPid             uint32
	_pad                  [4]byte   //nolint:unused // struct alignment padding for BPF compatibility
	ContentionThresholdNs uint64
	HoldThresholdNs       uint64
	FilterActive          uint8
	_pad2                 [3]byte //nolint:unused // struct alignment padding for BPF compatibility
}

// MutexProfilerMutexConfig is an alias for bpf2go generated name
type MutexProfilerMutexConfig = MutexProfilerConfig

// MutexProfilerObjects contains all BPF objects after loading
type MutexProfilerObjects struct {
	MutexProfilerPrograms
	MutexProfilerMaps
}

// MutexProfilerMaps contains all BPF maps
type MutexProfilerMaps struct {
	MutexStacks     *ebpf.Map `ebpf:"mutex_stacks"`
	LockStates      *ebpf.Map `ebpf:"lock_states"`
	PendingLocks    *ebpf.Map `ebpf:"pending_locks"`
	MutexStatsMap   *ebpf.Map `ebpf:"mutex_stats_map"`
	MutexEvents     *ebpf.Map `ebpf:"mutex_events"`
	MutexCfg        *ebpf.Map `ebpf:"mutex_cfg"`
	MutexTargetPids *ebpf.Map `ebpf:"mutex_target_pids"`
}

// MutexProfilerPrograms contains all BPF programs
type MutexProfilerPrograms struct {
	TraceMutexLockEnter *ebpf.Program `ebpf:"trace_mutex_lock_enter"`
	TraceMutexLockExit  *ebpf.Program `ebpf:"trace_mutex_lock_exit"`
	TraceMutexUnlock    *ebpf.Program `ebpf:"trace_mutex_unlock"`
}

// Close releases all BPF resources
func (o *MutexProfilerObjects) Close() error {
	if err := o.MutexProfilerMaps.Close(); err != nil {
		return err
	}
	return o.MutexProfilerPrograms.Close()
}

// Close releases all BPF maps
func (m *MutexProfilerMaps) Close() error {
	closers := []interface{ Close() error }{
		m.MutexStacks,
		m.LockStates,
		m.PendingLocks,
		m.MutexStatsMap,
		m.MutexEvents,
		m.MutexCfg,
		m.MutexTargetPids,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Close releases all BPF programs
func (p *MutexProfilerPrograms) Close() error {
	closers := []interface{ Close() error }{
		p.TraceMutexLockEnter,
		p.TraceMutexLockExit,
		p.TraceMutexUnlock,
	}
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
	return nil
}

// Placeholder BPF bytes - will be replaced by bpf2go //go:embed
var _MutexProfilerBytes = []byte{}

// LoadMutexProfiler returns the CollectionSpec for the Mutex profiler
// STUB: Returns error until real BPF code is generated
func LoadMutexProfiler() (*ebpf.CollectionSpec, error) {
	if len(_MutexProfilerBytes) == 0 {
		return nil, fmt.Errorf("mutex profiler BPF not compiled - run 'make docker-generate'")
	}
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_MutexProfilerBytes))
}

// LoadMutexProfilerObjects loads BPF objects
// STUB: Returns error until real BPF code is generated
func LoadMutexProfilerObjects(obj *MutexProfilerObjects, opts *ebpf.CollectionOptions) error {
	spec, err := LoadMutexProfiler()
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}
