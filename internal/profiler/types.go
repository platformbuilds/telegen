// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"time"
)

// Profile represents a collected profile
type Profile struct {
	// Type of profile
	Type ProfileType

	// Timestamp when the profile was collected
	Timestamp time.Time

	// Duration of the profiling period
	Duration time.Duration

	// ProcessInfo about the profiled processes
	ProcessInfo []ProcessInfo

	// Samples collected in this profile
	Samples []StackSample

	// Metadata about the profile
	Metadata map[string]string
}

// ProcessInfo contains information about a profiled process
type ProcessInfo struct {
	PID       uint32
	TGID      uint32
	Comm      string
	StartTime time.Time
	Cmdline   string
	Container string
}

// StackSample represents a single stack sample
type StackSample struct {
	// Stack frames from bottom to top
	Frames []ResolvedFrame

	// Value depends on profile type:
	// - CPU: sample count
	// - Off-CPU: total block time in nanoseconds
	// - Memory: bytes allocated
	// - Mutex: total wait time in nanoseconds
	Value int64

	// Count of occurrences
	Count int64

	// ProcessInfo
	PID  uint32
	TGID uint32
	Comm string

	// Timestamps
	FirstSeen time.Time
	LastSeen  time.Time

	// Type-specific fields
	BlockReason BlockReason // For off-CPU
	AllocType   uint8       // For memory
}

// ResolvedFrame is a fully resolved stack frame
type ResolvedFrame struct {
	// Address is the instruction pointer
	Address uint64

	// Function is the fully qualified function name
	Function string

	// ShortName is the function name without package path
	ShortName string

	// Module is the binary/library name
	Module string

	// File is the source file path
	File string

	// Line is the line number in the source file
	Line int

	// Column is the column number (if available)
	Column int

	// Inlined indicates if this frame was inlined
	Inlined bool

	// IsKernel indicates if this frame is from kernel space
	IsKernel bool

	// Language-specific fields
	Package  string // Go package
	Receiver string // Go method receiver
	Class    string // Java/Python class
}

// CPUSample represents a CPU profile sample from eBPF
type CPUSample struct {
	PID           uint32
	TGID          uint32
	CPU           uint32
	UserStackID   int32
	KernelStackID int32
	Timestamp     uint64
	Comm          [16]byte
}

// OffCPUSample represents an off-CPU profile sample from eBPF
type OffCPUSample struct {
	PID           uint32
	TGID          uint32
	UserStackID   int32
	KernelStackID int32
	Timestamp     uint64
	BlockTime     uint64
	BlockReason   uint8
	WakerPID      uint32
	Comm          [16]byte
}

// MemorySample represents a memory allocation sample from eBPF
type MemorySample struct {
	PID       uint32
	TID       uint32
	Address   uint64
	Size      uint64
	Timestamp uint64
	StackID   int32
	AllocType uint8
	IsFree    bool
	Comm      [16]byte
}

// MutexSample represents a mutex contention sample from eBPF
type MutexSample struct {
	PID       uint32
	TID       uint32
	LockAddr  uint64
	WaitTime  uint64
	HoldTime  uint64
	Timestamp uint64
	StackID   int32
	EventType uint8
	Comm      [16]byte
}

// WallSample represents a wall clock sample from eBPF
type WallSample struct {
	PID           uint32
	TID           uint32
	UserStackID   int32
	KernelStackID int32
	WallTime      uint64
	CPUTime       uint64
	OffCPUTime    uint64
	Comm          [16]byte
}

// StackKey is the key for stack aggregation
type StackKey struct {
	PID           uint32
	TGID          uint32
	UserStackID   int32
	KernelStackID int32
	Comm          [16]byte
}

// StackCount holds aggregated count for a stack
type StackCount struct {
	Count       uint64
	FirstSeenNs uint64
	LastSeenNs  uint64
}

// OffCPUKey is the key for off-CPU aggregation
type OffCPUKey struct {
	PID           uint32
	TGID          uint32
	UserStackID   int32
	KernelStackID int32
	BlockReason   uint8
	Comm          [16]byte
}

// OffCPUValue holds aggregated off-CPU statistics
type OffCPUValue struct {
	TotalTimeNs  uint64
	Count        uint64
	MaxTimeNs    uint64
	MinTimeNs    uint64
	SumSquaredNs uint64
}

// AllocKey is the key for allocation aggregation
type AllocKey struct {
	StackID   int32
	AllocType uint8
}

// AllocStats holds aggregated allocation statistics
type AllocStats struct {
	TotalBytes      uint64
	AllocCount      uint64
	FreeCount       uint64
	CurrentBytes    uint64
	CurrentCount    uint64
	MaxBytes        uint64
	TotalLifetimeNs uint64
}

// MutexKey is the key for mutex aggregation
type MutexKey struct {
	LockAddr uint64
	StackID  int32
}

// MutexStats holds aggregated mutex statistics
type MutexStats struct {
	TotalWaitNs      uint64
	TotalHoldNs      uint64
	ContentionCount  uint64
	AcquisitionCount uint64
	MaxWaitNs        uint64
	MaxHoldNs        uint64
	MinWaitNs        uint64
	MinHoldNs        uint64
}

// NewProfile creates a new profile
func NewProfile(profileType ProfileType) *Profile {
	return &Profile{
		Type:      profileType,
		Timestamp: time.Now(),
		Samples:   make([]StackSample, 0),
		Metadata:  make(map[string]string),
	}
}

// AddSample adds a sample to the profile
func (p *Profile) AddSample(sample StackSample) {
	p.Samples = append(p.Samples, sample)
}

// TotalValue returns the sum of all sample values
func (p *Profile) TotalValue() int64 {
	var total int64
	for _, s := range p.Samples {
		total += s.Value
	}
	return total
}

// TotalCount returns the sum of all sample counts
func (p *Profile) TotalCount() int64 {
	var total int64
	for _, s := range p.Samples {
		total += s.Count
	}
	return total
}
