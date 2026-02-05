// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"context"
	"time"
)

// ProfileType identifies the type of profile
type ProfileType string

const (
	ProfileTypeCPU        ProfileType = "cpu"
	ProfileTypeOffCPU     ProfileType = "off-cpu"
	ProfileTypeMemory     ProfileType = "memory"
	ProfileTypeMutex      ProfileType = "mutex"
	ProfileTypeWall       ProfileType = "wall"
	ProfileTypeGorout     ProfileType = "goroutine"
	ProfileTypeBlock      ProfileType = "block"
	ProfileTypeAllocs     ProfileType = "allocs"
	ProfileTypeHeap       ProfileType = "heap"
	ProfileTypeAllocBytes ProfileType = "alloc_bytes"
	ProfileTypeAllocCount ProfileType = "alloc_count"
)

// BlockReason identifies why a thread was blocked
type BlockReason uint8

const (
	BlockReasonUnknown     BlockReason = 0
	BlockReasonSleep       BlockReason = 1
	BlockReasonIO          BlockReason = 2
	BlockReasonMutex       BlockReason = 3
	BlockReasonChannel     BlockReason = 4
	BlockReasonNetwork     BlockReason = 5
	BlockReasonSync        BlockReason = 6
	BlockReasonSyscall     BlockReason = 7
	BlockReasonPreempted   BlockReason = 8
	BlockReasonWaiting     BlockReason = 9
	BlockReasonScheduler   BlockReason = 10
	BlockReasonCgroupLimit BlockReason = 11
)

// String returns the string representation of ProfileType
func (pt ProfileType) String() string {
	return string(pt)
}

// String returns the string representation of BlockReason
func (br BlockReason) String() string {
	switch br {
	case BlockReasonSleep:
		return "sleep"
	case BlockReasonIO:
		return "io"
	case BlockReasonMutex:
		return "mutex"
	case BlockReasonChannel:
		return "channel"
	case BlockReasonNetwork:
		return "network"
	case BlockReasonSync:
		return "sync"
	case BlockReasonSyscall:
		return "syscall"
	case BlockReasonPreempted:
		return "preempted"
	case BlockReasonWaiting:
		return "waiting"
	case BlockReasonScheduler:
		return "scheduler"
	case BlockReasonCgroupLimit:
		return "cgroup_limit"
	default:
		return "unknown"
	}
}

// Config holds profiler configuration
type Config struct {
	// Enabled profile types
	EnableCPU    bool
	EnableOffCPU bool
	EnableMemory bool
	EnableMutex  bool
	EnableWall   bool

	// Sampling configuration
	SampleRate         int           // Samples per second for CPU profiling
	CollectionInterval time.Duration // How often to collect/aggregate samples

	// Filtering
	TargetPID          uint32   // Specific PID to profile (0 = all)
	TargetPIDs         []uint32 // Multiple PIDs to profile
	TargetContainerIDs []string // Container IDs to profile
	ExcludeKernel      bool     // Exclude kernel stacks
	ExcludeUser        bool     // Exclude user stacks

	// Stack configuration
	MaxStackDepth int // Maximum stack depth to capture

	// Off-CPU profiling
	MinBlockTimeNs uint64 // Minimum blocking time to record (nanoseconds)

	// Memory profiling
	MinAllocSize uint64 // Minimum allocation size to track (bytes)

	// Mutex profiling
	ContentionThresholdNs uint64 // Minimum contention time to record (nanoseconds)

	// Symbol resolution
	SymbolCacheSize   int  // Size of symbol cache
	DebugInfoEnabled  bool // Use DWARF debug info
	DemanglingEnabled bool // Demangle C++/Rust symbols

	// Output
	OutputFormat    string // pprof, folded, json
	AggregateStacks bool   // Aggregate identical stacks
}

// DefaultConfig returns a default profiler configuration
func DefaultConfig() Config {
	return Config{
		EnableCPU:          true,
		EnableOffCPU:       false,
		EnableMemory:       false,
		EnableMutex:        false,
		EnableWall:         false,
		SampleRate:         99,
		CollectionInterval: 10 * time.Second,
		MaxStackDepth:      127,
		SymbolCacheSize:    10000,
		DebugInfoEnabled:   true,
		DemanglingEnabled:  true,
		OutputFormat:       "pprof",
		AggregateStacks:    true,
	}
}

// DifferentialConfig holds configuration for differential profiling
type DifferentialConfig struct {
	// Minimum percentage change to report
	MinPercentageChange float64

	// Minimum absolute change to report
	MinAbsoluteChange int64

	// Statistical significance threshold (p-value)
	SignificanceLevel float64

	// Number of top regressions/improvements to include
	TopN int

	// Whether to compare against a baseline profile
	UseBaseline  bool
	BaselinePath string

	// Time windows
	BaselineWindow   time.Duration
	ComparisonWindow time.Duration

	// Threshold for significance
	Threshold float64
}

// DefaultDifferentialConfig returns default differential config
func DefaultDifferentialConfig() DifferentialConfig {
	return DifferentialConfig{
		MinPercentageChange: 5.0,
		MinAbsoluteChange:   100,
		SignificanceLevel:   0.05,
		TopN:                20,
		UseBaseline:         false,
	}
}

// ProfileStorage is the interface for storing and retrieving profiles
type ProfileStorage interface {
	// Store saves a profile
	Store(profile *Profile) error

	// Load loads profiles matching the query
	Load(query ProfileQuery) ([]*Profile, error)

	// Query queries profiles matching the parameters
	Query(ctx context.Context, profileType ProfileType, timeRange TimeRange) ([]*Profile, error)

	// Delete removes profiles matching the query
	Delete(query ProfileQuery) error
}

// ProfileQuery specifies which profiles to load
type ProfileQuery struct {
	ProfileType ProfileType
	StartTime   time.Time
	EndTime     time.Time
	PID         uint32
	Container   string
	Limit       int
}

// Profiler is the interface for all profiler implementations
type Profiler interface {
	// Start begins profiling
	Start(ctx context.Context) error

	// Stop stops profiling
	Stop() error

	// Collect returns collected profiles since last call
	Collect() []*Profile
}

// TimeRange represents a time range for profile queries
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// FlameGraphConfig holds configuration for flame graph generation
// Note: FlameGraphFormat and ColorScheme are defined in flamegraph.go
type FlameGraphConfig struct {
	Title           string
	Width           int
	Height          int
	MinWidth        float64 // Minimum width percentage to show
	MaxDepth        int
	Reverse         bool
	Inverted        bool
	ColorScheme     ColorScheme
	ShowPercentages bool
	ShowSelf        bool
	CompactLabels   bool
	Format          FlameGraphFormat
}

// DefaultFlameGraphConfig returns default flame graph config
func DefaultFlameGraphConfig() FlameGraphConfig {
	return FlameGraphConfig{
		Title:           "Flame Graph",
		Width:           1200,
		Height:          600,
		MinWidth:        0.1,
		MaxDepth:        0,
		Reverse:         false,
		Inverted:        false,
		ColorScheme:     "hot",
		ShowPercentages: true,
		ShowSelf:        true,
		CompactLabels:   false,
	}
}

// DiffSummary and SignificanceResult are defined in differential.go
