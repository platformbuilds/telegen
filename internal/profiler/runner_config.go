// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"time"
)

// RunnerConfig holds configuration for the profiling runner
type RunnerConfig struct {
	// General settings
	Enabled            bool          `mapstructure:"enabled" yaml:"enabled"`
	CollectionInterval time.Duration `mapstructure:"collection_interval" yaml:"collection_interval"`
	UploadInterval     time.Duration `mapstructure:"upload_interval" yaml:"upload_interval"`

	// CPU profiling
	CPU CPUConfig `mapstructure:"cpu" yaml:"cpu"`

	// Off-CPU profiling
	OffCPU OffCPUConfig `mapstructure:"off_cpu" yaml:"off_cpu"`

	// Memory profiling
	Memory MemoryConfig `mapstructure:"memory" yaml:"memory"`

	// Mutex profiling
	Mutex MutexConfig `mapstructure:"mutex" yaml:"mutex"`

	// Wall clock profiling
	Wall WallConfig `mapstructure:"wall" yaml:"wall"`

	// Target filtering
	TargetPID          uint32   `mapstructure:"target_pid" yaml:"target_pid"`
	TargetPIDs         []uint32 `mapstructure:"target_pids" yaml:"target_pids"`
	TargetContainerIDs []string `mapstructure:"target_container_ids" yaml:"target_container_ids"`
	ExcludeKernel      bool     `mapstructure:"exclude_kernel" yaml:"exclude_kernel"`
	ExcludeUser        bool     `mapstructure:"exclude_user" yaml:"exclude_user"`

	// Symbol resolution
	Symbols SymbolsConfig `mapstructure:"symbols" yaml:"symbols"`

	// Output
	OutputFormat    string `mapstructure:"output_format" yaml:"output_format"`
	AggregateStacks bool   `mapstructure:"aggregate_stacks" yaml:"aggregate_stacks"`

	// Java eBPF profiling with perf-map-agent
	JavaEBPF JavaEBPFConfig `mapstructure:"java_ebpf" yaml:"java_ebpf"`

	// OTLP Log export
	LogExport LogExportRunnerConfig `mapstructure:"log_export" yaml:"log_export"`

	// Service metadata (injected by agent)
	ServiceName   string
	Namespace     string
	PodName       string
	ContainerName string
	NodeName      string
	ClusterName   string
}

// CPUConfig holds CPU profiling configuration
type CPUConfig struct {
	Enabled       bool `mapstructure:"enabled" yaml:"enabled"`
	SampleRate    int  `mapstructure:"sample_rate" yaml:"sample_rate"`
	MaxStackDepth int  `mapstructure:"max_stack_depth" yaml:"max_stack_depth"`
}

// OffCPUConfig holds off-CPU profiling configuration
type OffCPUConfig struct {
	Enabled        bool   `mapstructure:"enabled" yaml:"enabled"`
	MinBlockTimeNs uint64 `mapstructure:"min_block_time_ns" yaml:"min_block_time_ns"`
}

// MemoryConfig holds memory profiling configuration
type MemoryConfig struct {
	Enabled      bool   `mapstructure:"enabled" yaml:"enabled"`
	MinAllocSize uint64 `mapstructure:"min_alloc_size" yaml:"min_alloc_size"`
}

// MutexConfig holds mutex profiling configuration
type MutexConfig struct {
	Enabled               bool   `mapstructure:"enabled" yaml:"enabled"`
	ContentionThresholdNs uint64 `mapstructure:"contention_threshold_ns" yaml:"contention_threshold_ns"`
}

// WallConfig holds wall clock profiling configuration
type WallConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

// SymbolsConfig holds symbol resolution configuration
type SymbolsConfig struct {
	CacheSize         int  `mapstructure:"cache_size" yaml:"cache_size"`
	DebugInfoEnabled  bool `mapstructure:"debug_info_enabled" yaml:"debug_info_enabled"`
	DemanglingEnabled bool `mapstructure:"demangling_enabled" yaml:"demangling_enabled"`
	GoSymbols         bool `mapstructure:"go_symbols" yaml:"go_symbols"`
	KernelSymbols     bool `mapstructure:"kernel_symbols" yaml:"kernel_symbols"`
}

// JavaEBPFConfig holds Java eBPF profiling configuration
type JavaEBPFConfig struct {
	Enabled         bool          `mapstructure:"enabled" yaml:"enabled"`
	AgentJarPath    string        `mapstructure:"agent_jar_path" yaml:"agent_jar_path"`
	AgentLibPath    string        `mapstructure:"agent_lib_path" yaml:"agent_lib_path"`
	RefreshInterval time.Duration `mapstructure:"refresh_interval" yaml:"refresh_interval"`
	Timeout         time.Duration `mapstructure:"timeout" yaml:"timeout"`
	UnfoldAll       bool          `mapstructure:"unfold_all" yaml:"unfold_all"`
	UnfoldSimple    bool          `mapstructure:"unfold_simple" yaml:"unfold_simple"`
	DottedClass     bool          `mapstructure:"dotted_class" yaml:"dotted_class"`
}

// LogExportRunnerConfig holds OTLP log export configuration
type LogExportRunnerConfig struct {
	Enabled           bool              `mapstructure:"enabled" yaml:"enabled"`
	Endpoint          string            `mapstructure:"endpoint" yaml:"endpoint"`
	Headers           map[string]string `mapstructure:"headers" yaml:"headers"`
	Compression       string            `mapstructure:"compression" yaml:"compression"`
	Timeout           time.Duration     `mapstructure:"timeout" yaml:"timeout"`
	BatchSize         int               `mapstructure:"batch_size" yaml:"batch_size"`
	FlushInterval     time.Duration     `mapstructure:"flush_interval" yaml:"flush_interval"`
	IncludeStackTrace bool              `mapstructure:"include_stack_trace" yaml:"include_stack_trace"`
}

// DefaultRunnerConfig returns default profiling configuration
func DefaultRunnerConfig() RunnerConfig {
	return RunnerConfig{
		Enabled:            false,
		CollectionInterval: 10 * time.Second,
		UploadInterval:     60 * time.Second,
		CPU: CPUConfig{
			Enabled:       true,
			SampleRate:    99,
			MaxStackDepth: 127,
		},
		OffCPU: OffCPUConfig{
			Enabled:        true,
			MinBlockTimeNs: 1000000, // 1ms
		},
		Memory: MemoryConfig{
			Enabled:      true,
			MinAllocSize: 1024,
		},
		Mutex: MutexConfig{
			Enabled:               true,
			ContentionThresholdNs: 1000000, // 1ms
		},
		Wall: WallConfig{
			Enabled: false,
		},
		Symbols: SymbolsConfig{
			CacheSize:         10000,
			DebugInfoEnabled:  true,
			DemanglingEnabled: true,
			GoSymbols:         true,
			KernelSymbols:     true,
		},
		OutputFormat:    "pprof",
		AggregateStacks: true,
		JavaEBPF: JavaEBPFConfig{
			Enabled:         false,
			AgentJarPath:    "/opt/perf-map-agent/attach-main.jar",
			AgentLibPath:    "/opt/perf-map-agent/libperfmap.so",
			RefreshInterval: 60 * time.Second,
			Timeout:         30 * time.Second,
			UnfoldAll:       true,
			UnfoldSimple:    false,
			DottedClass:     true,
		},
		LogExport: LogExportRunnerConfig{
			Enabled:           false,
			Endpoint:          "http://localhost:4318/v1/logs",
			Compression:       "gzip",
			Timeout:           30 * time.Second,
			BatchSize:         100,
			FlushInterval:     10 * time.Second,
			IncludeStackTrace: true,
		},
	}
}
