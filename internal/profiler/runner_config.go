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

	// Target filtering - Process-based
	TargetPID          uint32   `mapstructure:"target_pid" yaml:"target_pid"`                     // Single PID to profile
	TargetPIDs         []uint32 `mapstructure:"target_pids" yaml:"target_pids"`                   // Multiple PIDs to profile
	TargetContainerIDs []string `mapstructure:"target_container_ids" yaml:"target_container_ids"` // Container IDs to profile
	TargetProcessNames []string `mapstructure:"target_process_names" yaml:"target_process_names"` // Process names to profile (e.g., "java", "python", "node")
	TargetExecutables  []string `mapstructure:"target_executables" yaml:"target_executables"`     // Full executable paths to profile
	ExcludeKernel      bool     `mapstructure:"exclude_kernel" yaml:"exclude_kernel"`             // Exclude kernel stacks
	ExcludeUser        bool     `mapstructure:"exclude_user" yaml:"exclude_user"`                 // Exclude user stacks

	// Target filtering - Kubernetes-based
	TargetNamespaces   []string          `mapstructure:"target_namespaces" yaml:"target_namespaces"`     // K8s namespaces to profile
	TargetDeployments  []string          `mapstructure:"target_deployments" yaml:"target_deployments"`   // K8s deployment names to profile
	TargetDaemonSets   []string          `mapstructure:"target_daemonsets" yaml:"target_daemonsets"`     // K8s daemonset names to profile
	TargetStatefulSets []string          `mapstructure:"target_statefulsets" yaml:"target_statefulsets"` // K8s statefulset names to profile
	TargetLabels       map[string]string `mapstructure:"target_labels" yaml:"target_labels"`             // K8s labels to match (e.g., app=myapp)
	ExcludeNamespaces  []string          `mapstructure:"exclude_namespaces" yaml:"exclude_namespaces"`   // K8s namespaces to exclude (e.g., kube-system)

	// Symbol resolution
	Symbols SymbolsConfig `mapstructure:"symbols" yaml:"symbols"`

	// Output
	OutputFormat    string `mapstructure:"output_format" yaml:"output_format"`
	AggregateStacks bool   `mapstructure:"aggregate_stacks" yaml:"aggregate_stacks"`

	// Java eBPF profiling with perf-map-agent
	JavaEBPF JavaEBPFConfig `mapstructure:"java_ebpf" yaml:"java_ebpf"`

	// OTLP Log export
	LogExport LogExportRunnerConfig `mapstructure:"log_export" yaml:"log_export"`

	// OTLP Metrics export (generates metrics from profiling data)
	MetricsExport MetricsExportRunnerConfig `mapstructure:"metrics_export" yaml:"metrics_export"`

	// Service metadata (injected by agent)
	ServiceName   string
	Namespace     string
	PodName       string
	ContainerName string
	NodeName      string
	ClusterName   string
	Deployment    string // K8s deployment name
	HostName      string // Hostname for non-k8s environments
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
	Enabled    bool `mapstructure:"enabled" yaml:"enabled"`
	SampleRate int  `mapstructure:"sample_rate" yaml:"sample_rate"`
}

// SymbolsConfig holds symbol resolution configuration
type SymbolsConfig struct {
	CacheSize         int  `mapstructure:"cache_size" yaml:"cache_size"`
	DebugInfoEnabled  bool `mapstructure:"debug_info_enabled" yaml:"debug_info_enabled"`
	DemanglingEnabled bool `mapstructure:"demangling_enabled" yaml:"demangling_enabled"`
	GoSymbols         bool `mapstructure:"go_symbols" yaml:"go_symbols"`
	KernelSymbols     bool `mapstructure:"kernel_symbols" yaml:"kernel_symbols"`
	// PerfMapPaths: list of glob paths to search for perf-<pid>.map files.
	// Supports `<pid>` substitution and simple globs like `*` and `?`.
	PerfMapPaths []string `mapstructure:"perf_map_paths" yaml:"perf_map_paths"`
	// PerfMapRecursive: if true, allow recursive directory walks for patterns
	// containing `**` (best-effort implementation).
	PerfMapRecursive bool `mapstructure:"perf_map_recursive" yaml:"perf_map_recursive"`
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

// MetricsExportRunnerConfig holds OTLP metrics export configuration for profiling data.
// This generates metrics like profiler.cpu.samples, profiler.cpu.duration_seconds, etc.
type MetricsExportRunnerConfig struct {
	// Enabled enables metrics export from profiling data
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Endpoint is the OTLP metrics endpoint (e.g., "http://localhost:4318/v1/metrics")
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`

	// Headers are custom HTTP headers to send with requests
	Headers map[string]string `mapstructure:"headers" yaml:"headers"`

	// Compression algorithm: "gzip" or "" (none)
	Compression string `mapstructure:"compression" yaml:"compression"`

	// Timeout for export requests
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`

	// HistogramBuckets for duration distributions (in seconds)
	// Default: latency-optimized buckets from 1ms to 60s
	HistogramBuckets []float64 `mapstructure:"histogram_buckets" yaml:"histogram_buckets"`

	// MemoryHistogramBuckets for allocation size distributions (in bytes)
	// Default: power-of-2 buckets from 64B to 64MB
	MemoryHistogramBuckets []float64 `mapstructure:"memory_histogram_buckets" yaml:"memory_histogram_buckets"`

	// IncludeProcessAttributes includes process.pid, process.executable.name
	IncludeProcessAttributes bool `mapstructure:"include_process_attributes" yaml:"include_process_attributes"`

	// IncludeStackAttributes includes code.function, code.class from top-of-stack
	IncludeStackAttributes bool `mapstructure:"include_stack_attributes" yaml:"include_stack_attributes"`
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
			PerfMapPaths:      nil,
			PerfMapRecursive:  false,
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
		MetricsExport: MetricsExportRunnerConfig{
			Enabled:     false,
			Endpoint:    "http://localhost:4318/v1/metrics",
			Compression: "gzip",
			Timeout:     30 * time.Second,
			// Default histogram buckets for latency (seconds): 1ms to 60s
			HistogramBuckets: []float64{
				0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
			},
			// Default histogram buckets for memory (bytes): 64B to 64MB
			MemoryHistogramBuckets: []float64{
				64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864,
			},
			IncludeProcessAttributes: true,
			IncludeStackAttributes:   true,
		},
	}
}
