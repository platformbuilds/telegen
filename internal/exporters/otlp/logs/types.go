// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package logs provides OTLP log export functionality for profile events.
// This package is used by both JFR and eBPF profilers to export profile data
// as structured OTLP logs.
package logs

import "time"

// ProfileEvent represents a single profiling event from any source (JFR, eBPF).
// This is the common format used for OTLP log export.
type ProfileEvent struct {
	Timestamp        string `json:"timestamp"`
	EventType        string `json:"eventType"`
	ServiceName      string `json:"serviceName"`
	ServiceVersion   string `json:"serviceVersion,omitempty"`
	ProfileType      string `json:"profileType"`
	ProfileSource    string `json:"profileSource,omitempty"` // "jfr", "ebpf"
	K8sPodName       string `json:"k8s_pod_name,omitempty"`
	K8sNamespace     string `json:"k8s_namespace,omitempty"`
	K8sContainerName string `json:"k8s_container_name,omitempty"`
	K8sNodeName      string `json:"k8s_node_name,omitempty"`
	K8sDeployment    string `json:"k8s_deployment,omitempty"`
	HostName         string `json:"hostname,omitempty"` // For non-k8s environments
	AppName          string `json:"appName,omitempty"`  // Application name (serviceName or comm)

	// Thread info
	ThreadName string `json:"threadName,omitempty"`
	ThreadID   int64  `json:"threadId,omitempty"`

	// Stack trace info
	TopFunction      string       `json:"topFunction,omitempty"`
	TopClass         string       `json:"topClass,omitempty"`
	TopMethod        string       `json:"topMethod,omitempty"`
	StackPath        string       `json:"stackPath,omitempty"`
	StackDepth       int          `json:"stackDepth,omitempty"`
	StackTrace       string       `json:"stackTrace,omitempty"`       // JSON-encoded stack frames (deprecated, for JFR backward compat)
	StackFrames      []StackFrame `json:"stackFrames,omitempty"`      // Proper JSON array (preferred for eBPF)
	ResolutionStatus string       `json:"resolutionStatus,omitempty"` // "resolved" or "unresolved"

	// Timing/weight
	SampleWeight    int64   `json:"sampleWeight"`
	DurationNs      int64   `json:"durationNs,omitempty"` // Meaning varies by profile type (see below)
	SelfTimeMs      int64   `json:"selfTimeMs,omitempty"`
	SelfTimePercent float64 `json:"selfTimePercent,omitempty"`
	TotalSamples    int64   `json:"totalSamples,omitempty"`

	// Duration semantics by profile type:
	// - cpu: Estimated on-CPU time (sample_count × sample_period)
	// - offcpu: Actual blocked time in nanoseconds
	// - mutex: Lock wait time in nanoseconds
	// - block: Go blocking time in nanoseconds
	// - wall: Total wall-clock time (on-CPU + off-CPU)
	// - memory/heap/alloc_*: Not applicable (use AllocationSize)

	// JFR-specific fields (empty for eBPF)
	State          string `json:"state,omitempty"`
	AllocationSize int64  `json:"allocationSize,omitempty"`
	TLABSize       int64  `json:"tlabSize,omitempty"`
	ObjectClass    string `json:"objectClass,omitempty"`
	MonitorClass   string `json:"monitorClass,omitempty"`
	GCName         string `json:"gcName,omitempty"`
	GCCause        string `json:"gcCause,omitempty"`

	// eBPF-specific fields (empty for JFR)
	PID            uint32 `json:"pid,omitempty"`
	TID            uint32 `json:"tid,omitempty"`
	Comm           string `json:"comm,omitempty"`           // Process name
	ContainerID    string `json:"containerId,omitempty"`    // Container ID if available
	BlockReason    string `json:"blockReason,omitempty"`    // For off-cpu profiles
	KernelFrames   int    `json:"kernelFrames,omitempty"`   // Number of kernel frames
	UserFrames     int    `json:"userFrames,omitempty"`     // Number of user frames
	LockAddress    string `json:"lockAddress,omitempty"`    // For mutex profiles (hex address)
	LockClass      string `json:"lockClass,omitempty"`      // Lock type/class name from DWARF
	AllocationType string `json:"allocationType,omitempty"` // Allocation type: "malloc", "calloc", "realloc", "mmap", "new"

	// Application Artifact (language-agnostic)
	AppBinary  string `json:"appBinary,omitempty"`  // Application binary/jar/script (e.g., "payment-service.jar", "api-gateway", "app.py")
	AppVersion string `json:"appVersion,omitempty"` // App version extracted from artifact (e.g., "2.4.1")

	// Language & Runtime (OpenTelemetry process.runtime.* conventions)
	Language              string `json:"language,omitempty"`                // Language name: "java", "go", "python", "node", "rust", "ruby"
	ProcessRuntimeName    string `json:"process.runtime.name,omitempty"`    // Runtime name: "OpenJ9", "HotSpot", "Go", "CPython", "Node.js", "GraalVM Native Image"
	ProcessRuntimeVersion string `json:"process.runtime.version,omitempty"` // Runtime version: "1.8.0_352", "go1.21.5", "3.11.2", "v18.16.0"
	ProcessRuntimeVendor  string `json:"process.runtime.vendor,omitempty"`  // Runtime vendor: "IBM", "Oracle", "Google", "Python Software Foundation"

	// Process Information (OpenTelemetry process.* conventions)
	ProcessExecutableName string `json:"process.executable.name,omitempty"` // Executable name: "java", "api-gateway", "python3", "node"
	ProcessExecutablePath string `json:"process.executable.path,omitempty"` // Full executable path: "/usr/bin/java", "/app/api-gateway"
	ProcessCommandLine    string `json:"process.command_line,omitempty"`    // Full command line for debugging
}

// StackFrame represents a single frame in the stack trace
type StackFrame struct {
	// Common fields
	Function string `json:"function"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Depth    int    `json:"depth,omitempty"`

	// Java/JFR-specific
	Class       string `json:"class,omitempty"`
	Method      string `json:"method,omitempty"`
	BCI         int    `json:"bci,omitempty"` // Bytecode index
	SelfTimeMs  int64  `json:"selfTimeMs,omitempty"`
	TotalTimeMs int64  `json:"totalTimeMs,omitempty"`

	// eBPF/native-specific
	Address    uint64 `json:"address,omitempty"`
	Module     string `json:"module,omitempty"` // Binary/library name
	IsKernel   bool   `json:"isKernel,omitempty"`
	IsInline   bool   `json:"isInline,omitempty"`
	Demangled  string `json:"demangled,omitempty"` // Demangled C++/Rust symbol
	SourceLine string `json:"sourceLine,omitempty"`
}

// ExporterConfig holds configuration for the OTLP log exporter
type ExporterConfig struct {
	// Endpoint is the OTLP logs endpoint (e.g., http://localhost:4318/v1/logs)
	Endpoint string

	// Headers to include in requests
	Headers map[string]string

	// Compression type (gzip, none)
	Compression string

	// Timeout for requests
	Timeout time.Duration

	// BatchSize is the number of log records to batch before sending
	BatchSize int

	// FlushInterval is how often to flush logs even if batch is not full
	FlushInterval time.Duration

	// IncludeStackTrace includes full stack trace in log body
	IncludeStackTrace bool

	// IncludeRawJSON includes the full JSON representation in log body
	IncludeRawJSON bool

	// Service metadata
	ServiceName   string
	Namespace     string
	PodName       string
	ContainerName string
	NodeName      string
	ClusterName   string

	// Telegen metadata (instrumentation scope and SDK attributes)
	ScopeName           string // e.g., "telegen.jfr", "telegen.profiler"
	ScopeVersion        string // e.g., "1.0.0"
	TelemetrySDKName    string // defaults to "telegen"
	TelemetrySDKVersion string // agent version
	TelemetrySDKLang    string // e.g., "java", "native", "go"
}

// DefaultExporterConfig returns default configuration
func DefaultExporterConfig() ExporterConfig {
	return ExporterConfig{
		Endpoint:          "http://localhost:4318/v1/logs",
		Compression:       "gzip",
		Timeout:           30 * time.Second,
		BatchSize:         100,
		FlushInterval:     10 * time.Second,
		IncludeStackTrace: true,
		IncludeRawJSON:    true,
		ScopeName:         "telegen.profiler",
		TelemetrySDKName:  "telegen",
		TelemetrySDKLang:  "native",
	}
}
