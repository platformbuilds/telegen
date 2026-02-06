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

	// Thread info
	ThreadName string `json:"threadName,omitempty"`
	ThreadID   int64  `json:"threadId,omitempty"`

	// Stack trace info
	TopFunction string       `json:"topFunction,omitempty"`
	TopClass    string       `json:"topClass,omitempty"`
	TopMethod   string       `json:"topMethod,omitempty"`
	StackPath   string       `json:"stackPath,omitempty"`
	StackDepth  int          `json:"stackDepth,omitempty"`
	StackTrace  string       `json:"stackTrace,omitempty"`  // JSON-encoded stack frames (deprecated, for JFR backward compat)
	StackFrames []StackFrame `json:"stackFrames,omitempty"` // Proper JSON array (preferred for eBPF)

	// Timing/weight
	SampleWeight    int64   `json:"sampleWeight"`
	DurationNs      int64   `json:"durationNs,omitempty"`
	SelfTimeMs      int64   `json:"selfTimeMs,omitempty"`
	SelfTimePercent float64 `json:"selfTimePercent,omitempty"`
	TotalSamples    int64   `json:"totalSamples,omitempty"`

	// JFR-specific fields (empty for eBPF)
	State          string `json:"state,omitempty"`
	AllocationSize int64  `json:"allocationSize,omitempty"`
	TLABSize       int64  `json:"tlabSize,omitempty"`
	ObjectClass    string `json:"objectClass,omitempty"`
	MonitorClass   string `json:"monitorClass,omitempty"`
	GCName         string `json:"gcName,omitempty"`
	GCCause        string `json:"gcCause,omitempty"`

	// eBPF-specific fields (empty for JFR)
	PID          uint32 `json:"pid,omitempty"`
	TID          uint32 `json:"tid,omitempty"`
	Comm         string `json:"comm,omitempty"`         // Process name
	ContainerID  string `json:"containerId,omitempty"`  // Container ID if available
	BlockReason  string `json:"blockReason,omitempty"`  // For off-cpu profiles
	KernelFrames int    `json:"kernelFrames,omitempty"` // Number of kernel frames
	UserFrames   int    `json:"userFrames,omitempty"`   // Number of user frames
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
