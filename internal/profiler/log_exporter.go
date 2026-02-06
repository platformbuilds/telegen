// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package profiler provides eBPF-based profiling with multiple export formats.
package profiler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/exporters/otlp/logs"
	"github.com/platformbuilds/telegen/internal/profiler/perfmap"
	"github.com/platformbuilds/telegen/internal/version"
)

// LogExporter converts eBPF profile data to ProfileEvent format and exports as OTLP logs.
// This uses the shared OTLP logs exporter for consistent telegen metadata.
type LogExporter struct {
	config         LogExporterConfig
	log            *slog.Logger
	logExporter    *logs.Exporter
	perfMapReader  *perfmap.PerfMapReader
	symbolResolver *SymbolResolver

	// Track unresolved PIDs to avoid log spam
	unresolvedPIDsLogged sync.Map // pid -> bool
}

// LogExporterConfig holds configuration for the profile log exporter
type LogExporterConfig struct {
	// Endpoint is the OTLP logs endpoint
	Endpoint string

	// BatchSize is the number of events to batch before sending
	BatchSize int

	// FlushInterval is how often to flush events
	FlushInterval time.Duration

	// IncludeStackTrace includes full stack trace in log body
	IncludeStackTrace bool

	// Service metadata
	ServiceName   string
	Namespace     string
	PodName       string
	ContainerName string
	NodeName      string
	ClusterName   string
	Deployment    string // K8s deployment name
	HostName      string // Hostname for non-k8s environments

	// Headers for OTLP requests
	Headers map[string]string

	// ProfileSource identifies the source (ebpf, jfr)
	ProfileSource string

	// Telegen metadata (optional, defaults provided)
	ScopeName        string // defaults to "telegen.profiler"
	ScopeVersion     string // defaults to agent version
	TelemetrySDKLang string // defaults to "native", can be "java" for Java profiles

	// Profiler settings for duration calculation
	CPUSampleRate int // CPU sampling rate in Hz (for duration estimation)
}

// DefaultLogExporterConfig returns default configuration
func DefaultLogExporterConfig() LogExporterConfig {
	return LogExporterConfig{
		Endpoint:          "http://localhost:4318/v1/logs",
		BatchSize:         100,
		FlushInterval:     10 * time.Second,
		IncludeStackTrace: true,
		ProfileSource:     "ebpf",
	}
}

// NewLogExporter creates a new eBPF profile log exporter
func NewLogExporter(cfg LogExporterConfig, log *slog.Logger) (*LogExporter, error) {
	if log == nil {
		log = slog.Default()
	}

	// Create the underlying OTLP log exporter with telegen metadata
	scopeName := cfg.ScopeName
	if scopeName == "" {
		scopeName = "telegen.profiler"
	}
	scopeVersion := cfg.ScopeVersion
	if scopeVersion == "" {
		scopeVersion = version.Version()
	}
	sdkLang := cfg.TelemetrySDKLang
	if sdkLang == "" {
		sdkLang = "native" // eBPF profiles are language-agnostic
	}

	otlpCfg := logs.ExporterConfig{
		Endpoint:            cfg.Endpoint,
		Headers:             cfg.Headers,
		BatchSize:           cfg.BatchSize,
		FlushInterval:       cfg.FlushInterval,
		IncludeStackTrace:   cfg.IncludeStackTrace,
		IncludeRawJSON:      true,
		ServiceName:         cfg.ServiceName,
		Namespace:           cfg.Namespace,
		PodName:             cfg.PodName,
		ContainerName:       cfg.ContainerName,
		NodeName:            cfg.NodeName,
		ClusterName:         cfg.ClusterName,
		ScopeName:           scopeName,
		ScopeVersion:        scopeVersion,
		TelemetrySDKName:    "telegen",
		TelemetrySDKVersion: version.Version(),
		TelemetrySDKLang:    sdkLang,
	}

	otlpExporter, err := logs.NewExporter(otlpCfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	// Create symbol resolver
	symbolResolver, err := NewSymbolResolver(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create symbol resolver: %w", err)
	}

	return &LogExporter{
		config:         cfg,
		log:            log.With("component", "ebpf_log_exporter"),
		logExporter:    otlpExporter,
		perfMapReader:  perfmap.NewPerfMapReader(),
		symbolResolver: symbolResolver,
	}, nil
}

// Export exports a profile as OTLP logs
func (e *LogExporter) Export(ctx context.Context, profile *Profile) error {
	if profile == nil || len(profile.Samples) == 0 {
		return nil
	}

	// Convert eBPF profile samples to ProfileEvent format
	events := e.convertToEvents(profile)

	// Export using the underlying OTLP exporter
	return e.logExporter.ExportBatch(ctx, events)
}

// ExportSample exports a single sample as OTLP log
func (e *LogExporter) ExportSample(ctx context.Context, sample StackSample, profileType ProfileType) error {
	event := e.sampleToEvent(sample, profileType, time.Now())
	return e.logExporter.Export(ctx, event)
}

// Flush flushes any pending events
func (e *LogExporter) Flush(ctx context.Context) error {
	return e.logExporter.Flush(ctx)
}

// Close closes the exporter
func (e *LogExporter) Close() error {
	return e.logExporter.Close()
}

// convertToEvents converts an eBPF profile to ProfileEvent slice
func (e *LogExporter) convertToEvents(profile *Profile) []*logs.ProfileEvent {
	events := make([]*logs.ProfileEvent, 0, len(profile.Samples))
	timestamp := profile.Timestamp

	for _, sample := range profile.Samples {
		event := e.sampleToEvent(sample, profile.Type, timestamp)
		events = append(events, event)
	}

	return events
}

// sampleToEvent converts a single eBPF stack sample to a ProfileEvent
func (e *LogExporter) sampleToEvent(sample StackSample, profileType ProfileType, timestamp time.Time) *logs.ProfileEvent {
	// Determine app name: use service name if available, otherwise use process comm
	appName := e.config.ServiceName
	if appName == "" {
		appName = sample.Comm
	}

	event := &logs.ProfileEvent{
		Timestamp:        timestamp.Format(time.RFC3339Nano),
		EventType:        e.profileTypeToEventType(profileType),
		ServiceName:      e.config.ServiceName,
		ProfileType:      profileType.String(),
		ProfileSource:    "ebpf",
		K8sPodName:       e.config.PodName,
		K8sNamespace:     e.config.Namespace,
		K8sContainerName: e.config.ContainerName,
		K8sNodeName:      e.config.NodeName,
		K8sDeployment:    e.config.Deployment,
		HostName:         e.config.HostName,
		AppName:          appName,
		SampleWeight:     sample.Value,
		TotalSamples:     sample.Count,
		PID:              sample.PID,
		TID:              sample.TGID, // Use TGID as TID
		Comm:             sample.Comm,
	}

	// Set thread info from comm
	event.ThreadName = sample.Comm
	event.ThreadID = int64(sample.PID)

	// Process stack frames
	if len(sample.Frames) > 0 {
		event.StackDepth = len(sample.Frames)

		// Get top frame
		topFrame := sample.Frames[0]
		event.TopFunction = topFrame.Function
		event.TopClass = topFrame.Class
		event.TopMethod = topFrame.ShortName
		if event.TopMethod == "" {
			event.TopMethod = topFrame.Function
		}

		// Set resolution status based on top frame
		if topFrame.Resolved {
			event.ResolutionStatus = "resolved"
		} else {
			event.ResolutionStatus = "unresolved"
		}

		// Build stack path (simplified call path)
		event.StackPath = e.buildStackPath(sample.Frames)

		// Set full stack trace as proper JSON array (eBPF-specific)
		if e.config.IncludeStackTrace {
			event.StackFrames = e.convertFrames(sample.Frames)
		}
	} else {
		// No frames means unresolved
		event.ResolutionStatus = "unresolved"
	}

	// Set profile-type specific fields and calculate duration
	switch profileType {
	case ProfileTypeCPU:
		// CPU profiling: calculate estimated on-CPU time from sample count
		// Duration = sample_count * (1/sample_rate) in nanoseconds
		if e.config.CPUSampleRate > 0 {
			// Each sample represents ~(1/sample_rate) seconds
			samplePeriodNs := int64(1000000000 / e.config.CPUSampleRate)
			event.DurationNs = sample.Value * samplePeriodNs
		} else {
			// Default to 99 Hz if not configured
			event.DurationNs = sample.Value * 10101010 // ~10.1ms per sample at 99Hz
		}
	case ProfileTypeOffCPU:
		event.DurationNs = sample.Value // Off-CPU value is block time in ns
		event.BlockReason = sample.BlockReason.String()
	case ProfileTypeMemory, ProfileTypeHeap, ProfileTypeAllocCount, ProfileTypeAllocBytes, ProfileTypeAllocs:
		// Memory profiling: Value is bytes allocated, not time
		event.AllocationSize = sample.Value
		// No duration for memory allocations
	case ProfileTypeMutex:
		// Mutex contention: Value is wait time in ns
		event.DurationNs = sample.Value
	case ProfileTypeBlock:
		// Block profiling: Similar to off-CPU, value is blocked time in ns
		event.DurationNs = sample.Value
		event.BlockReason = "block"
	case ProfileTypeWall:
		// Wall clock profiling: Value would be wall time in ns
		event.DurationNs = sample.Value
	default:
		// Unknown profile type: set value as duration conservatively
		e.log.Debug("unknown profile type, treating value as duration",
			"profile_type", profileType, "value", sample.Value)
		event.DurationNs = sample.Value
	}

	// Log warning if symbols are unresolved (stripped binaries) - once per PID
	if event.ResolutionStatus == "unresolved" && len(sample.Frames) > 0 {
		pidKey := sample.PID
		if _, alreadyLogged := e.unresolvedPIDsLogged.LoadOrStore(pidKey, true); !alreadyLogged {
			e.log.Warn("profiling stripped binary without debug symbols",
				"pid", sample.PID, "comm", sample.Comm,
				"hint", "rebuild with debug symbols or see docs/profiling-stripped-binaries.md")
		}
	}

	return event
}

// convertFrames converts ResolvedFrame slice to logs.StackFrame slice
func (e *LogExporter) convertFrames(frames []ResolvedFrame) []logs.StackFrame {
	result := make([]logs.StackFrame, len(frames))

	for i, f := range frames {
		result[i] = logs.StackFrame{
			Function: f.Function,
			Class:    f.Class,
			Method:   f.ShortName,
			Line:     f.Line,
			File:     f.File,
			Depth:    i,
			Module:   f.Module,
			Address:  f.Address,
			IsInline: f.Inlined,
		}

		// Use Function as fallback for Method
		if result[i].Method == "" {
			result[i].Method = f.Function
		}

		// For non-Java frames, use Module as class
		if result[i].Class == "" && f.Module != "" {
			result[i].Class = f.Module
		}
	}

	return result
}

// buildStackPath creates a simplified call path string
func (e *LogExporter) buildStackPath(frames []ResolvedFrame) string {
	if len(frames) == 0 {
		return ""
	}

	// Take top N frames for the path
	maxFrames := 5
	if len(frames) < maxFrames {
		maxFrames = len(frames)
	}

	parts := make([]string, maxFrames)
	for i := 0; i < maxFrames; i++ {
		f := frames[i]
		name := f.ShortName
		if name == "" {
			name = f.Function
		}
		parts[i] = name
	}

	return strings.Join(parts, " <- ")
}

// profileTypeToEventType maps ProfileType to eBPF-style event type names
func (e *LogExporter) profileTypeToEventType(pt ProfileType) string {
	switch pt {
	case ProfileTypeCPU:
		return "ebpf.CPUSample"
	case ProfileTypeOffCPU:
		return "ebpf.OffCPUSample"
	case ProfileTypeMemory:
		return "ebpf.AllocationSample"
	case ProfileTypeHeap:
		return "ebpf.HeapSample"
	case ProfileTypeAllocCount:
		return "ebpf.AllocCountSample"
	case ProfileTypeAllocBytes:
		return "ebpf.AllocBytesSample"
	case ProfileTypeAllocs:
		return "ebpf.AllocsSample"
	case ProfileTypeMutex:
		return "ebpf.MutexSample"
	case ProfileTypeBlock:
		return "ebpf.BlockSample"
	case ProfileTypeWall:
		return "ebpf.WallSample"
	case ProfileTypeGorout:
		return "ebpf.GoroutineSample"
	default:
		return "ebpf.Sample"
	}
}

// ResolveJavaSymbols attempts to resolve Java symbols using perf-map
func (e *LogExporter) ResolveJavaSymbols(pid uint32, frames []ResolvedFrame) []ResolvedFrame {
	pm, err := e.perfMapReader.Load(pid)
	if err != nil {
		return frames // Return original frames if perf-map not available
	}

	resolved := make([]ResolvedFrame, len(frames))
	copy(resolved, frames)

	for i := range resolved {
		if resolved[i].Function == "" || resolved[i].Function == "[unknown]" {
			// Try to resolve using perf-map
			sym := pm.Resolve(resolved[i].Address)
			if sym != nil {
				resolved[i].Function = sym.Name
				resolved[i].Class = sym.Class
				resolved[i].ShortName = sym.Method
				if resolved[i].ShortName == "" {
					resolved[i].ShortName = sym.Name
				}
			}
		}
	}

	return resolved
}
