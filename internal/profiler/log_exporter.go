// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package profiler provides eBPF-based profiling with multiple export formats.
package profiler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/jfr/converter"
	"github.com/platformbuilds/telegen/internal/profiler/perfmap"
)

// LogExporter converts eBPF profile data to ProfileEvent format and exports as OTLP logs.
// This provides a unified export path for both JFR-based (Java) and eBPF-based (native/Java) profiling.
type LogExporter struct {
	config         LogExporterConfig
	log            *slog.Logger
	logExporter    *converter.OTLPLogExporter
	perfMapReader  *perfmap.PerfMapReader
	symbolResolver *SymbolResolver

	mu      sync.Mutex
	pending []*converter.ProfileEvent
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

	// Headers for OTLP requests
	Headers map[string]string

	// ProfileSource identifies the source (ebpf, jfr)
	ProfileSource string
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

	// Create the underlying OTLP log exporter
	otlpCfg := converter.OTLPLogExporterConfig{
		Endpoint:          cfg.Endpoint,
		Headers:           cfg.Headers,
		BatchSize:         cfg.BatchSize,
		FlushInterval:     cfg.FlushInterval,
		IncludeStackTrace: cfg.IncludeStackTrace,
		IncludeRawJSON:    true,
		ServiceName:       cfg.ServiceName,
		Namespace:         cfg.Namespace,
		PodName:           cfg.PodName,
		ContainerName:     cfg.ContainerName,
		NodeName:          cfg.NodeName,
		ClusterName:       cfg.ClusterName,
	}

	otlpExporter, err := converter.NewOTLPLogExporter(otlpCfg, log)
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
		pending:        make([]*converter.ProfileEvent, 0, cfg.BatchSize),
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
func (e *LogExporter) convertToEvents(profile *Profile) []*converter.ProfileEvent {
	events := make([]*converter.ProfileEvent, 0, len(profile.Samples))
	timestamp := profile.Timestamp

	for _, sample := range profile.Samples {
		event := e.sampleToEvent(sample, profile.Type, timestamp)
		events = append(events, event)
	}

	return events
}

// sampleToEvent converts a single eBPF stack sample to a ProfileEvent
func (e *LogExporter) sampleToEvent(sample StackSample, profileType ProfileType, timestamp time.Time) *converter.ProfileEvent {
	event := &converter.ProfileEvent{
		Timestamp:        timestamp.Format(time.RFC3339Nano),
		EventType:        e.profileTypeToEventType(profileType),
		ServiceName:      e.config.ServiceName,
		ProfileType:      profileType.String(),
		K8sPodName:       e.config.PodName,
		K8sNamespace:     e.config.Namespace,
		K8sContainerName: e.config.ContainerName,
		K8sNodeName:      e.config.NodeName,
		SampleWeight:     sample.Value,
		TotalSamples:     sample.Count,
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

		// Build stack path (simplified call path)
		event.StackPath = e.buildStackPath(sample.Frames)

		// Serialize full stack trace
		if e.config.IncludeStackTrace {
			stackFrames := e.convertFrames(sample.Frames)
			if stackJSON, err := json.Marshal(stackFrames); err == nil {
				event.StackTrace = string(stackJSON)
			}
		}
	}

	// Set profile-type specific fields
	switch profileType {
	case ProfileTypeOffCPU:
		event.DurationNs = sample.Value // Off-CPU value is block time in ns
		event.State = sample.BlockReason.String()
	case ProfileTypeMemory:
		event.AllocationSize = sample.Value
	}

	return event
}

// convertFrames converts ResolvedFrame slice to converter.StackFrame slice
func (e *LogExporter) convertFrames(frames []ResolvedFrame) []converter.StackFrame {
	result := make([]converter.StackFrame, len(frames))

	for i, f := range frames {
		result[i] = converter.StackFrame{
			Class:  f.Class,
			Method: f.ShortName,
			Line:   f.Line,
			File:   f.File,
			Depth:  i,
		}

		// Use Function as fallback
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

// profileTypeToEventType maps ProfileType to JFR-style event type names
func (e *LogExporter) profileTypeToEventType(pt ProfileType) string {
	switch pt {
	case ProfileTypeCPU:
		return "jdk.ExecutionSample" // Compatible with JFR event names
	case ProfileTypeOffCPU:
		return "jdk.ThreadPark"
	case ProfileTypeMemory:
		return "jdk.ObjectAllocationSample"
	case ProfileTypeMutex:
		return "jdk.JavaMonitorEnter"
	case ProfileTypeBlock:
		return "jdk.ThreadSleep"
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
