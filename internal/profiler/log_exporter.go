// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package profiler provides eBPF-based profiling with multiple export formats.
package profiler

import (
	"bufio"
	"bytes"
	"context"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/exporters/otlp/logs"
	"github.com/platformbuilds/telegen/internal/helpers/container"
	"github.com/platformbuilds/telegen/internal/profiler/perfmap"
	"github.com/platformbuilds/telegen/internal/version"
)

// Allocation type constants (from bpf/profiler/alloc_profiler.c)
const (
	allocMalloc        uint8 = 1
	allocCalloc        uint8 = 2
	allocRealloc       uint8 = 3
	allocMmap          uint8 = 4
	allocNew           uint8 = 5
	allocPosixMemalign uint8 = 6
	freeFree           uint8 = 1
	freeMunmap         uint8 = 2
	freeDelete         uint8 = 3
)

// defaultCPUSampleRateHz is the standard sample rate for CPU profiling when not configured.
// 99 Hz is used to avoid lockstep sampling with common timer frequencies.
const defaultCPUSampleRateHz = 99

// samplePeriodFromHz calculates the nanoseconds per sample for a given sample rate.
// Uses float64 arithmetic to avoid integer division truncation.
func samplePeriodFromHz(hz int) int64 {
	if hz <= 0 {
		hz = defaultCPUSampleRateHz
	}
	return int64(float64(1_000_000_000) / float64(hz))
}

// LogExporter converts eBPF profile data to ProfileEvent format and exports as OTLP logs.
// This uses the shared OTLP logs exporter for consistent telegen metadata.
type LogExporter struct {
	config           LogExporterConfig
	log              *slog.Logger
	logExporter      *logs.Exporter
	perfMapReader    *perfmap.PerfMapReader
	symbolResolver   *SymbolResolver
	metadataResolver *ProcessMetadataResolver // Shared resolver for consistent app.name

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
func NewLogExporter(cfg LogExporterConfig, log *slog.Logger, resolver *SymbolResolver, metadataResolver *ProcessMetadataResolver) (*LogExporter, error) {
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

	// Use provided shared resolver or create new one
	if resolver == nil {
		var err error
		resolver, err = NewSymbolResolver(log)
		if err != nil {
			log.Warn("failed to create symbol resolver for log exporter, symbols may be incomplete", "error", err)
			resolver = nil
		}
	}

	// Use provided shared metadata resolver or create new one
	if metadataResolver == nil {
		metadataResolver = NewProcessMetadataResolver(log)
	}

	return &LogExporter{
		config:           cfg,
		log:              log.With("component", "ebpf_log_exporter"),
		logExporter:      otlpExporter,
		perfMapReader:    perfmap.NewPerfMapReader(),
		symbolResolver:   resolver,
		metadataResolver: metadataResolver,
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
	// Use shared resolver for consistent app.name across metrics and logs
	// Pass empty string for serviceName to auto-detect from profiled process (jar name, binary, etc.)
	// e.config.ServiceName is the TELEGEN AGENT's identity, not the profiled app's name
	appName := e.metadataResolver.ResolveAppName(sample.PID, sample.Comm, "")

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

	// Extract process runtime metadata using shared resolver (OTel-compliant)
	procMeta := e.metadataResolver.GetMetadata(sample.PID)
	if procMeta != nil {
		// Note: appName already resolved via ResolveAppName() - no override needed

		// Populate OTel-compliant fields
		event.AppBinary = procMeta.AppBinary
		event.AppVersion = procMeta.AppVersion
		if procMeta.AppVersion != "" {
			event.ServiceVersion = procMeta.AppVersion
		}
		event.Language = procMeta.Language
		event.ProcessRuntimeName = procMeta.RuntimeName
		event.ProcessRuntimeVersion = procMeta.RuntimeVersion
		event.ProcessRuntimeVendor = procMeta.RuntimeVendor
		event.ProcessExecutableName = procMeta.ExecutableName
		event.ProcessExecutablePath = procMeta.ExecutablePath
		event.ProcessCommandLine = procMeta.CommandLine
	}

	// Set thread info from comm
	event.ThreadName = sample.Comm
	event.ThreadID = int64(sample.PID)

	// Extract container ID from cgroup (if in container)
	if cInfo, err := container.InfoForPID(sample.PID); err == nil && cInfo.ContainerID != "" {
		event.ContainerID = cInfo.ContainerID
	}

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

		// Count user vs kernel frames
		for _, frame := range sample.Frames {
			if frame.IsKernel {
				event.KernelFrames++
			} else {
				event.UserFrames++
			}
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
		samplePeriodNs := samplePeriodFromHz(e.config.CPUSampleRate)
		event.DurationNs = sample.Value * samplePeriodNs
	case ProfileTypeOffCPU:
		event.DurationNs = sample.Value // Off-CPU value is block time in ns
		event.BlockReason = sample.BlockReason.String()
	case ProfileTypeMemory, ProfileTypeHeap, ProfileTypeAllocCount, ProfileTypeAllocBytes, ProfileTypeAllocs:
		// Memory profiling: Value is bytes allocated, not time
		event.AllocationSize = sample.Value
		// Set allocation type from eBPF data
		if sample.AllocType > 0 {
			event.AllocationType = allocTypeToString(sample.AllocType)
		}
		// No duration for memory allocations
	case ProfileTypeMutex:
		// Mutex contention: Value is wait time in ns
		event.DurationNs = sample.Value
		// Set lock address if available
		if sample.LockAddr != 0 {
			event.LockAddress = fmt.Sprintf("0x%x", sample.LockAddr)
			// Try to resolve lock class/type from DWARF
			if lockClass := e.lookupLockClass(sample.PID, sample.LockAddr); lockClass != "" {
				event.LockClass = lockClass
			}
		}
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

// allocTypeToString converts allocation type enum to human-readable string
// Note: Free types (freeFree, freeMunmap, freeDelete) use same numeric values as alloc types
// but are handled separately in free event processing, not allocation type classification
func allocTypeToString(allocType uint8) string {
	switch allocType {
	case allocMalloc:
		return "malloc"
	case allocCalloc:
		return "calloc"
	case allocRealloc:
		return "realloc"
	case allocMmap:
		return "mmap"
	case allocNew:
		return "new"
	case allocPosixMemalign:
		return "posix_memalign"
	default:
		return "unknown"
	}
}

// lookupLockClass attempts to resolve lock type/class name from address using DWARF
func (e *LogExporter) lookupLockClass(pid uint32, addr uint64) string {
	// This requires DWARF type information from the binary
	// Try to find the variable/symbol at this address and extract its type

	// Read /proc/<pid>/maps to find which binary contains this address
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return ""
	}

	// Parse maps to find memory region containing the lock address
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var binaryPath string
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}

		// Parse address range
		addrs := strings.Split(parts[0], "-")
		if len(addrs) != 2 {
			continue
		}

		start, err1 := strconv.ParseUint(addrs[0], 16, 64)
		end, err2 := strconv.ParseUint(addrs[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}

		// Check if lock address is in this range
		if addr >= start && addr < end {
			// Found the region, get the binary path
			if len(parts) >= 6 {
				binaryPath = parts[5]
				break
			}
		}
	}

	if binaryPath == "" || binaryPath == "[heap]" || binaryPath == "[stack]" || binaryPath == "[vdso]" {
		// Lock is in heap/stack, use generic names
		if binaryPath == "[heap]" {
			return "heap_lock"
		}
		return ""
	}

	// Try to open the binary and read DWARF info
	f, err := elf.Open(binaryPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Load DWARF debug information
	dwarfData, err := f.DWARF()
	if err != nil {
		// No DWARF debug info available
		return ""
	}

	// Search DWARF entries for variables/types at this address
	reader := dwarfData.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		// Look for variable declarations
		if entry.Tag == dwarf.TagVariable {
			// Check if this variable has a location matching our address
			if locAttr := entry.Val(dwarf.AttrLocation); locAttr != nil {
				// Location expressions are complex, skip for now
				// In a full implementation, we'd decode the location expression
				continue
			}
		}

		// Look for type definitions that might be mutex types
		if entry.Tag == dwarf.TagStructType || entry.Tag == dwarf.TagTypedef {
			if nameAttr := entry.Val(dwarf.AttrName); nameAttr != nil {
				typeName := nameAttr.(string)
				// Check if this looks like a mutex type
				if strings.Contains(strings.ToLower(typeName), "mutex") ||
					strings.Contains(strings.ToLower(typeName), "lock") ||
					strings.Contains(strings.ToLower(typeName), "spinlock") {
					// Found a potential lock type
					// Without full location decoding, we can't be 100% sure this is THE lock
					// But we can use heuristics for common patterns

					// For Go: sync.Mutex, sync.RWMutex
					// For C/C++: pthread_mutex_t, std::mutex
					return typeName
				}
			}
		}
	}

	// Fallback: try to detect lock type from common patterns in binary
	// This is a heuristic approach when DWARF doesn't have full info

	// Check for common lock type symbols in the binary
	syms, err := f.Symbols()
	if err == nil {
		for _, sym := range syms {
			if sym.Value == 0 {
				continue
			}

			// Check if symbol address is close to lock address (within 1KB)
			if addr >= sym.Value && addr < sym.Value+1024 {
				name := sym.Name

				// Extract type info from symbol name
				if strings.Contains(name, "sync.Mutex") {
					return "sync.Mutex"
				}
				if strings.Contains(name, "sync.RWMutex") {
					return "sync.RWMutex"
				}
				if strings.Contains(name, "pthread_mutex") {
					return "pthread_mutex_t"
				}
				if strings.Contains(name, "std::mutex") || strings.Contains(name, "_ZSt") {
					return "std::mutex"
				}
			}
		}
	}

	// Unable to determine lock class
	return ""
}
