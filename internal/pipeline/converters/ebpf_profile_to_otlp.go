package converters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// EBPFProfileConverter converts eBPF profiling data to OTLP format.
// This handles CPU profiling, memory profiling, off-CPU profiling, and mutex contention.
type EBPFProfileConverter struct {
	// IncludeStackTraces includes stack traces in the log body.
	IncludeStackTraces bool
	// MaxStackDepth limits the stack trace depth.
	MaxStackDepth int
	// AggregateSymbols aggregates samples by symbol.
	AggregateSymbols bool
}

// ProfileData represents eBPF profiling data.
type ProfileData struct {
	Type       ProfileType    `json:"type"`
	StartTime  time.Time      `json:"startTime"`
	EndTime    time.Time      `json:"endTime"`
	Duration   time.Duration  `json:"duration"`
	SampleRate int            `json:"sampleRate"` // Hz
	Process    *ProfiledProcess `json:"process"`
	Samples    []ProfileSample `json:"samples"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// ProfileType represents the type of profile.
type ProfileType string

const (
	ProfileTypeCPU      ProfileType = "cpu"
	ProfileTypeMemory   ProfileType = "memory"
	ProfileTypeOffCPU   ProfileType = "off_cpu"
	ProfileTypeMutex    ProfileType = "mutex"
	ProfileTypeBlock    ProfileType = "block"
	ProfileTypeGoroutine ProfileType = "goroutine"
)

// ProfiledProcess represents the profiled process.
type ProfiledProcess struct {
	PID         int       `json:"pid"`
	Comm        string    `json:"comm"`
	Exe         string    `json:"exe,omitempty"`
	Cmdline     string    `json:"cmdline,omitempty"`
	ContainerID string    `json:"containerId,omitempty"`
	StartTime   time.Time `json:"startTime,omitempty"`
}

// ProfileSample represents a single profile sample.
type ProfileSample struct {
	Timestamp   time.Time     `json:"timestamp"`
	Value       int64         `json:"value"` // count, bytes, or nanoseconds depending on type
	Labels      map[string]string `json:"labels,omitempty"`
	StackTrace  []StackFrame  `json:"stackTrace,omitempty"`
}

// StackFrame represents a single stack frame.
type StackFrame struct {
	Address    uint64 `json:"address"`
	Symbol     string `json:"symbol,omitempty"`
	Module     string `json:"module,omitempty"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	IsKernel   bool   `json:"isKernel,omitempty"`
	IsJIT      bool   `json:"isJIT,omitempty"`
}

// ProfileBatch represents a batch of profile data.
type ProfileBatch struct {
	Profiles []ProfileData  `json:"profiles"`
	HostInfo *ProfileHostInfo `json:"hostInfo,omitempty"`
}

// ProfileHostInfo contains host information.
type ProfileHostInfo struct {
	Hostname    string `json:"hostname"`
	HostID      string `json:"hostId,omitempty"`
	Kernel      string `json:"kernel,omitempty"`
	Arch        string `json:"arch,omitempty"`
	CPUCount    int    `json:"cpuCount,omitempty"`
}

// NewEBPFProfileConverter creates a new EBPFProfileConverter with default settings.
func NewEBPFProfileConverter() *EBPFProfileConverter {
	return &EBPFProfileConverter{
		IncludeStackTraces: true,
		MaxStackDepth:      128,
		AggregateSymbols:   true,
	}
}

// Name returns the converter name.
func (c *EBPFProfileConverter) Name() string {
	return "ebpf_profile_to_otlp"
}

// ConvertProfiles converts eBPF profiles to OTLP logs.
// Profiles are represented as OTLP logs with pprof-like JSON in the body.
func (c *EBPFProfileConverter) ConvertProfiles(ctx context.Context, source interface{}) (plog.Logs, error) {
	batch, ok := source.(*ProfileBatch)
	if !ok {
		return plog.Logs{}, fmt.Errorf("expected *ProfileBatch, got %T", source)
	}

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()

	// Set resource attributes.
	res := rl.Resource()
	res.Attributes().PutStr("service.name", "profiler")
	res.Attributes().PutStr("telemetry.sdk.name", "telegen")
	if batch.HostInfo != nil {
		res.Attributes().PutStr("host.name", batch.HostInfo.Hostname)
		if batch.HostInfo.HostID != "" {
			res.Attributes().PutStr("host.id", batch.HostInfo.HostID)
		}
		if batch.HostInfo.Arch != "" {
			res.Attributes().PutStr("host.arch", batch.HostInfo.Arch)
		}
		if batch.HostInfo.CPUCount > 0 {
			res.Attributes().PutInt("host.cpu.count", int64(batch.HostInfo.CPUCount))
		}
	}

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("telegen.profiler.ebpf")
	sl.Scope().SetVersion("1.0.0")

	for _, profile := range batch.Profiles {
		lr := sl.LogRecords().AppendEmpty()
		c.convertProfile(&profile, lr)
	}

	return logs, nil
}

// convertProfile converts a single profile to a log record.
func (c *EBPFProfileConverter) convertProfile(profile *ProfileData, lr plog.LogRecord) {
	lr.SetTimestamp(pcommon.NewTimestampFromTime(profile.StartTime))
	lr.SetObservedTimestamp(Now())
	lr.SetSeverityNumber(plog.SeverityNumberInfo)
	lr.SetSeverityText("INFO")

	// Set body as JSON representation of the profile.
	if c.IncludeStackTraces {
		profileJSON, err := json.Marshal(profile)
		if err == nil {
			lr.Body().SetStr(string(profileJSON))
		} else {
			lr.Body().SetStr(fmt.Sprintf("profile:%s", profile.Type))
		}
	} else {
		// Create a summary without stack traces.
		summary := c.createProfileSummary(profile)
		summaryJSON, _ := json.Marshal(summary)
		lr.Body().SetStr(string(summaryJSON))
	}

	// Set attributes.
	attrs := lr.Attributes()
	attrs.PutStr("profile.type", string(profile.Type))
	attrs.PutInt("profile.duration_ns", int64(profile.Duration))
	attrs.PutInt("profile.sample_count", int64(len(profile.Samples)))
	attrs.PutInt("profile.sample_rate_hz", int64(profile.SampleRate))

	// Process info.
	if profile.Process != nil {
		attrs.PutInt("process.pid", int64(profile.Process.PID))
		attrs.PutStr("process.command", profile.Process.Comm)
		if profile.Process.Exe != "" {
			attrs.PutStr("process.executable.path", profile.Process.Exe)
		}
		if profile.Process.ContainerID != "" {
			attrs.PutStr("container.id", profile.Process.ContainerID)
		}
	}

	// Profile-specific attributes.
	c.addProfileTypeAttributes(profile, attrs)

	// Metadata.
	for k, v := range profile.Metadata {
		attrs.PutStr("profile.metadata."+k, v)
	}
}

// createProfileSummary creates a summary of the profile without stack traces.
func (c *EBPFProfileConverter) createProfileSummary(profile *ProfileData) map[string]interface{} {
	summary := map[string]interface{}{
		"type":        string(profile.Type),
		"startTime":   profile.StartTime.Format(time.RFC3339),
		"endTime":     profile.EndTime.Format(time.RFC3339),
		"duration":    profile.Duration.String(),
		"sampleCount": len(profile.Samples),
		"sampleRate":  profile.SampleRate,
	}

	if c.AggregateSymbols {
		symbolCounts := c.aggregateBySymbol(profile.Samples)
		if len(symbolCounts) > 0 {
			// Get top 10 symbols.
			topSymbols := make([]map[string]interface{}, 0, 10)
			for symbol, count := range symbolCounts {
				if len(topSymbols) < 10 {
					topSymbols = append(topSymbols, map[string]interface{}{
						"symbol": symbol,
						"count":  count,
					})
				}
			}
			summary["topSymbols"] = topSymbols
		}
	}

	return summary
}

// aggregateBySymbol aggregates samples by their top stack frame symbol.
func (c *EBPFProfileConverter) aggregateBySymbol(samples []ProfileSample) map[string]int64 {
	counts := make(map[string]int64)
	for _, sample := range samples {
		if len(sample.StackTrace) > 0 {
			symbol := sample.StackTrace[0].Symbol
			if symbol == "" {
				symbol = fmt.Sprintf("0x%x", sample.StackTrace[0].Address)
			}
			counts[symbol] += sample.Value
		}
	}
	return counts
}

// addProfileTypeAttributes adds profile-type-specific attributes.
func (c *EBPFProfileConverter) addProfileTypeAttributes(profile *ProfileData, attrs pcommon.Map) {
	switch profile.Type {
	case ProfileTypeCPU:
		attrs.PutStr("profile.unit", "samples")
		var totalSamples int64
		for _, s := range profile.Samples {
			totalSamples += s.Value
		}
		attrs.PutInt("profile.cpu.total_samples", totalSamples)

	case ProfileTypeMemory:
		attrs.PutStr("profile.unit", "bytes")
		var totalBytes int64
		var allocCount int64
		for _, s := range profile.Samples {
			totalBytes += s.Value
			allocCount++
		}
		attrs.PutInt("profile.memory.total_bytes", totalBytes)
		attrs.PutInt("profile.memory.allocation_count", allocCount)

	case ProfileTypeOffCPU:
		attrs.PutStr("profile.unit", "nanoseconds")
		var totalNs int64
		for _, s := range profile.Samples {
			totalNs += s.Value
		}
		attrs.PutInt("profile.off_cpu.total_ns", totalNs)

	case ProfileTypeMutex:
		attrs.PutStr("profile.unit", "nanoseconds")
		var totalContentionNs int64
		var contentionCount int64
		for _, s := range profile.Samples {
			totalContentionNs += s.Value
			contentionCount++
		}
		attrs.PutInt("profile.mutex.contention_ns", totalContentionNs)
		attrs.PutInt("profile.mutex.contention_count", contentionCount)

	case ProfileTypeBlock:
		attrs.PutStr("profile.unit", "nanoseconds")
		var totalBlockNs int64
		for _, s := range profile.Samples {
			totalBlockNs += s.Value
		}
		attrs.PutInt("profile.block.total_ns", totalBlockNs)

	case ProfileTypeGoroutine:
		attrs.PutStr("profile.unit", "count")
		attrs.PutInt("profile.goroutine.count", int64(len(profile.Samples)))
	}
}

// ConvertLogs implements LogConverter interface (alias for ConvertProfiles).
func (c *EBPFProfileConverter) ConvertLogs(ctx context.Context, source interface{}) (plog.Logs, error) {
	return c.ConvertProfiles(ctx, source)
}

// ConvertMetrics converts profile data to aggregated metrics.
func (c *EBPFProfileConverter) ConvertMetrics(ctx context.Context, source interface{}) (pmetric.Metrics, error) {
	batch, ok := source.(*ProfileBatch)
	if !ok {
		return pmetric.Metrics{}, fmt.Errorf("expected *ProfileBatch, got %T", source)
	}

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	res := rm.Resource()
	res.Attributes().PutStr("service.name", "profiler")

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen.profiler.ebpf")
	sm.Scope().SetVersion("1.0.0")

	// Aggregate metrics by profile type.
	for _, profile := range batch.Profiles {
		c.addProfileMetrics(&profile, sm)
	}

	return metrics, nil
}

// addProfileMetrics adds metrics for a single profile.
func (c *EBPFProfileConverter) addProfileMetrics(profile *ProfileData, sm pmetric.ScopeMetrics) {
	baseAttrs := make(map[string]string)
	if profile.Process != nil {
		baseAttrs["process.pid"] = fmt.Sprintf("%d", profile.Process.PID)
		baseAttrs["process.command"] = profile.Process.Comm
	}

	switch profile.Type {
	case ProfileTypeCPU:
		m := sm.Metrics().AppendEmpty()
		m.SetName("profiler.cpu.samples")
		m.SetDescription("CPU profile samples")
		sum := m.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		
		var total int64
		for _, s := range profile.Samples {
			total += s.Value
		}
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(total)
		dp.SetTimestamp(pcommon.NewTimestampFromTime(profile.EndTime))
		for k, v := range baseAttrs {
			dp.Attributes().PutStr(k, v)
		}

	case ProfileTypeMemory:
		// Memory allocated metric.
		m := sm.Metrics().AppendEmpty()
		m.SetName("profiler.memory.allocated")
		m.SetDescription("Memory allocated")
		m.SetUnit("By")
		sum := m.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		
		var total int64
		for _, s := range profile.Samples {
			total += s.Value
		}
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(total)
		dp.SetTimestamp(pcommon.NewTimestampFromTime(profile.EndTime))
		for k, v := range baseAttrs {
			dp.Attributes().PutStr(k, v)
		}

	case ProfileTypeOffCPU:
		m := sm.Metrics().AppendEmpty()
		m.SetName("profiler.off_cpu.time")
		m.SetDescription("Time spent off-CPU")
		m.SetUnit("ns")
		sum := m.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		
		var total int64
		for _, s := range profile.Samples {
			total += s.Value
		}
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(total)
		dp.SetTimestamp(pcommon.NewTimestampFromTime(profile.EndTime))
		for k, v := range baseAttrs {
			dp.Attributes().PutStr(k, v)
		}

	case ProfileTypeMutex:
		m := sm.Metrics().AppendEmpty()
		m.SetName("profiler.mutex.contention")
		m.SetDescription("Mutex contention time")
		m.SetUnit("ns")
		sum := m.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		
		var total int64
		for _, s := range profile.Samples {
			total += s.Value
		}
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(total)
		dp.SetTimestamp(pcommon.NewTimestampFromTime(profile.EndTime))
		for k, v := range baseAttrs {
			dp.Attributes().PutStr(k, v)
		}
	}
}
