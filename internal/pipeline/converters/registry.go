package converters

import (
	"context"
	"fmt"
	"sync"
)

// ConverterType identifies the type of converter.
type ConverterType string

const (
	ConverterPrometheus   ConverterType = "prometheus"
	ConverterJFR          ConverterType = "jfr"
	ConverterSecurity     ConverterType = "security"
	ConverterGPU          ConverterType = "gpu"
	ConverterEBPFProfile  ConverterType = "ebpf_profile"
)

// ConverterRegistry manages all signal converters.
type ConverterRegistry struct {
	mu               sync.RWMutex
	metricConverters map[ConverterType]MetricConverter
	traceConverters  map[ConverterType]TraceConverter
	logConverters    map[ConverterType]LogConverter
	profileConverters map[ConverterType]ProfileConverter
}

// NewConverterRegistry creates a new converter registry with default converters.
func NewConverterRegistry() *ConverterRegistry {
	r := &ConverterRegistry{
		metricConverters:  make(map[ConverterType]MetricConverter),
		traceConverters:   make(map[ConverterType]TraceConverter),
		logConverters:     make(map[ConverterType]LogConverter),
		profileConverters: make(map[ConverterType]ProfileConverter),
	}

	// Register default converters.
	r.registerDefaults()

	return r
}

// registerDefaults registers the default converters.
func (r *ConverterRegistry) registerDefaults() {
	// Prometheus converter (metrics).
	promConv := NewPrometheusConverter()
	r.metricConverters[ConverterPrometheus] = promConv

	// JFR converter (logs + metrics).
	jfrConv := NewJFRConverter()
	r.logConverters[ConverterJFR] = jfrConv
	r.metricConverters[ConverterJFR] = jfrConv

	// Security converter (logs + metrics).
	secConv := NewSecurityConverter()
	r.logConverters[ConverterSecurity] = secConv
	r.metricConverters[ConverterSecurity] = secConv

	// GPU converter (traces + metrics).
	gpuConv := NewGPUConverter()
	r.traceConverters[ConverterGPU] = gpuConv
	r.metricConverters[ConverterGPU] = gpuConv

	// eBPF Profile converter (logs + metrics).
	profileConv := NewEBPFProfileConverter()
	r.logConverters[ConverterEBPFProfile] = profileConv
	r.profileConverters[ConverterEBPFProfile] = profileConv
	r.metricConverters[ConverterEBPFProfile] = profileConv
}

// RegisterMetricConverter registers a metric converter.
func (r *ConverterRegistry) RegisterMetricConverter(t ConverterType, c MetricConverter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metricConverters[t] = c
}

// RegisterTraceConverter registers a trace converter.
func (r *ConverterRegistry) RegisterTraceConverter(t ConverterType, c TraceConverter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traceConverters[t] = c
}

// RegisterLogConverter registers a log converter.
func (r *ConverterRegistry) RegisterLogConverter(t ConverterType, c LogConverter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logConverters[t] = c
}

// RegisterProfileConverter registers a profile converter.
func (r *ConverterRegistry) RegisterProfileConverter(t ConverterType, c ProfileConverter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profileConverters[t] = c
}

// GetMetricConverter returns a metric converter by type.
func (r *ConverterRegistry) GetMetricConverter(t ConverterType) (MetricConverter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.metricConverters[t]
	return c, ok
}

// GetTraceConverter returns a trace converter by type.
func (r *ConverterRegistry) GetTraceConverter(t ConverterType) (TraceConverter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.traceConverters[t]
	return c, ok
}

// GetLogConverter returns a log converter by type.
func (r *ConverterRegistry) GetLogConverter(t ConverterType) (LogConverter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.logConverters[t]
	return c, ok
}

// GetProfileConverter returns a profile converter by type.
func (r *ConverterRegistry) GetProfileConverter(t ConverterType) (ProfileConverter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.profileConverters[t]
	return c, ok
}

// ConvertingPipeline provides a unified interface for converting various formats to OTLP.
type ConvertingPipeline struct {
	registry *ConverterRegistry
}

// NewConvertingPipeline creates a new converting pipeline.
func NewConvertingPipeline() *ConvertingPipeline {
	return &ConvertingPipeline{
		registry: NewConverterRegistry(),
	}
}

// Registry returns the converter registry.
func (p *ConvertingPipeline) Registry() *ConverterRegistry {
	return p.registry
}

// ConvertPrometheusMetrics converts Prometheus metrics to OTLP.
func (p *ConvertingPipeline) ConvertPrometheusMetrics(ctx context.Context, families []*PrometheusMetricFamily) (interface{}, error) {
	conv, ok := p.registry.GetMetricConverter(ConverterPrometheus)
	if !ok {
		return nil, fmt.Errorf("prometheus converter not found")
	}
	return conv.ConvertMetrics(ctx, families)
}

// ConvertPrometheusText parses and converts Prometheus text format to OTLP.
func (p *ConvertingPipeline) ConvertPrometheusText(ctx context.Context, text string) (interface{}, error) {
	families, err := ParsePrometheusText(text)
	if err != nil {
		return nil, fmt.Errorf("parsing prometheus text: %w", err)
	}
	return p.ConvertPrometheusMetrics(ctx, families)
}

// ConvertJFREvents converts JFR events to OTLP logs.
func (p *ConvertingPipeline) ConvertJFREvents(ctx context.Context, recording *JFRRecording) (interface{}, error) {
	conv, ok := p.registry.GetLogConverter(ConverterJFR)
	if !ok {
		return nil, fmt.Errorf("JFR converter not found")
	}
	return conv.ConvertLogs(ctx, recording)
}

// ConvertSecurityEvents converts security events to OTLP logs.
func (p *ConvertingPipeline) ConvertSecurityEvents(ctx context.Context, batch *SecurityEventBatch) (interface{}, error) {
	conv, ok := p.registry.GetLogConverter(ConverterSecurity)
	if !ok {
		return nil, fmt.Errorf("security converter not found")
	}
	return conv.ConvertLogs(ctx, batch)
}

// ConvertGPUEvents converts GPU events to OTLP traces.
func (p *ConvertingPipeline) ConvertGPUEvents(ctx context.Context, batch *GPUEventBatch) (interface{}, error) {
	conv, ok := p.registry.GetTraceConverter(ConverterGPU)
	if !ok {
		return nil, fmt.Errorf("GPU converter not found")
	}
	return conv.ConvertTraces(ctx, batch)
}

// ConvertEBPFProfiles converts eBPF profiles to OTLP logs.
func (p *ConvertingPipeline) ConvertEBPFProfiles(ctx context.Context, batch *ProfileBatch) (interface{}, error) {
	conv, ok := p.registry.GetProfileConverter(ConverterEBPFProfile)
	if !ok {
		return nil, fmt.Errorf("eBPF profile converter not found")
	}
	return conv.ConvertProfiles(ctx, batch)
}
