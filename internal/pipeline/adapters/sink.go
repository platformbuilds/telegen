package adapters

import (
	"context"
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// UnifiedPipelineSink bridges collector adapters to the unified exporter.
// It implements SignalSink and converts pdata types to Signal types.
type UnifiedPipelineSink struct {
	// exporter is the V3 unified exporter.
	// Type: *pipeline.UnifiedExporter (avoided import cycle by using interface)
	exporter SignalExporter

	// Stats.
	tracesSent  atomic.Int64
	logsSent    atomic.Int64
	metricsSent atomic.Int64
}

// SignalExporter is the interface for the unified exporter.
// This avoids import cycles with the pipeline package.
type SignalExporter interface {
	ExportTraces(ctx context.Context, traces ptrace.Traces) error
	ExportLogs(ctx context.Context, logs plog.Logs) error
	ExportMetrics(ctx context.Context, metrics pmetric.Metrics) error
}

// NewUnifiedPipelineSink creates a new unified pipeline sink.
func NewUnifiedPipelineSink(exporter SignalExporter) *UnifiedPipelineSink {
	return &UnifiedPipelineSink{
		exporter: exporter,
	}
}

// SendTraces sends trace data to the unified exporter.
func (s *UnifiedPipelineSink) SendTraces(ctx context.Context, traces ptrace.Traces) error {
	if err := s.exporter.ExportTraces(ctx, traces); err != nil {
		return err
	}
	s.tracesSent.Add(int64(traces.SpanCount()))
	return nil
}

// SendLogs sends log data to the unified exporter.
func (s *UnifiedPipelineSink) SendLogs(ctx context.Context, logs plog.Logs) error {
	if err := s.exporter.ExportLogs(ctx, logs); err != nil {
		return err
	}
	s.logsSent.Add(int64(logs.LogRecordCount()))
	return nil
}

// SendMetrics sends metric data to the unified exporter.
func (s *UnifiedPipelineSink) SendMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if err := s.exporter.ExportMetrics(ctx, metrics); err != nil {
		return err
	}
	s.metricsSent.Add(int64(metrics.DataPointCount()))
	return nil
}

// Stats returns sink statistics.
func (s *UnifiedPipelineSink) Stats() SinkStats {
	return SinkStats{
		TracesSent:  s.tracesSent.Load(),
		LogsSent:    s.logsSent.Load(),
		MetricsSent: s.metricsSent.Load(),
	}
}

// SinkStats holds sink statistics.
type SinkStats struct {
	TracesSent  int64
	LogsSent    int64
	MetricsSent int64
}

// DefaultAdapterSet creates a registry with all standard V2 collector adapters.
func DefaultAdapterSet(sink SignalSink) *AdapterRegistry {
	registry := NewAdapterRegistry(sink)

	// Agent mode collectors.
	registry.Register(NewEBPFTracesAdapter())
	registry.Register(NewEBPFProfilingAdapter())
	registry.Register(NewJFRProfilingAdapter())
	registry.Register(NewFileLogsAdapter())
	registry.Register(NewHostMetricsAdapter())
	registry.Register(NewKubeMetricsAdapter())
	registry.Register(NewNetworkFlowsAdapter())

	// V2 recent features.
	registry.Register(NewKafkaLogsAdapter())
	registry.Register(NewSecurityAdapter())
	registry.Register(NewGPUAdapter())
	registry.Register(NewDatabaseTracingAdapter())
	registry.Register(NewLogTraceCorrelationAdapter())

	return registry
}
