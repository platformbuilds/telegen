// Package pipeline provides the unified signal processing pipeline for Telegen V3.
package pipeline

import (
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// PipelineSignalType represents the type of telemetry signal in the V3 pipeline.
type PipelineSignalType int

const (
	// SignalTypeTrace represents distributed tracing data.
	SignalTypeTrace PipelineSignalType = iota
	// SignalTypeLog represents log data.
	SignalTypeLog
	// SignalTypeMetric represents metric data.
	SignalTypeMetric
)

// String returns the string representation of the signal type.
func (t PipelineSignalType) String() string {
	switch t {
	case SignalTypeTrace:
		return "trace"
	case SignalTypeLog:
		return "log"
	case SignalTypeMetric:
		return "metric"
	default:
		return "unknown"
	}
}

// PipelineSignal is the common interface for all telemetry signals in the V3 pipeline.
// All signals (traces, logs, metrics) implement this interface, allowing
// unified processing through the pipeline.
type PipelineSignal interface {
	// Type returns the signal type (trace, log, metric).
	Type() PipelineSignalType

	// Resource returns the resource associated with this signal.
	Resource() pcommon.Resource

	// Timestamp returns the primary timestamp of this signal.
	Timestamp() time.Time

	// ToPData converts the signal to the appropriate pdata type.
	// Returns ptrace.Traces, plog.Logs, or pmetric.Metrics.
	ToPData() any

	// Size returns the approximate size in bytes.
	Size() int

	// Collector returns the name of the collector that produced this signal.
	Collector() string
}

// PipelineSignalProcessor processes signals in the pipeline.
type PipelineSignalProcessor interface {
	// Process processes a signal and returns the processed signal.
	// May return nil to drop the signal.
	Process(signal PipelineSignal) (PipelineSignal, error)
}

// PipelineSignalExporter exports signals to external systems.
type PipelineSignalExporter interface {
	// Export exports signals to the configured endpoint.
	Export(signals []PipelineSignal) error

	// Shutdown gracefully shuts down the exporter.
	Shutdown() error
}

// PipelineSignalQueue buffers signals for export.
type PipelineSignalQueue interface {
	// Enqueue adds a signal to the queue.
	Enqueue(signal PipelineSignal) error

	// Dequeue removes and returns signals from the queue.
	Dequeue(maxBatch int) ([]PipelineSignal, error)

	// Size returns the current queue size.
	Size() int

	// Close closes the queue.
	Close() error
}

// TraceSignal wraps ptrace.Traces as a Signal.
type TraceSignal struct {
	traces    ptrace.Traces
	timestamp time.Time
	collector string
}

// NewTraceSignal creates a new trace signal.
func NewTraceSignal(traces ptrace.Traces, collector string) *TraceSignal {
	ts := &TraceSignal{
		traces:    traces,
		timestamp: time.Now(),
		collector: collector,
	}

	// Try to extract timestamp from first span.
	if traces.ResourceSpans().Len() > 0 {
		rs := traces.ResourceSpans().At(0)
		if rs.ScopeSpans().Len() > 0 {
			ss := rs.ScopeSpans().At(0)
			if ss.Spans().Len() > 0 {
				span := ss.Spans().At(0)
				ts.timestamp = span.StartTimestamp().AsTime()
			}
		}
	}

	return ts
}

func (s *TraceSignal) Type() PipelineSignalType { return SignalTypeTrace }
func (s *TraceSignal) Timestamp() time.Time     { return s.timestamp }
func (s *TraceSignal) ToPData() any             { return s.traces }
func (s *TraceSignal) Collector() string        { return s.collector }
func (s *TraceSignal) Size() int                { return s.traces.SpanCount() * 500 } // Estimate
func (s *TraceSignal) Resource() pcommon.Resource {
	if s.traces.ResourceSpans().Len() > 0 {
		return s.traces.ResourceSpans().At(0).Resource()
	}
	return pcommon.NewResource()
}

// LogSignal wraps plog.Logs as a Signal.
type LogSignal struct {
	logs      plog.Logs
	timestamp time.Time
	collector string
}

// NewLogSignal creates a new log signal.
func NewLogSignal(logs plog.Logs, collector string) *LogSignal {
	ls := &LogSignal{
		logs:      logs,
		timestamp: time.Now(),
		collector: collector,
	}

	// Try to extract timestamp from first log record.
	if logs.ResourceLogs().Len() > 0 {
		rl := logs.ResourceLogs().At(0)
		if rl.ScopeLogs().Len() > 0 {
			sl := rl.ScopeLogs().At(0)
			if sl.LogRecords().Len() > 0 {
				lr := sl.LogRecords().At(0)
				ls.timestamp = lr.Timestamp().AsTime()
			}
		}
	}

	return ls
}

func (s *LogSignal) Type() PipelineSignalType { return SignalTypeLog }
func (s *LogSignal) Timestamp() time.Time     { return s.timestamp }
func (s *LogSignal) ToPData() any             { return s.logs }
func (s *LogSignal) Collector() string        { return s.collector }
func (s *LogSignal) Size() int                { return s.logs.LogRecordCount() * 200 } // Estimate
func (s *LogSignal) Resource() pcommon.Resource {
	if s.logs.ResourceLogs().Len() > 0 {
		return s.logs.ResourceLogs().At(0).Resource()
	}
	return pcommon.NewResource()
}

// MetricSignal wraps pmetric.Metrics as a Signal.
type MetricSignal struct {
	metrics   pmetric.Metrics
	timestamp time.Time
	collector string
}

// NewMetricSignal creates a new metric signal.
func NewMetricSignal(metrics pmetric.Metrics, collector string) *MetricSignal {
	return &MetricSignal{
		metrics:   metrics,
		timestamp: time.Now(),
		collector: collector,
	}
}

func (s *MetricSignal) Type() PipelineSignalType { return SignalTypeMetric }
func (s *MetricSignal) Timestamp() time.Time     { return s.timestamp }
func (s *MetricSignal) ToPData() any             { return s.metrics }
func (s *MetricSignal) Collector() string        { return s.collector }
func (s *MetricSignal) Size() int                { return s.metrics.DataPointCount() * 100 } // Estimate
func (s *MetricSignal) Resource() pcommon.Resource {
	if s.metrics.ResourceMetrics().Len() > 0 {
		return s.metrics.ResourceMetrics().At(0).Resource()
	}
	return pcommon.NewResource()
}

// Ensure implementations satisfy the PipelineSignal interface.
var (
	_ PipelineSignal = (*TraceSignal)(nil)
	_ PipelineSignal = (*LogSignal)(nil)
	_ PipelineSignal = (*MetricSignal)(nil)
)
