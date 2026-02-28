package pipeline

import (
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestSignalType_String(t *testing.T) {
	tests := []struct {
		st   PipelineSignalType
		want string
	}{
		{SignalTypeTrace, "trace"},
		{SignalTypeLog, "log"},
		{SignalTypeMetric, "metric"},
		{PipelineSignalType(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.st.String(); got != tt.want {
			t.Errorf("SignalType(%d).String() = %q, want %q", tt.st, got, tt.want)
		}
	}
}

func TestTraceSignal(t *testing.T) {
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "test-service")
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("test-span")
	span.SetTraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	span.SetSpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})

	signal := NewTraceSignal(traces, "ebpf-tracer")

	if signal.Type() != SignalTypeTrace {
		t.Errorf("Type() = %v, want %v", signal.Type(), SignalTypeTrace)
	}
	if signal.Collector() != "ebpf-tracer" {
		t.Errorf("Collector() = %v, want %v", signal.Collector(), "ebpf-tracer")
	}
	if signal.Timestamp().IsZero() {
		t.Error("Timestamp() should not be zero")
	}
	if signal.Size() <= 0 {
		t.Error("Size() should be positive")
	}

	pdata := signal.ToPData()
	if _, ok := pdata.(ptrace.Traces); !ok {
		t.Error("ToPData() should return ptrace.Traces")
	}

	resource := signal.Resource()
	if v, _ := resource.Attributes().Get("service.name"); v.Str() != "test-service" {
		t.Error("Resource() should return the trace resource")
	}
}

func TestLogSignal(t *testing.T) {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "test-service")
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test log message")

	signal := NewLogSignal(logs, "file-logs")

	if signal.Type() != SignalTypeLog {
		t.Errorf("Type() = %v, want %v", signal.Type(), SignalTypeLog)
	}
	if signal.Collector() != "file-logs" {
		t.Errorf("Collector() = %v, want %v", signal.Collector(), "file-logs")
	}
	if signal.Timestamp().IsZero() {
		t.Error("Timestamp() should not be zero")
	}
	if signal.Size() <= 0 {
		t.Error("Size() should be positive")
	}

	pdata := signal.ToPData()
	if _, ok := pdata.(plog.Logs); !ok {
		t.Error("ToPData() should return plog.Logs")
	}

	resource := signal.Resource()
	if v, _ := resource.Attributes().Get("service.name"); v.Str() != "test-service" {
		t.Error("Resource() should return the log resource")
	}
}

func TestMetricSignal(t *testing.T) {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "test-service")
	sm := rm.ScopeMetrics().AppendEmpty()
	m := sm.Metrics().AppendEmpty()
	m.SetName("test_metric")
	m.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(42)

	signal := NewMetricSignal(metrics, "host-metrics")

	if signal.Type() != SignalTypeMetric {
		t.Errorf("Type() = %v, want %v", signal.Type(), SignalTypeMetric)
	}
	if signal.Collector() != "host-metrics" {
		t.Errorf("Collector() = %v, want %v", signal.Collector(), "host-metrics")
	}
	if signal.Timestamp().IsZero() {
		t.Error("Timestamp() should not be zero")
	}
	if signal.Size() <= 0 {
		t.Error("Size() should be positive")
	}

	pdata := signal.ToPData()
	if _, ok := pdata.(pmetric.Metrics); !ok {
		t.Error("ToPData() should return pmetric.Metrics")
	}

	resource := signal.Resource()
	if v, _ := resource.Attributes().Get("service.name"); v.Str() != "test-service" {
		t.Error("Resource() should return the metric resource")
	}
}

func TestEmptySignals(t *testing.T) {
	t.Run("empty trace signal", func(t *testing.T) {
		traces := ptrace.NewTraces()
		signal := NewTraceSignal(traces, "test")

		// Should not panic, should return empty resource.
		resource := signal.Resource()
		if resource.Attributes().Len() != 0 {
			t.Error("empty signal should return empty resource")
		}

		// Timestamp should still be set (to now).
		if time.Since(signal.Timestamp()) > time.Second {
			t.Error("timestamp should be recent")
		}
	})

	t.Run("empty log signal", func(t *testing.T) {
		logs := plog.NewLogs()
		signal := NewLogSignal(logs, "test")

		resource := signal.Resource()
		if resource.Attributes().Len() != 0 {
			t.Error("empty signal should return empty resource")
		}
	})

	t.Run("empty metric signal", func(t *testing.T) {
		metrics := pmetric.NewMetrics()
		signal := NewMetricSignal(metrics, "test")

		resource := signal.Resource()
		if resource.Attributes().Len() != 0 {
			t.Error("empty signal should return empty resource")
		}
	})
}

func TestSignalInterfaceCompliance(t *testing.T) {
	// This test verifies that all signal types implement the Signal interface.
	var signals []PipelineSignal

	traces := ptrace.NewTraces()
	signals = append(signals, NewTraceSignal(traces, "trace-collector"))

	logs := plog.NewLogs()
	signals = append(signals, NewLogSignal(logs, "log-collector"))

	metrics := pmetric.NewMetrics()
	signals = append(signals, NewMetricSignal(metrics, "metric-collector"))

	for _, s := range signals {
		// Call all interface methods to verify implementation.
		_ = s.Type()
		_ = s.Resource()
		_ = s.Timestamp()
		_ = s.ToPData()
		_ = s.Size()
		_ = s.Collector()
	}
}
