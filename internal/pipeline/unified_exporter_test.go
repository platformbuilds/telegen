package pipeline

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestNewUnifiedExporter(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := DefaultExporterConfig()
		exp, err := NewUnifiedExporter(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if exp == nil {
			t.Fatal("exporter should not be nil")
		}
	})

	t.Run("empty endpoint", func(t *testing.T) {
		config := DefaultExporterConfig()
		config.Endpoint = ""
		_, err := NewUnifiedExporter(config)
		if err == nil {
			t.Error("expected error for empty endpoint")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		config := ExporterConfig{Endpoint: "localhost:4317"}
		exp, err := NewUnifiedExporter(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if exp.config.Timeout != 30*time.Second {
			t.Errorf("expected timeout 30s, got %v", exp.config.Timeout)
		}
		if exp.config.MaxConcurrentExports != 4 {
			t.Errorf("expected max concurrent 4, got %d", exp.config.MaxConcurrentExports)
		}
		if exp.config.BatchSize != 1000 {
			t.Errorf("expected batch size 1000, got %d", exp.config.BatchSize)
		}
	})
}

func TestUnifiedExporter_Export(t *testing.T) {
	t.Run("export trace", func(t *testing.T) {
		exp := ueCreateTestExporter(t)

		traces := ueCreateTestTraces()
		signal := NewTraceSignal(traces, "test")

		err := exp.Export(context.Background(), signal)
		if err != nil {
			t.Fatalf("export failed: %v", err)
		}

		stats := exp.Stats()
		if stats.ExportedTraces != 1 {
			t.Errorf("expected 1 exported trace, got %d", stats.ExportedTraces)
		}
	})

	t.Run("export log", func(t *testing.T) {
		exp := ueCreateTestExporter(t)

		logs := ueCreateTestLogs()
		signal := NewLogSignal(logs, "test")

		err := exp.Export(context.Background(), signal)
		if err != nil {
			t.Fatalf("export failed: %v", err)
		}

		stats := exp.Stats()
		if stats.ExportedLogs != 1 {
			t.Errorf("expected 1 exported log, got %d", stats.ExportedLogs)
		}
	})

	t.Run("export metric", func(t *testing.T) {
		exp := ueCreateTestExporter(t)

		metrics := ueCreateTestMetrics()
		signal := NewMetricSignal(metrics, "test")

		err := exp.Export(context.Background(), signal)
		if err != nil {
			t.Fatalf("export failed: %v", err)
		}

		stats := exp.Stats()
		if stats.ExportedMetrics != 1 {
			t.Errorf("expected 1 exported metric, got %d", stats.ExportedMetrics)
		}
	})

	t.Run("export after shutdown", func(t *testing.T) {
		exp := ueCreateTestExporter(t)
		exp.Shutdown(context.Background())

		traces := ueCreateTestTraces()
		signal := NewTraceSignal(traces, "test")

		err := exp.Export(context.Background(), signal)
		if err == nil {
			t.Error("expected error after shutdown")
		}
	})
}

func TestUnifiedExporter_ExportBatch(t *testing.T) {
	t.Run("mixed signal types", func(t *testing.T) {
		exp := ueCreateTestExporter(t)

		signals := []PipelineSignal{
			NewTraceSignal(ueCreateTestTraces(), "test"),
			NewLogSignal(ueCreateTestLogs(), "test"),
			NewMetricSignal(ueCreateTestMetrics(), "test"),
		}

		err := exp.ExportBatch(context.Background(), signals)
		if err != nil {
			t.Fatalf("batch export failed: %v", err)
		}

		stats := exp.Stats()
		if stats.ExportedTraces != 1 {
			t.Errorf("expected 1 exported trace, got %d", stats.ExportedTraces)
		}
		if stats.ExportedLogs != 1 {
			t.Errorf("expected 1 exported log, got %d", stats.ExportedLogs)
		}
		if stats.ExportedMetrics != 1 {
			t.Errorf("expected 1 exported metric, got %d", stats.ExportedMetrics)
		}
	})

	t.Run("empty batch", func(t *testing.T) {
		exp := ueCreateTestExporter(t)

		err := exp.ExportBatch(context.Background(), nil)
		if err != nil {
			t.Errorf("empty batch should not fail: %v", err)
		}
	})

	t.Run("multiple traces merged", func(t *testing.T) {
		exp := ueCreateTestExporter(t)

		signals := []PipelineSignal{
			NewTraceSignal(ueCreateTestTraces(), "test1"),
			NewTraceSignal(ueCreateTestTraces(), "test2"),
			NewTraceSignal(ueCreateTestTraces(), "test3"),
		}

		err := exp.ExportBatch(context.Background(), signals)
		if err != nil {
			t.Fatalf("batch export failed: %v", err)
		}

		stats := exp.Stats()
		if stats.ExportedTraces != 3 {
			t.Errorf("expected 3 exported traces, got %d", stats.ExportedTraces)
		}
	})
}

func TestUnifiedExporter_Backoff(t *testing.T) {
	config := ExporterConfig{
		Endpoint: "localhost:4317",
		Retry: RetryConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	exp, _ := NewUnifiedExporter(config)

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1 * time.Second}, // Capped at max.
		{6, 1 * time.Second},
	}

	for _, tt := range tests {
		backoff := exp.calculateBackoff(tt.attempt)
		if backoff != tt.expected {
			t.Errorf("attempt %d: expected %v, got %v", tt.attempt, tt.expected, backoff)
		}
	}
}

func TestUnifiedExporter_Shutdown(t *testing.T) {
	exp := ueCreateTestExporter(t)

	err := exp.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	// Second shutdown should be safe.
	err = exp.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("second shutdown failed: %v", err)
	}
}

func TestMergeTraces(t *testing.T) {
	traces1 := ueCreateTestTraces()
	traces2 := ueCreateTestTraces()

	merged := mergeTraces([]ptrace.Traces{traces1, traces2})

	if merged.SpanCount() != 2 {
		t.Errorf("expected 2 spans, got %d", merged.SpanCount())
	}
}

func TestMergeLogs(t *testing.T) {
	logs1 := ueCreateTestLogs()
	logs2 := ueCreateTestLogs()

	merged := mergeLogs([]plog.Logs{logs1, logs2})

	if merged.LogRecordCount() != 2 {
		t.Errorf("expected 2 log records, got %d", merged.LogRecordCount())
	}
}

func TestMergeMetrics(t *testing.T) {
	metrics1 := ueCreateTestMetrics()
	metrics2 := ueCreateTestMetrics()

	merged := mergeMetrics([]pmetric.Metrics{metrics1, metrics2})

	if merged.DataPointCount() != 2 {
		t.Errorf("expected 2 data points, got %d", merged.DataPointCount())
	}
}

// Helper functions.

func ueCreateTestExporter(t *testing.T) *UnifiedExporter {
	t.Helper()

	config := DefaultExporterConfig()
	exp, err := NewUnifiedExporter(config)
	if err != nil {
		t.Fatalf("failed to create exporter: %v", err)
	}

	// Install mock clients.
	exp.traceClient = &mockTraceClient{}
	exp.logClient = &mockLogClient{}
	exp.metricClient = &mockMetricClient{}

	return exp
}

func ueCreateTestTraces() ptrace.Traces {
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "test")
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("test-span")
	return traces
}

func ueCreateTestLogs() plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "test")
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test log")
	return logs
}

func ueCreateTestMetrics() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "test")
	sm := rm.ScopeMetrics().AppendEmpty()
	m := sm.Metrics().AppendEmpty()
	m.SetName("test_metric")
	m.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(42)
	return metrics
}

// Mock clients.

type ueMockTraceClient struct{}

func (c *ueMockTraceClient) Export(ctx context.Context, traces ptrace.Traces) error {
	return nil
}

type ueMockLogClient struct{}

func (c *ueMockLogClient) Export(ctx context.Context, logs plog.Logs) error {
	return nil
}

type ueMockMetricClient struct{}

func (c *ueMockMetricClient) Export(ctx context.Context, metrics pmetric.Metrics) error {
	return nil
}
