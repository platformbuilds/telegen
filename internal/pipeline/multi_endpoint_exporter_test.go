package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestMultiEndpointExporter_Create(t *testing.T) {
	t.Run("requires endpoints", func(t *testing.T) {
		_, err := NewMultiEndpointExporter(MultiEndpointConfig{}, nil)
		if err == nil {
			t.Error("expected error for empty endpoints")
		}
	})

	t.Run("requires enabled endpoints", func(t *testing.T) {
		config := MultiEndpointConfig{
			Endpoints: []EndpointConfig{
				{Name: "primary", URL: "localhost:4317", Enabled: false},
			},
		}
		_, err := NewMultiEndpointExporter(config, nil)
		if err == nil {
			t.Error("expected error when no endpoints enabled")
		}
	})

	t.Run("creates with valid config", func(t *testing.T) {
		config := MultiEndpointConfig{
			Endpoints: []EndpointConfig{
				{Name: "primary", URL: "localhost:4317", Enabled: true},
			},
		}
		me, err := NewMultiEndpointExporter(config, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if me == nil {
			t.Fatal("expected non-nil exporter")
		}
	})
}

func TestMultiEndpointExporter_FailoverMode(t *testing.T) {
	var primaryCalls, secondaryCalls atomic.Int32
	var primaryShouldFail atomic.Bool
	primaryShouldFail.Store(true)

	// Create mock exporters.
	config := MultiEndpointConfig{
		Endpoints: []EndpointConfig{
			{Name: "primary", URL: "localhost:4317", Enabled: true, Priority: 1},
			{Name: "secondary", URL: "localhost:4318", Enabled: true, Priority: 2},
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 10, // High to avoid tripping.
			OpenDuration:     time.Minute,
		},
		Retry: RetryConfig{Enabled: false},
	}

	me, err := NewMultiEndpointExporter(config, slog.Default())
	if err != nil {
		t.Fatalf("failed to create exporter: %v", err)
	}

	// Replace exporters with mocks.
	me.endpoints[0].exporter.traceClient = &mockTraceClient{
		exportFn: func(ctx context.Context, traces ptrace.Traces) error {
			primaryCalls.Add(1)
			if primaryShouldFail.Load() {
				return errors.New("primary failed")
			}
			return nil
		},
	}
	me.endpoints[1].exporter.traceClient = &mockTraceClient{
		exportFn: func(ctx context.Context, traces ptrace.Traces) error {
			secondaryCalls.Add(1)
			return nil
		},
	}

	ctx := context.Background()
	traces := createTestTraces()

	// Should failover to secondary.
	err = me.ExportTraces(ctx, traces)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if primaryCalls.Load() != 1 {
		t.Errorf("expected 1 primary call, got %d", primaryCalls.Load())
	}
	if secondaryCalls.Load() != 1 {
		t.Errorf("expected 1 secondary call, got %d", secondaryCalls.Load())
	}

	// Now primary works.
	primaryShouldFail.Store(false)
	err = me.ExportTraces(ctx, traces)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Primary should be called.
	if primaryCalls.Load() != 2 {
		t.Errorf("expected 2 primary calls, got %d", primaryCalls.Load())
	}
	// Secondary should not be called again.
	if secondaryCalls.Load() != 1 {
		t.Errorf("expected 1 secondary call, got %d", secondaryCalls.Load())
	}
}

func TestMultiEndpointExporter_FanOutMode(t *testing.T) {
	var primaryCalls, secondaryCalls atomic.Int32

	config := MultiEndpointConfig{
		Endpoints: []EndpointConfig{
			{Name: "primary", URL: "localhost:4317", Enabled: true},
			{Name: "secondary", URL: "localhost:4318", Enabled: true},
		},
		FanOut:         true,
		CircuitBreaker: DefaultCircuitBreakerConfig(),
		Retry:          RetryConfig{Enabled: false},
	}

	me, err := NewMultiEndpointExporter(config, slog.Default())
	if err != nil {
		t.Fatalf("failed to create exporter: %v", err)
	}

	// Replace exporters with mocks.
	me.endpoints[0].exporter.logClient = &mockLogClient{
		exportFn: func(ctx context.Context, logs plog.Logs) error {
			primaryCalls.Add(1)
			return nil
		},
	}
	me.endpoints[1].exporter.logClient = &mockLogClient{
		exportFn: func(ctx context.Context, logs plog.Logs) error {
			secondaryCalls.Add(1)
			return nil
		},
	}

	ctx := context.Background()
	logs := createTestLogs()

	err = me.ExportLogs(ctx, logs)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Both should be called in fan-out mode.
	if primaryCalls.Load() != 1 {
		t.Errorf("expected 1 primary call, got %d", primaryCalls.Load())
	}
	if secondaryCalls.Load() != 1 {
		t.Errorf("expected 1 secondary call, got %d", secondaryCalls.Load())
	}
}

func TestMultiEndpointExporter_CircuitBreakerIntegration(t *testing.T) {
	var primaryCalls atomic.Int32

	config := MultiEndpointConfig{
		Endpoints: []EndpointConfig{
			{Name: "primary", URL: "localhost:4317", Enabled: true},
			{Name: "secondary", URL: "localhost:4318", Enabled: true},
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:      2,
			SuccessThreshold:      1,
			OpenDuration:          50 * time.Millisecond,
			HalfOpenMaxConcurrent: 1,
		},
		Retry: RetryConfig{Enabled: false},
	}

	me, err := NewMultiEndpointExporter(config, slog.Default())
	if err != nil {
		t.Fatalf("failed to create exporter: %v", err)
	}

	// Primary always fails.
	me.endpoints[0].exporter.metricClient = &mockMetricClient{
		exportFn: func(ctx context.Context, metrics pmetric.Metrics) error {
			primaryCalls.Add(1)
			return errors.New("primary failed")
		},
	}
	me.endpoints[1].exporter.metricClient = &mockMetricClient{
		exportFn: func(ctx context.Context, metrics pmetric.Metrics) error {
			return nil
		},
	}

	ctx := context.Background()
	metrics := createTestMetrics()

	// Trip circuit breaker on primary (2 failures).
	me.ExportMetrics(ctx, metrics)
	me.ExportMetrics(ctx, metrics)

	// Circuit should be open.
	cbStats := me.endpoints[0].circuitBreaker.Stats()
	if cbStats.State != CircuitOpen {
		t.Errorf("expected circuit to be open, got %v", cbStats.State)
	}

	// More exports should skip primary.
	primaryBefore := primaryCalls.Load()
	me.ExportMetrics(ctx, metrics)
	me.ExportMetrics(ctx, metrics)

	if primaryCalls.Load() != primaryBefore {
		t.Error("expected primary to be skipped while circuit is open")
	}
}

func TestMultiEndpointExporter_CriticalFailure(t *testing.T) {
	var criticalCalled atomic.Bool
	var criticalErrMsg string

	config := MultiEndpointConfig{
		Endpoints: []EndpointConfig{
			{Name: "primary", URL: "localhost:4317", Enabled: true},
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 100, // High to keep circuit closed.
		},
		Retry: RetryConfig{Enabled: false},
		CriticalFailureCallback: func(signalType PipelineSignalType, count int, err error) {
			criticalCalled.Store(true)
			criticalErrMsg = err.Error()
		},
	}

	me, err := NewMultiEndpointExporter(config, slog.Default())
	if err != nil {
		t.Fatalf("failed to create exporter: %v", err)
	}

	// Single endpoint always fails.
	me.endpoints[0].exporter.traceClient = &mockTraceClient{
		exportFn: func(ctx context.Context, traces ptrace.Traces) error {
			return errors.New("endpoint down")
		},
	}

	ctx := context.Background()
	traces := createTestTraces()

	err = me.ExportTraces(ctx, traces)
	if err == nil {
		t.Error("expected error when all endpoints fail")
	}

	if !criticalCalled.Load() {
		t.Error("expected critical failure callback to be called")
	}

	if criticalErrMsg != "endpoint down" {
		t.Errorf("expected error message 'endpoint down', got %s", criticalErrMsg)
	}

	stats := me.Stats()
	if stats.TotalDropped == 0 {
		t.Error("expected TotalDropped > 0")
	}
}

func TestMultiEndpointExporter_Stats(t *testing.T) {
	config := MultiEndpointConfig{
		Endpoints: []EndpointConfig{
			{Name: "primary", URL: "localhost:4317", Enabled: true},
			{Name: "secondary", URL: "localhost:4318", Enabled: true},
		},
	}

	me, err := NewMultiEndpointExporter(config, nil)
	if err != nil {
		t.Fatalf("failed to create exporter: %v", err)
	}

	stats := me.Stats()
	if len(stats.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints in stats, got %d", len(stats.Endpoints))
	}
	if stats.Endpoints[0].Name != "primary" {
		t.Errorf("expected primary endpoint, got %s", stats.Endpoints[0].Name)
	}
}

func TestMultiEndpointExporter_Shutdown(t *testing.T) {
	config := MultiEndpointConfig{
		Endpoints: []EndpointConfig{
			{Name: "primary", URL: "localhost:4317", Enabled: true},
		},
	}

	me, err := NewMultiEndpointExporter(config, nil)
	if err != nil {
		t.Fatalf("failed to create exporter: %v", err)
	}

	ctx := context.Background()
	if err := me.Shutdown(ctx); err != nil {
		t.Errorf("unexpected shutdown error: %v", err)
	}

	// Export after shutdown should fail.
	traces := createTestTraces()
	err = me.ExportTraces(ctx, traces)
	if err == nil {
		t.Error("expected error after shutdown")
	}
}

// Mock clients.

type mockTraceClient struct {
	exportFn func(context.Context, ptrace.Traces) error
}

func (m *mockTraceClient) Export(ctx context.Context, traces ptrace.Traces) error {
	if m.exportFn != nil {
		return m.exportFn(ctx, traces)
	}
	return nil
}

type mockLogClient struct {
	exportFn func(context.Context, plog.Logs) error
}

func (m *mockLogClient) Export(ctx context.Context, logs plog.Logs) error {
	if m.exportFn != nil {
		return m.exportFn(ctx, logs)
	}
	return nil
}

type mockMetricClient struct {
	exportFn func(context.Context, pmetric.Metrics) error
}

func (m *mockMetricClient) Export(ctx context.Context, metrics pmetric.Metrics) error {
	if m.exportFn != nil {
		return m.exportFn(ctx, metrics)
	}
	return nil
}

// Helper functions.

func createTestTraces() ptrace.Traces {
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "test")
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("test-span")
	return traces
}

func createTestLogs() plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "test")
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test log")
	return logs
}

func createTestMetrics() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "test")
	sm := rm.ScopeMetrics().AppendEmpty()
	m := sm.Metrics().AppendEmpty()
	m.SetName("test_metric")
	m.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(42)
	return metrics
}
