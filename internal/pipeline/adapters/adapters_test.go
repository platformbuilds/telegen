package adapters

import (
	"context"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// mockSink records signals sent to it.
type mockSink struct {
	traceCount  atomic.Int64
	logCount    atomic.Int64
	metricCount atomic.Int64
}

func (s *mockSink) SendTraces(ctx context.Context, traces ptrace.Traces) error {
	s.traceCount.Add(int64(traces.SpanCount()))
	return nil
}

func (s *mockSink) SendLogs(ctx context.Context, logs plog.Logs) error {
	s.logCount.Add(int64(logs.LogRecordCount()))
	return nil
}

func (s *mockSink) SendMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	s.metricCount.Add(int64(metrics.DataPointCount()))
	return nil
}

func TestAdapterRegistry(t *testing.T) {
	sink := &mockSink{}
	registry := NewAdapterRegistry(sink)

	t.Run("register and get", func(t *testing.T) {
		adapter := NewEBPFTracesAdapter()
		registry.Register(adapter)

		got, ok := registry.Get(CollectorEBPFTraces)
		if !ok {
			t.Error("expected to find adapter")
		}
		if got.Type() != CollectorEBPFTraces {
			t.Errorf("expected type %v, got %v", CollectorEBPFTraces, got.Type())
		}
	})

	t.Run("list adapters", func(t *testing.T) {
		types := registry.List()
		if len(types) == 0 {
			t.Error("expected at least one adapter")
		}
	})
}

func TestEBPFTracesAdapter(t *testing.T) {
	sink := &mockSink{}
	adapter := NewEBPFTracesAdapter()

	ctx := context.Background()

	t.Run("start and stop", func(t *testing.T) {
		if err := adapter.Start(ctx, sink); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		if !adapter.IsRunning() {
			t.Error("expected adapter to be running")
		}

		if err := adapter.Stop(ctx); err != nil {
			t.Fatalf("Stop failed: %v", err)
		}
		if adapter.IsRunning() {
			t.Error("expected adapter to not be running")
		}
	})

	t.Run("send traces", func(t *testing.T) {
		adapter.Start(ctx, sink)
		defer adapter.Stop(ctx)

		traces := createTestTraces()
		if err := adapter.OnTraces(ctx, traces); err != nil {
			t.Fatalf("OnTraces failed: %v", err)
		}

		if sink.traceCount.Load() == 0 {
			t.Error("expected traces to be sent")
		}
	})

	t.Run("ignore when not running", func(t *testing.T) {
		adapter := NewEBPFTracesAdapter()
		traces := createTestTraces()

		// Should not error when not running.
		if err := adapter.OnTraces(ctx, traces); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestEBPFProfilingAdapter(t *testing.T) {
	sink := &mockSink{}
	adapter := NewEBPFProfilingAdapter()

	ctx := context.Background()
	adapter.Start(ctx, sink)
	defer adapter.Stop(ctx)

	t.Run("send profiles as logs", func(t *testing.T) {
		logs := createTestLogs()
		if err := adapter.OnProfiles(ctx, logs); err != nil {
			t.Fatalf("OnProfiles failed: %v", err)
		}

		if sink.logCount.Load() == 0 {
			t.Error("expected logs to be sent")
		}
	})

	t.Run("send profile metrics", func(t *testing.T) {
		metrics := createTestMetrics()
		if err := adapter.OnProfileMetrics(ctx, metrics); err != nil {
			t.Fatalf("OnProfileMetrics failed: %v", err)
		}

		if sink.metricCount.Load() == 0 {
			t.Error("expected metrics to be sent")
		}
	})
}

func TestFileLogsAdapter(t *testing.T) {
	sink := &mockSink{}
	adapter := NewFileLogsAdapter()

	ctx := context.Background()
	adapter.Start(ctx, sink)
	defer adapter.Stop(ctx)

	logs := createTestLogs()
	if err := adapter.OnLogs(ctx, logs); err != nil {
		t.Fatalf("OnLogs failed: %v", err)
	}

	if sink.logCount.Load() == 0 {
		t.Error("expected logs to be sent")
	}
}

func TestHostMetricsAdapter(t *testing.T) {
	sink := &mockSink{}
	adapter := NewHostMetricsAdapter()

	ctx := context.Background()
	adapter.Start(ctx, sink)
	defer adapter.Stop(ctx)

	metrics := createTestMetrics()
	if err := adapter.OnMetrics(ctx, metrics); err != nil {
		t.Fatalf("OnMetrics failed: %v", err)
	}

	if sink.metricCount.Load() == 0 {
		t.Error("expected metrics to be sent")
	}
}

func TestKafkaLogsAdapter(t *testing.T) {
	sink := &mockSink{}
	adapter := NewKafkaLogsAdapter()

	ctx := context.Background()
	adapter.Start(ctx, sink)
	defer adapter.Stop(ctx)

	logs := createTestLogs()
	if err := adapter.OnLogs(ctx, logs); err != nil {
		t.Fatalf("OnLogs failed: %v", err)
	}

	if sink.logCount.Load() == 0 {
		t.Error("expected logs to be sent")
	}
}

func TestSecurityAdapter(t *testing.T) {
	sink := &mockSink{}
	adapter := NewSecurityAdapter()

	ctx := context.Background()
	adapter.Start(ctx, sink)
	defer adapter.Stop(ctx)

	t.Run("send security events", func(t *testing.T) {
		events := createTestLogs()
		if err := adapter.OnSecurityEvents(ctx, events); err != nil {
			t.Fatalf("OnSecurityEvents failed: %v", err)
		}
	})

	t.Run("send security metrics", func(t *testing.T) {
		metrics := createTestMetrics()
		if err := adapter.OnSecurityMetrics(ctx, metrics); err != nil {
			t.Fatalf("OnSecurityMetrics failed: %v", err)
		}
	})
}

func TestGPUAdapter(t *testing.T) {
	sink := &mockSink{}
	adapter := NewGPUAdapter()

	ctx := context.Background()
	adapter.Start(ctx, sink)
	defer adapter.Stop(ctx)

	t.Run("send GPU traces", func(t *testing.T) {
		traces := createTestTraces()
		if err := adapter.OnGPUTraces(ctx, traces); err != nil {
			t.Fatalf("OnGPUTraces failed: %v", err)
		}
	})

	t.Run("send GPU metrics", func(t *testing.T) {
		metrics := createTestMetrics()
		if err := adapter.OnGPUMetrics(ctx, metrics); err != nil {
			t.Fatalf("OnGPUMetrics failed: %v", err)
		}
	})
}

func TestDefaultAdapterSet(t *testing.T) {
	sink := &mockSink{}
	registry := DefaultAdapterSet(sink)

	expectedAdapters := []CollectorType{
		CollectorEBPFTraces,
		CollectorEBPFProfiling,
		CollectorJFRProfiling,
		CollectorFileLogs,
		CollectorHostMetrics,
		CollectorKubeMetrics,
		CollectorNetworkFlows,
		CollectorKafkaLogs,
		CollectorSecurity,
		CollectorGPU,
		CollectorDatabaseTracing,
		CollectorLogTrace,
	}

	for _, ct := range expectedAdapters {
		if _, ok := registry.Get(ct); !ok {
			t.Errorf("expected adapter %v to be registered", ct)
		}
	}
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
