package pipeline

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/mirastacklabs-ai/telegen/internal/pipeline/adapters"
)

func TestUnifiedPipelineCreation(t *testing.T) {
	config := DefaultUnifiedPipelineConfig()
	config.Exporter.Endpoint = "localhost:4317"
	config.Exporter.Insecure = true

	pipeline, err := NewUnifiedPipeline(config)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer pipeline.cancel()

	if pipeline.exporter == nil {
		t.Error("exporter should not be nil")
	}

	if pipeline.adapterRegistry == nil {
		t.Error("adapter registry should not be nil")
	}

	if pipeline.converterPipeline == nil {
		t.Error("converter pipeline should not be nil")
	}

	// Check that adapters are registered.
	adapterList := pipeline.adapterRegistry.List()
	if len(adapterList) == 0 {
		t.Error("expected adapters to be registered")
	}

	// Verify specific adapters exist.
	expectedAdapters := []adapters.CollectorType{
		adapters.CollectorEBPFTraces,
		adapters.CollectorEBPFProfiling,
		adapters.CollectorJFRProfiling,
		adapters.CollectorFileLogs,
		adapters.CollectorHostMetrics,
		adapters.CollectorKubeMetrics,
		adapters.CollectorNetworkFlows,
		adapters.CollectorKafkaLogs,
		adapters.CollectorSecurity,
		adapters.CollectorGPU,
		adapters.CollectorDatabaseTracing,
		adapters.CollectorLogTrace,
	}

	for _, expected := range expectedAdapters {
		if _, ok := pipeline.Adapter(expected); !ok {
			t.Errorf("adapter %s not registered", expected)
		}
	}
}

func TestUnifiedPipelineWithMultiEndpoint(t *testing.T) {
	config := DefaultUnifiedPipelineConfig()
	config.Exporter.Endpoint = "localhost:4317"
	config.Exporter.Insecure = true
	config.MultiEndpoint = &MultiEndpointConfig{
		FanOut: false, // failover mode
		Endpoints: []EndpointConfig{
			{
				Name:    "primary",
				URL:     "localhost:4317",
				Enabled: true,
			},
			{
				Name:    "secondary",
				URL:     "localhost:4318",
				Enabled: true,
			},
		},
	}

	pipeline, err := NewUnifiedPipeline(config)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer pipeline.cancel()

	if pipeline.multiExporter == nil {
		t.Error("multi-endpoint exporter should not be nil")
	}
}

func TestUnifiedPipelineSendSignals(t *testing.T) {
	config := DefaultUnifiedPipelineConfig()
	config.Exporter.Endpoint = "localhost:4317"
	config.Exporter.Insecure = true

	pipeline, err := NewUnifiedPipeline(config)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer pipeline.cancel()

	ctx := context.Background()

	// Test SendTraces.
	t.Run("send_traces", func(t *testing.T) {
		traces := createTestTracesV3()
		err := pipeline.SendTraces(ctx, traces)
		if err != nil {
			t.Errorf("SendTraces failed: %v", err)
		}

		// Read from channel to prevent blocking.
		select {
		case <-pipeline.traceCh:
			// Good.
		case <-time.After(100 * time.Millisecond):
			t.Error("traces not received in channel")
		}

		if pipeline.receivedTraces.Load() == 0 {
			t.Error("receivedTraces should be > 0")
		}
	})

	// Test SendLogs.
	t.Run("send_logs", func(t *testing.T) {
		logs := createTestLogsV3()
		err := pipeline.SendLogs(ctx, logs)
		if err != nil {
			t.Errorf("SendLogs failed: %v", err)
		}

		select {
		case <-pipeline.logCh:
			// Good.
		case <-time.After(100 * time.Millisecond):
			t.Error("logs not received in channel")
		}

		if pipeline.receivedLogs.Load() == 0 {
			t.Error("receivedLogs should be > 0")
		}
	})

	// Test SendMetrics.
	t.Run("send_metrics", func(t *testing.T) {
		metrics := createTestMetricsV3()
		err := pipeline.SendMetrics(ctx, metrics)
		if err != nil {
			t.Errorf("SendMetrics failed: %v", err)
		}

		select {
		case <-pipeline.metricCh:
			// Good.
		case <-time.After(100 * time.Millisecond):
			t.Error("metrics not received in channel")
		}

		if pipeline.receivedMetrics.Load() == 0 {
			t.Error("receivedMetrics should be > 0")
		}
	})
}

func TestUnifiedPipelineStats(t *testing.T) {
	config := DefaultUnifiedPipelineConfig()
	config.Exporter.Endpoint = "localhost:4317"
	config.Exporter.Insecure = true

	pipeline, err := NewUnifiedPipeline(config)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer pipeline.cancel()

	ctx := context.Background()

	// Send some signals.
	traces := createTestTracesV3()
	_ = pipeline.SendTraces(ctx, traces)
	<-pipeline.traceCh // Drain.

	logs := createTestLogsV3()
	_ = pipeline.SendLogs(ctx, logs)
	<-pipeline.logCh // Drain.

	metrics := createTestMetricsV3()
	_ = pipeline.SendMetrics(ctx, metrics)
	<-pipeline.metricCh // Drain.

	stats := pipeline.Stats()

	if stats.ReceivedTraces == 0 {
		t.Error("ReceivedTraces should be > 0")
	}
	if stats.ReceivedLogs == 0 {
		t.Error("ReceivedLogs should be > 0")
	}
	if stats.ReceivedMetrics == 0 {
		t.Error("ReceivedMetrics should be > 0")
	}
	if stats.Adapters == 0 {
		t.Error("Adapters count should be > 0")
	}
}

func TestUnifiedPipelineConverters(t *testing.T) {
	config := DefaultUnifiedPipelineConfig()
	config.Exporter.Endpoint = "localhost:4317"
	config.Exporter.Insecure = true

	pipeline, err := NewUnifiedPipeline(config)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer pipeline.cancel()

	// Test that converters are accessible.
	convUnifiedPipeline := pipeline.Converters()
	if convUnifiedPipeline == nil {
		t.Fatal("converter pipeline should not be nil")
	}

	// Test Prometheus text conversion.
	promText := `# HELP test_counter A test counter
# TYPE test_counter counter
test_counter{label="value"} 42
`
	result, err := convUnifiedPipeline.ConvertPrometheusText(context.Background(), promText)
	if err != nil {
		t.Fatalf("ConvertPrometheusText failed: %v", err)
	}
	if result == nil {
		t.Error("conversion result should not be nil")
	}
}

func TestUnifiedPipelineIsRunning(t *testing.T) {
	config := DefaultUnifiedPipelineConfig()
	config.Exporter.Endpoint = "localhost:4317"
	config.Exporter.Insecure = true

	pipeline, err := NewUnifiedPipeline(config)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer pipeline.cancel()

	if pipeline.IsRunning() {
		t.Error("pipeline should not be running before Start")
	}
}

func TestUnifiedPipelineAdapterAccess(t *testing.T) {
	config := DefaultUnifiedPipelineConfig()
	config.Exporter.Endpoint = "localhost:4317"
	config.Exporter.Insecure = true

	pipeline, err := NewUnifiedPipeline(config)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer pipeline.cancel()

	// Test getting adapters.
	ebpfAdapter, ok := pipeline.Adapter(adapters.CollectorEBPFTraces)
	if !ok {
		t.Fatal("eBPF traces adapter not found")
	}
	if ebpfAdapter.Name() != "eBPF Traces" {
		t.Errorf("expected name 'eBPF Traces', got '%s'", ebpfAdapter.Name())
	}

	securityAdapter, ok := pipeline.Adapter(adapters.CollectorSecurity)
	if !ok {
		t.Fatal("security adapter not found")
	}
	if securityAdapter.Name() != "Security Monitoring" {
		t.Errorf("expected name 'Security Monitoring', got '%s'", securityAdapter.Name())
	}

	gpuAdapter, ok := pipeline.Adapter(adapters.CollectorGPU)
	if !ok {
		t.Fatal("GPU adapter not found")
	}
	if gpuAdapter.Name() != "GPU/AI-ML Tracing" {
		t.Errorf("expected name 'GPU/AI-ML Tracing', got '%s'", gpuAdapter.Name())
	}
}

// Helper functions to create test data.

func createTestTracesV3() ptrace.Traces {
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "test-service")

	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("test-span")
	span.SetTraceID(pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	span.SetSpanID(pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	span.SetStartTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	span.SetEndTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(time.Millisecond)))

	return traces
}

func createTestLogsV3() plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "test-service")

	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test log message")
	lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	lr.SetSeverityNumber(plog.SeverityNumberInfo)

	return logs
}

func createTestMetricsV3() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "test-service")

	sm := rm.ScopeMetrics().AppendEmpty()
	m := sm.Metrics().AppendEmpty()
	m.SetName("test.metric")
	gauge := m.SetEmptyGauge()
	dp := gauge.DataPoints().AppendEmpty()
	dp.SetDoubleValue(42.0)
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	return metrics
}
