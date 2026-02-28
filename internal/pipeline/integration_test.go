package pipeline_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// ============================================================
// Integration Tests for V3 Pipeline
// ============================================================

// TestPipelineMetricsEndToEnd tests the full metrics pipeline flow.
func TestPipelineMetricsEndToEnd(t *testing.T) {
	// Create test metrics
	md := createTestMetrics("test_metric", 10)

	// Verify structure
	if md.ResourceMetrics().Len() != 1 {
		t.Errorf("expected 1 resource metrics, got %d", md.ResourceMetrics().Len())
	}

	rm := md.ResourceMetrics().At(0)
	if rm.ScopeMetrics().Len() != 1 {
		t.Errorf("expected 1 scope metrics, got %d", rm.ScopeMetrics().Len())
	}

	sm := rm.ScopeMetrics().At(0)
	if sm.Metrics().Len() != 1 {
		t.Errorf("expected 1 metric, got %d", sm.Metrics().Len())
	}

	metric := sm.Metrics().At(0)
	if metric.Name() != "test_metric" {
		t.Errorf("expected name 'test_metric', got '%s'", metric.Name())
	}
	if metric.Gauge().DataPoints().Len() != 10 {
		t.Errorf("expected 10 data points, got %d", metric.Gauge().DataPoints().Len())
	}
}

// TestPipelineTracesEndToEnd tests the full traces pipeline flow.
func TestPipelineTracesEndToEnd(t *testing.T) {
	// Create test traces
	td := createTestTraces("test-service", 5)

	// Verify structure
	if td.ResourceSpans().Len() != 1 {
		t.Errorf("expected 1 resource spans, got %d", td.ResourceSpans().Len())
	}

	rs := td.ResourceSpans().At(0)

	// Check service name
	serviceName, ok := rs.Resource().Attributes().Get("service.name")
	if !ok || serviceName.Str() != "test-service" {
		t.Errorf("expected service.name 'test-service', got '%v'", serviceName)
	}

	if rs.ScopeSpans().Len() != 1 {
		t.Errorf("expected 1 scope spans, got %d", rs.ScopeSpans().Len())
	}

	ss := rs.ScopeSpans().At(0)
	if ss.Spans().Len() != 5 {
		t.Errorf("expected 5 spans, got %d", ss.Spans().Len())
	}
}

// TestPipelineLogsEndToEnd tests the full logs pipeline flow.
func TestPipelineLogsEndToEnd(t *testing.T) {
	// Create test logs
	ld := createTestLogs("test-app", 3)

	// Verify structure
	if ld.ResourceLogs().Len() != 1 {
		t.Errorf("expected 1 resource logs, got %d", ld.ResourceLogs().Len())
	}

	rl := ld.ResourceLogs().At(0)
	if rl.ScopeLogs().Len() != 1 {
		t.Errorf("expected 1 scope logs, got %d", rl.ScopeLogs().Len())
	}

	sl := rl.ScopeLogs().At(0)
	if sl.LogRecords().Len() != 3 {
		t.Errorf("expected 3 log records, got %d", sl.LogRecords().Len())
	}
}

// TestPipelineMetricsWithAttributes tests metrics with various attribute configurations.
func TestPipelineMetricsWithAttributes(t *testing.T) {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()

	// Set resource attributes
	rm.Resource().Attributes().PutStr("service.name", "test-service")
	rm.Resource().Attributes().PutStr("service.namespace", "production")
	rm.Resource().Attributes().PutStr("host.name", "node-1")
	rm.Resource().Attributes().PutInt("host.port", 8080)

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("test-scope")
	sm.Scope().SetVersion("1.0.0")

	// Create counter metric
	counter := sm.Metrics().AppendEmpty()
	counter.SetName("http_requests_total")
	counter.SetDescription("Total HTTP requests")
	counter.SetUnit("1")
	sum := counter.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

	dp := sum.DataPoints().AppendEmpty()
	dp.SetIntValue(100)
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	dp.Attributes().PutStr("method", "GET")
	dp.Attributes().PutStr("path", "/api/v1/users")
	dp.Attributes().PutInt("status_code", 200)

	// Verify
	if md.MetricCount() != 1 {
		t.Errorf("expected 1 metric, got %d", md.MetricCount())
	}
	if md.DataPointCount() != 1 {
		t.Errorf("expected 1 data point, got %d", md.DataPointCount())
	}
}

// TestPipelineTracesWithEvents tests traces with span events.
func TestPipelineTracesWithEvents(t *testing.T) {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "event-service")

	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("process-request")
	span.SetTraceID(pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	span.SetSpanID(pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	span.SetStartTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-time.Second)))
	span.SetEndTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	span.SetKind(ptrace.SpanKindServer)
	span.Status().SetCode(ptrace.StatusCodeOk)

	// Add events
	event1 := span.Events().AppendEmpty()
	event1.SetName("request.received")
	event1.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-900 * time.Millisecond)))

	event2 := span.Events().AppendEmpty()
	event2.SetName("validation.complete")
	event2.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-500 * time.Millisecond)))
	event2.Attributes().PutBool("valid", true)

	// Verify
	if td.SpanCount() != 1 {
		t.Errorf("expected 1 span, got %d", td.SpanCount())
	}

	resultSpan := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if resultSpan.Events().Len() != 2 {
		t.Errorf("expected 2 events, got %d", resultSpan.Events().Len())
	}
}

// TestPipelineLogsWithSeverity tests logs with different severity levels.
func TestPipelineLogsWithSeverity(t *testing.T) {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "log-service")

	sl := rl.ScopeLogs().AppendEmpty()

	severities := []struct {
		text     string
		severity plog.SeverityNumber
	}{
		{"Debug message", plog.SeverityNumberDebug},
		{"Info message", plog.SeverityNumberInfo},
		{"Warning message", plog.SeverityNumberWarn},
		{"Error message", plog.SeverityNumberError},
		{"Fatal message", plog.SeverityNumberFatal},
	}

	for _, s := range severities {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(s.text)
		lr.SetSeverityNumber(s.severity)
		lr.SetSeverityText(s.severity.String())
		lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	}

	// Verify
	if ld.LogRecordCount() != 5 {
		t.Errorf("expected 5 log records, got %d", ld.LogRecordCount())
	}
}

// TestPipelineConcurrentProcessing tests concurrent signal processing.
func TestPipelineConcurrentProcessing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})

	// Process metrics concurrently
	go func() {
		for i := 0; i < 100; i++ {
			md := createTestMetrics("concurrent_metric", 1)
			_ = md.MetricCount() // Access data
		}
		done <- struct{}{}
	}()

	// Process traces concurrently
	go func() {
		for i := 0; i < 100; i++ {
			td := createTestTraces("concurrent-service", 1)
			_ = td.SpanCount() // Access data
		}
		done <- struct{}{}
	}()

	// Process logs concurrently
	go func() {
		for i := 0; i < 100; i++ {
			ld := createTestLogs("concurrent-app", 1)
			_ = ld.LogRecordCount() // Access data
		}
		done <- struct{}{}
	}()

	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("timeout waiting for concurrent processing")
		}
	}
}

// TestPipelineDataCloning tests data cloning/copying behavior.
func TestPipelineDataCloning(t *testing.T) {
	// Create original
	original := createTestMetrics("original", 1)

	// Clone
	clone := pmetric.NewMetrics()
	original.CopyTo(clone)

	// Modify clone
	clone.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).SetName("modified")

	// Verify original unchanged
	originalName := original.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Name()
	if originalName != "original" {
		t.Errorf("original was modified: %s", originalName)
	}

	// Verify clone changed
	cloneName := clone.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Name()
	if cloneName != "modified" {
		t.Errorf("clone was not modified: %s", cloneName)
	}
}

// TestPipelineEmptySignals tests handling of empty signals.
func TestPipelineEmptySignals(t *testing.T) {
	// Empty metrics
	emptyMetrics := pmetric.NewMetrics()
	if emptyMetrics.MetricCount() != 0 {
		t.Errorf("expected 0 metrics, got %d", emptyMetrics.MetricCount())
	}
	if emptyMetrics.DataPointCount() != 0 {
		t.Errorf("expected 0 data points, got %d", emptyMetrics.DataPointCount())
	}

	// Empty traces
	emptyTraces := ptrace.NewTraces()
	if emptyTraces.SpanCount() != 0 {
		t.Errorf("expected 0 spans, got %d", emptyTraces.SpanCount())
	}

	// Empty logs
	emptyLogs := plog.NewLogs()
	if emptyLogs.LogRecordCount() != 0 {
		t.Errorf("expected 0 log records, got %d", emptyLogs.LogRecordCount())
	}
}

// ============================================================
// Helper Functions
// ============================================================

func createTestMetrics(name string, dataPoints int) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "test-service")

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("test-scope")

	metric := sm.Metrics().AppendEmpty()
	metric.SetName(name)
	gauge := metric.SetEmptyGauge()

	for i := 0; i < dataPoints; i++ {
		dp := gauge.DataPoints().AppendEmpty()
		dp.SetDoubleValue(float64(i))
		dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	}

	return md
}

func createTestTraces(serviceName string, spanCount int) ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", serviceName)

	ss := rs.ScopeSpans().AppendEmpty()
	ss.Scope().SetName("test-scope")

	for i := 0; i < spanCount; i++ {
		span := ss.Spans().AppendEmpty()
		span.SetName("span-" + string(rune('A'+i)))
		span.SetKind(ptrace.SpanKindInternal)
	}

	return td
}

func createTestLogs(appName string, recordCount int) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", appName)

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("test-scope")

	for i := 0; i < recordCount; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr("Log message " + string(rune('A'+i)))
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
		lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	}

	return ld
}
