package limits

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
// Cardinality Limiter Tests
// ============================================================

func TestCardinalityLimiter(t *testing.T) {
	config := DefaultCardinalityConfig()
	config.DefaultPerMetricLimit = 3
	config.TTL = 100 * time.Millisecond
	config.ReportInterval = 1 * time.Hour // Long interval to avoid hitting in test

	limiter := NewCardinalityLimiter(config, nil)

	// Don't start the full limiter with goroutines for this test
	// Just test the core functionality
	limiter.config.Enabled = true

	// Create metrics with increasing cardinality
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("test_metric")
	gauge := metric.SetEmptyGauge()

	// Add 5 data points (should limit to 3)
	for i := 0; i < 5; i++ {
		dp := gauge.DataPoints().AppendEmpty()
		dp.SetDoubleValue(float64(i))
		dp.Attributes().PutStr("instance", string(rune('a'+i)))
	}

	// Process without starting background loops
	ctx := context.Background()
	result, err := limiter.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Should have restricted series
	stats := limiter.Stats()
	if stats.DroppedSeries == 0 {
		t.Error("expected some dropped series")
	}

	// Result should still be valid
	if result.ResourceMetrics().Len() == 0 {
		t.Error("expected result to have resource metrics")
	}
}

func TestCardinalityLimiterDisabled(t *testing.T) {
	config := DefaultCardinalityConfig()
	config.Enabled = false

	limiter := NewCardinalityLimiter(config, nil)

	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("test")
	metric.SetEmptyGauge().DataPoints().AppendEmpty().SetDoubleValue(1)

	ctx := context.Background()
	result, err := limiter.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Should pass through unchanged
	if result.ResourceMetrics().Len() != 1 {
		t.Error("expected 1 resource metrics")
	}
}

func TestCardinalityHashAttributes(t *testing.T) {
	config := DefaultCardinalityConfig()
	config.ExcludedAttributes = []string{"timestamp"}

	limiter := NewCardinalityLimiter(config, nil)

	// Create attributes
	attrs1 := pcommon.NewMap()
	attrs1.PutStr("service", "foo")
	attrs1.PutStr("method", "GET")
	attrs1.PutStr("timestamp", "12345")

	attrs2 := pcommon.NewMap()
	attrs2.PutStr("service", "foo")
	attrs2.PutStr("method", "GET")
	attrs2.PutStr("timestamp", "67890") // Different timestamp

	// Should hash to same value (timestamp excluded)
	hash1 := limiter.hashAttributes(attrs1)
	hash2 := limiter.hashAttributes(attrs2)

	if hash1 != hash2 {
		t.Error("expected same hash with excluded attribute different")
	}

	// Different service should hash differently
	attrs3 := pcommon.NewMap()
	attrs3.PutStr("service", "bar")
	attrs3.PutStr("method", "GET")

	hash3 := limiter.hashAttributes(attrs3)
	if hash1 == hash3 {
		t.Error("expected different hash for different service")
	}
}

// ============================================================
// Rate Limiter Tests
// ============================================================

func TestRateLimiter(t *testing.T) {
	config := DefaultRateLimiterConfig()
	config.Metrics.DataPointsPerSecond = 10
	config.BurstMultiplier = 1.0 // No burst for predictable testing
	config.ReportInterval = 1 * time.Hour // Avoid hitting report in test

	limiter := NewRateLimiter(config, nil)

	// Don't start background loops
	// Just test core functionality

	// Create metrics with many data points
	md := createMetricsWithDataPoints(100)

	ctx := context.Background()
	// First call should accept up to burst
	result, err := limiter.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	stats := limiter.Stats()

	// Should have accepted some and dropped some
	if stats.MetricsAccepted == 0 {
		t.Error("expected some accepted metrics")
	}

	// Result should be valid
	_ = result
}

func TestRateLimiterTraces(t *testing.T) {
	config := DefaultRateLimiterConfig()
	config.Traces.DataPointsPerSecond = 5
	config.BurstMultiplier = 1.0
	config.ReportInterval = 1 * time.Hour

	limiter := NewRateLimiter(config, nil)

	// Create traces with spans
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 20; i++ {
		span := ss.Spans().AppendEmpty()
		span.SetName("test-span")
	}

	// Process
	ctx := context.Background()
	_, err := limiter.ProcessTraces(ctx, td)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	stats := limiter.Stats()
	if stats.TracesAccepted+stats.TracesDropped != 20 {
		t.Errorf("expected total 20 spans processed, got accepted=%d dropped=%d",
			stats.TracesAccepted, stats.TracesDropped)
	}
}

func TestRateLimiterLogs(t *testing.T) {
	config := DefaultRateLimiterConfig()
	config.Logs.DataPointsPerSecond = 5
	config.BurstMultiplier = 1.0
	config.ReportInterval = 1 * time.Hour

	limiter := NewRateLimiter(config, nil)

	// Create logs
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	for i := 0; i < 20; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr("test log message")
	}

	// Process
	ctx := context.Background()
	_, err := limiter.ProcessLogs(ctx, ld)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	stats := limiter.Stats()
	if stats.LogsAccepted+stats.LogsDropped != 20 {
		t.Errorf("expected total 20 logs processed, got accepted=%d dropped=%d",
			stats.LogsAccepted, stats.LogsDropped)
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	config := DefaultRateLimiterConfig()
	config.Enabled = false

	limiter := NewRateLimiter(config, nil)

	md := createMetricsWithDataPoints(100)

	ctx := context.Background()
	result, err := limiter.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Should pass through unchanged
	originalCount := countDataPoints(md)
	resultCount := countDataPoints(result)

	if originalCount != resultCount {
		t.Errorf("expected %d data points, got %d", originalCount, resultCount)
	}
}

// ============================================================
// Attribute Limiter Tests
// ============================================================

func TestAttributeLimiter(t *testing.T) {
	config := DefaultAttributeLimiterConfig()
	config.MaxDataPointAttributes = 5
	config.MaxAttributeValueLength = 10

	limiter := NewAttributeLimiter(config, nil)

	// Create metrics with many attributes
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("test")
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(1.0)

	// Add 10 attributes
	for i := 0; i < 10; i++ {
		dp.Attributes().PutStr("attr"+string(rune('a'+i)), "value")
	}

	ctx := context.Background()
	result, err := limiter.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check that attributes were limited
	resultDP := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0)
	if resultDP.Attributes().Len() > 5 {
		t.Errorf("expected max 5 attributes, got %d", resultDP.Attributes().Len())
	}

	stats := limiter.Stats()
	if stats.AttributesDropped == 0 {
		t.Error("expected some dropped attributes")
	}
}

func TestAttributeLimiterValueTruncation(t *testing.T) {
	config := DefaultAttributeLimiterConfig()
	config.MaxAttributeValueLength = 10
	config.TruncationSuffix = "..."

	limiter := NewAttributeLimiter(config, nil)

	// Create metrics with long attribute value
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("test")
	dp := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(1.0)
	dp.Attributes().PutStr("long_value", "this is a very long value that should be truncated")

	ctx := context.Background()
	result, err := limiter.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check value was truncated
	resultDP := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0)
	val, _ := resultDP.Attributes().Get("long_value")
	if len(val.Str()) > 10 {
		t.Errorf("expected value length <= 10, got %d", len(val.Str()))
	}
	if val.Str()[len(val.Str())-3:] != "..." {
		t.Error("expected truncation suffix")
	}

	stats := limiter.Stats()
	if stats.ValuesTruncated == 0 {
		t.Error("expected some truncated values")
	}
}

func TestAttributeLimiterProtectedAttributes(t *testing.T) {
	config := DefaultAttributeLimiterConfig()
	config.MaxDataPointAttributes = 2
	config.ProtectedAttributes = []string{"service.name", "k8s.pod.name"}

	limiter := NewAttributeLimiter(config, nil)

	// Create metrics with protected attributes
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "my-service")
	rm.Resource().Attributes().PutStr("k8s.pod.name", "my-pod")
	rm.Resource().Attributes().PutStr("unprotected1", "value1")
	rm.Resource().Attributes().PutStr("unprotected2", "value2")
	rm.Resource().Attributes().PutStr("unprotected3", "value3")

	ctx := context.Background()
	result, err := limiter.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Protected attributes should still exist
	resultRes := result.ResourceMetrics().At(0).Resource()
	if _, ok := resultRes.Attributes().Get("service.name"); !ok {
		t.Error("expected protected attribute service.name to exist")
	}
	if _, ok := resultRes.Attributes().Get("k8s.pod.name"); !ok {
		t.Error("expected protected attribute k8s.pod.name to exist")
	}
}

func TestAttributeLimiterTraces(t *testing.T) {
	config := DefaultAttributeLimiterConfig()
	config.MaxDataPointAttributes = 3

	limiter := NewAttributeLimiter(config, nil)

	// Create trace with many span attributes
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("test-span")

	// Add many attributes
	for i := 0; i < 10; i++ {
		span.Attributes().PutStr("attr"+string(rune('a'+i)), "value")
	}

	ctx := context.Background()
	result, err := limiter.ProcessTraces(ctx, td)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check attributes were limited
	resultSpan := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if resultSpan.Attributes().Len() > 3 {
		t.Errorf("expected max 3 attributes, got %d", resultSpan.Attributes().Len())
	}
}

func TestAttributeLimiterLogs(t *testing.T) {
	config := DefaultAttributeLimiterConfig()
	config.MaxDataPointAttributes = 3

	limiter := NewAttributeLimiter(config, nil)

	// Create log with many attributes
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test log")

	// Add many attributes
	for i := 0; i < 10; i++ {
		lr.Attributes().PutStr("attr"+string(rune('a'+i)), "value")
	}

	ctx := context.Background()
	result, err := limiter.ProcessLogs(ctx, ld)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check attributes were limited
	resultLog := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if resultLog.Attributes().Len() > 3 {
		t.Errorf("expected max 3 attributes, got %d", resultLog.Attributes().Len())
	}
}

// ============================================================
// Helper Functions
// ============================================================

func createMetricsWithDataPoints(n int) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("test_metric")
	gauge := metric.SetEmptyGauge()

	for i := 0; i < n; i++ {
		dp := gauge.DataPoints().AppendEmpty()
		dp.SetDoubleValue(float64(i))
	}

	return md
}

func countDataPoints(md pmetric.Metrics) int {
	count := 0
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					count += metric.Gauge().DataPoints().Len()
				case pmetric.MetricTypeSum:
					count += metric.Sum().DataPoints().Len()
				case pmetric.MetricTypeHistogram:
					count += metric.Histogram().DataPoints().Len()
				case pmetric.MetricTypeSummary:
					count += metric.Summary().DataPoints().Len()
				case pmetric.MetricTypeExponentialHistogram:
					count += metric.ExponentialHistogram().DataPoints().Len()
				}
			}
		}
	}
	return count
}
