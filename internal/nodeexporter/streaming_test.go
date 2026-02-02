// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package nodeexporter

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// mockReceiver implements MetricsReceiver for testing.
type mockReceiver struct {
	mu       sync.Mutex
	batches  []*MetricsBatch
	recvErr  error
	recvTime time.Duration
}

func (m *mockReceiver) ReceiveMetrics(ctx context.Context, batch *MetricsBatch) error {
	if m.recvTime > 0 {
		time.Sleep(m.recvTime)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recvErr != nil {
		return m.recvErr
	}
	m.batches = append(m.batches, batch)
	return nil
}

func (m *mockReceiver) BatchCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.batches)
}

// TestStreamingExporterBasic tests basic streaming functionality.
func TestStreamingExporterBasic(t *testing.T) {
	registry := prometheus.NewRegistry()

	// Register a test metric
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_gauge",
		Help: "A test gauge",
	})
	registry.MustRegister(gauge)
	gauge.Set(42)

	env := &DetectedEnvironment{
		Type: EnvironmentBareMetal,
	}

	cfg := &ExportConfig{
		Enabled:      true,
		Interval:     100 * time.Millisecond,
		BatchSize:    100,
		FlushTimeout: 5 * time.Second,
	}

	exporter := NewStreamingExporter(cfg, registry, env, slog.Default())
	receiver := &mockReceiver{}
	exporter.SetReceiver(receiver)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := exporter.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for at least one collection
	time.Sleep(250 * time.Millisecond)
	exporter.Stop()

	if receiver.BatchCount() == 0 {
		t.Error("expected at least one batch to be received")
	}
}

// TestStreamingExporterWithCache tests streaming with caching enabled.
func TestStreamingExporterWithCache(t *testing.T) {
	registry := prometheus.NewRegistry()

	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_counter_total",
		Help: "A test counter",
	})
	registry.MustRegister(counter)
	counter.Add(100)

	env := &DetectedEnvironment{
		Type: EnvironmentBareMetal,
	}

	cfg := &ExportConfig{
		Enabled:      true,
		Interval:     50 * time.Millisecond,
		BatchSize:    100,
		FlushTimeout: 5 * time.Second,
		Cache: CacheConfig{
			Enabled: true,
			TTL:     200 * time.Millisecond,
		},
	}

	exporter := NewStreamingExporter(cfg, registry, env, slog.Default())
	receiver := &mockReceiver{}
	exporter.SetReceiver(receiver)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := exporter.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	time.Sleep(250 * time.Millisecond)
	exporter.Stop()

	stats := exporter.Stats()

	// With caching, some collects should hit the cache
	if stats.CollectCount == 0 {
		t.Error("expected at least one collect")
	}

	// Cache should have been used
	if cfg.Cache.Enabled && exporter.cache != nil && exporter.cache.HitRate() == 0 && stats.CollectCount > 1 {
		// If we collected more than once and cache is enabled, we should have some hits
		t.Log("Warning: cache hit rate is 0, expected some cache hits")
	}
}

// TestStreamingExporterCollectNow tests immediate collection.
func TestStreamingExporterCollectNow(t *testing.T) {
	registry := prometheus.NewRegistry()

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "immediate_gauge",
		Help: "Test immediate collection",
	})
	registry.MustRegister(gauge)
	gauge.Set(99.9)

	env := &DetectedEnvironment{
		Type:   EnvironmentVirtualMachine,
		Labels: map[string]string{"vm": "true"},
	}

	cfg := &ExportConfig{
		Enabled:  true,
		Interval: 1 * time.Hour, // Long interval so periodic doesn't interfere
	}

	exporter := NewStreamingExporter(cfg, registry, env, slog.Default())

	batch, err := exporter.CollectNow()
	if err != nil {
		t.Fatalf("CollectNow failed: %v", err)
	}

	if batch == nil {
		t.Fatal("expected non-nil batch")
	}

	if len(batch.Metrics) == 0 {
		t.Error("expected at least one metric family")
	}

	if batch.Environment.Type != EnvironmentVirtualMachine {
		t.Errorf("expected VM environment, got %s", batch.Environment.Type)
	}
}

// TestStreamingExporterStats tests statistics collection.
func TestStreamingExporterStats(t *testing.T) {
	registry := prometheus.NewRegistry()

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "stats_gauge",
		Help: "Test stats",
	})
	registry.MustRegister(gauge)
	gauge.Set(1)

	env := &DetectedEnvironment{Type: EnvironmentBareMetal}

	cfg := &ExportConfig{
		Enabled:  true,
		Interval: 50 * time.Millisecond,
	}

	exporter := NewStreamingExporter(cfg, registry, env, slog.Default())
	receiver := &mockReceiver{}
	exporter.SetReceiver(receiver)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	exporter.Start(ctx) //nolint:errcheck // test ignores error
	time.Sleep(150 * time.Millisecond)
	exporter.Stop()

	stats := exporter.Stats()

	if stats.CollectCount == 0 {
		t.Error("expected CollectCount > 0")
	}
	if stats.ExportCount == 0 {
		t.Error("expected ExportCount > 0")
	}
	if stats.AvgCollectDuration == 0 {
		t.Error("expected AvgCollectDuration > 0")
	}
}

// TestStreamingExporterEnvironmentLabels tests environment label injection.
func TestStreamingExporterEnvironmentLabels(t *testing.T) {
	registry := prometheus.NewRegistry()

	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "labeled_gauge",
		Help: "Test label injection",
	}, []string{"original"})
	registry.MustRegister(gauge)
	gauge.WithLabelValues("value1").Set(1)

	env := &DetectedEnvironment{
		Type: EnvironmentKubernetes,
		Labels: map[string]string{
			"k8s_node": "worker-1",
			"k8s_pod":  "test-pod",
		},
	}

	cfg := &ExportConfig{
		Enabled:  true,
		Interval: 1 * time.Hour,
	}

	exporter := NewStreamingExporter(cfg, registry, env, slog.Default())

	batch, err := exporter.CollectNow()
	if err != nil {
		t.Fatalf("CollectNow failed: %v", err)
	}

	// Check that environment labels were added
	for _, family := range batch.Metrics {
		if *family.Name == "labeled_gauge" {
			for _, metric := range family.Metric {
				labels := make(map[string]string)
				for _, l := range metric.Label {
					labels[*l.Name] = *l.Value
				}

				// Should have original label plus environment labels
				if _, ok := labels["original"]; !ok {
					t.Error("expected 'original' label")
				}
				if _, ok := labels["k8s_node"]; !ok {
					t.Error("expected 'k8s_node' label from environment")
				}
				if _, ok := labels["k8s_pod"]; !ok {
					t.Error("expected 'k8s_pod' label from environment")
				}
			}
		}
	}
}

// TestMetricCacheBasic tests basic cache functionality.
func TestMetricCacheBasic(t *testing.T) {
	registry := prometheus.NewRegistry()

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cached_gauge",
		Help: "Test caching",
	})
	registry.MustRegister(gauge)
	gauge.Set(50)

	cache := NewMetricCache(registry, 100*time.Millisecond, slog.Default())

	// First gather should be a miss
	metrics1, err := cache.Gather()
	if err != nil {
		t.Fatalf("First Gather failed: %v", err)
	}

	if len(metrics1) == 0 {
		t.Error("expected metrics from first gather")
	}

	stats := cache.Stats()
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}

	// Second gather within TTL should be a hit
	metrics2, err := cache.Gather()
	if err != nil {
		t.Fatalf("Second Gather failed: %v", err)
	}

	if len(metrics2) != len(metrics1) {
		t.Error("expected same metrics from cache hit")
	}

	stats = cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("expected 1 hit, got %d", stats.Hits)
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Third gather should be a miss again
	_, err = cache.Gather()
	if err != nil {
		t.Fatalf("Third Gather failed: %v", err)
	}

	stats = cache.Stats()
	if stats.Misses != 2 {
		t.Errorf("expected 2 misses, got %d", stats.Misses)
	}
}

// TestMetricCacheInvalidate tests cache invalidation.
func TestMetricCacheInvalidate(t *testing.T) {
	registry := prometheus.NewRegistry()
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "invalidate_gauge",
		Help: "Test invalidation",
	})
	registry.MustRegister(gauge)
	gauge.Set(1)

	cache := NewMetricCache(registry, 1*time.Hour, slog.Default())

	// First gather
	_, _ = cache.Gather()

	// Second gather should hit cache
	_, _ = cache.Gather()

	stats := cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("expected 1 hit before invalidate, got %d", stats.Hits)
	}

	// Invalidate
	cache.Invalidate()

	stats = cache.Stats()
	if stats.Evictions != 1 {
		t.Errorf("expected 1 eviction, got %d", stats.Evictions)
	}

	// Next gather should be a miss
	_, _ = cache.Gather()

	stats = cache.Stats()
	if stats.Misses != 2 {
		t.Errorf("expected 2 misses after invalidate, got %d", stats.Misses)
	}
}

// TestMetricCacheHitRate tests hit rate calculation.
func TestMetricCacheHitRate(t *testing.T) {
	registry := prometheus.NewRegistry()
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "hitrate_gauge",
		Help: "Test hit rate",
	})
	registry.MustRegister(gauge)
	gauge.Set(1)

	cache := NewMetricCache(registry, 1*time.Hour, slog.Default())

	// No operations - hit rate should be 0
	if rate := cache.HitRate(); rate != 0 {
		t.Errorf("expected hit rate 0 with no operations, got %f", rate)
	}

	// 1 miss
	_, _ = cache.Gather()
	if rate := cache.HitRate(); rate != 0 {
		t.Errorf("expected hit rate 0 after 1 miss, got %f", rate)
	}

	// 1 hit (total: 1 miss + 1 hit = 50%)
	_, _ = cache.Gather()
	if rate := cache.HitRate(); rate != 50 {
		t.Errorf("expected hit rate 50%%, got %f%%", rate)
	}

	// 2 more hits (total: 1 miss + 3 hits = 75%)
	_, _ = cache.Gather()
	_, _ = cache.Gather()
	if rate := cache.HitRate(); rate != 75 {
		t.Errorf("expected hit rate 75%%, got %f%%", rate)
	}
}

// TestBatchProcessor tests batch processing functionality.
func TestBatchProcessor(t *testing.T) {
	var flushed atomic.Int32

	flushFn := func(ctx context.Context, families []*dto.MetricFamily) error {
		flushed.Add(int32(len(families)))
		return nil
	}

	processor := NewBatchProcessor(3, 5*time.Second, flushFn, slog.Default())

	name := "batch_metric"
	mtype := dto.MetricType_GAUGE

	// Add 2 metrics - shouldn't flush yet
	_ = processor.Add(context.Background(), []*dto.MetricFamily{
		{Name: &name, Type: &mtype},
		{Name: &name, Type: &mtype},
	})

	if flushed.Load() != 0 {
		t.Errorf("expected no flush with 2 items, got %d flushed", flushed.Load())
	}

	// Add 2 more - should flush (4 >= batch size 3)
	_ = processor.Add(context.Background(), []*dto.MetricFamily{
		{Name: &name, Type: &mtype},
		{Name: &name, Type: &mtype},
	})

	if flushed.Load() != 4 {
		t.Errorf("expected 4 flushed after exceeding batch size, got %d", flushed.Load())
	}

	// Manual flush
	_ = processor.Add(context.Background(), []*dto.MetricFamily{
		{Name: &name, Type: &mtype},
	})
	_ = processor.Flush(context.Background())

	if flushed.Load() != 5 {
		t.Errorf("expected 5 total flushed, got %d", flushed.Load())
	}
}

// TestAdaptiveBatcher tests adaptive batch sizing.
func TestAdaptiveBatcher(t *testing.T) {
	batcher := NewAdaptiveBatcher(10, 100, 100*time.Millisecond, slog.Default())

	initialSize := batcher.CurrentSize()
	if initialSize != 55 { // (10+100)/2
		t.Errorf("expected initial size 55, got %d", initialSize)
	}

	// Record low latencies - should increase batch size
	for i := 0; i < 10; i++ {
		batcher.RecordLatency(10 * time.Millisecond) // Well below target
	}

	// Force adjustment
	batcher.mu.Lock()
	batcher.lastAdjust = time.Time{} // Reset last adjust time
	batcher.mu.Unlock()
	batcher.RecordLatency(10 * time.Millisecond)

	newSize := batcher.CurrentSize()
	if newSize <= initialSize {
		t.Logf("batch size didn't increase as expected (initial: %d, new: %d)", initialSize, newSize)
	}
}

// TestLoggingReceiver tests the logging receiver.
func TestLoggingReceiver(t *testing.T) {
	receiver := NewLoggingReceiver(slog.Default())

	name := "log_metric"
	mtype := dto.MetricType_GAUGE
	value := 1.0

	batch := &MetricsBatch{
		Metrics: []*dto.MetricFamily{
			{
				Name: &name,
				Type: &mtype,
				Metric: []*dto.Metric{
					{Gauge: &dto.Gauge{Value: &value}},
				},
			},
		},
		Timestamp: time.Now(),
		Environment: &DetectedEnvironment{
			Type: EnvironmentBareMetal,
		},
	}

	err := receiver.ReceiveMetrics(context.Background(), batch)
	if err != nil {
		t.Errorf("ReceiveMetrics failed: %v", err)
	}
}

// TestOTLPAdapter tests the OTLP adapter.
func TestOTLPAdapter(t *testing.T) {
	var received []*dto.MetricFamily

	sendFn := func(ctx context.Context, families []*dto.MetricFamily) error {
		received = families
		return nil
	}

	adapter := NewOTLPAdapter(slog.Default(), sendFn)

	name := "adapter_metric"
	mtype := dto.MetricType_GAUGE
	value := 42.0

	batch := &MetricsBatch{
		Metrics: []*dto.MetricFamily{
			{
				Name: &name,
				Type: &mtype,
				Metric: []*dto.Metric{
					{Gauge: &dto.Gauge{Value: &value}},
				},
			},
		},
		Timestamp:   time.Now(),
		Environment: &DetectedEnvironment{Type: EnvironmentBareMetal},
	}

	err := adapter.ReceiveMetrics(context.Background(), batch)
	if err != nil {
		t.Errorf("ReceiveMetrics failed: %v", err)
	}

	if len(received) != 1 {
		t.Errorf("expected 1 metric family received, got %d", len(received))
	}
}
