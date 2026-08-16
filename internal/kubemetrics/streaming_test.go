// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// MockMetricsExporter is a mock OTEL metrics exporter for testing.
// It is safe for concurrent use because the streaming exporter calls Export
// from a background goroutine.
type MockMetricsExporter struct {
	mu       sync.Mutex
	exported []*metricdata.ResourceMetrics
	err      error
}

func (m *MockMetricsExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.exported = append(m.exported, rm)
	return nil
}

// Count returns how many times Export has been called.
func (m *MockMetricsExporter) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.exported)
}

func (m *MockMetricsExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (m *MockMetricsExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}

func (m *MockMetricsExporter) ForceFlush(ctx context.Context) error {
	return nil
}

func (m *MockMetricsExporter) Shutdown(ctx context.Context) error {
	return nil
}

// MockLogsExporter is a mock logs exporter for testing
type MockLogsExporter struct {
	exported []OTLPLogRecord
	err      error
}

func (m *MockLogsExporter) Export(ctx context.Context, logs []OTLPLogRecord) error {
	if m.err != nil {
		return m.err
	}
	m.exported = append(m.exported, logs...)
	return nil
}

func (m *MockLogsExporter) Shutdown(ctx context.Context) error {
	return nil
}

func TestStreamingConfig(t *testing.T) {
	cfg := DefaultStreamingConfig()

	if cfg.Enabled {
		t.Error("streaming should be disabled by default")
	}
	if cfg.Interval != 15*time.Second {
		t.Errorf("expected 15s interval, got %v", cfg.Interval)
	}
	if cfg.BatchSize != 1000 {
		t.Errorf("expected 1000 batch size, got %d", cfg.BatchSize)
	}
	if !cfg.UseOTLP {
		t.Error("OTLP should be enabled by default")
	}
	if !cfg.IncludeSignalMetadata {
		t.Error("signal metadata should be enabled by default")
	}
}

func TestLogsStreamingConfig(t *testing.T) {
	cfg := DefaultLogsStreamingConfig()

	if cfg.Enabled {
		t.Error("logs streaming should be disabled by default")
	}
	if cfg.BufferSize != 1000 {
		t.Errorf("expected 1000 buffer size, got %d", cfg.BufferSize)
	}
	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("expected 5s flush interval, got %v", cfg.FlushInterval)
	}
	if len(cfg.EventTypes) != 2 {
		t.Errorf("expected 2 event types, got %d", len(cfg.EventTypes))
	}
}

func TestSignalMetadataDefinitions(t *testing.T) {
	// Test that all expected metadata is defined
	expectedPrefixes := []string{
		"kube_pod", "kube_deployment", "kube_node",
		"container_cpu", "container_memory", "container_network",
		"kube_event",
	}

	for _, prefix := range expectedPrefixes {
		meta, ok := SignalMetadataDefinitions[prefix]
		if !ok {
			t.Errorf("missing metadata for prefix: %s", prefix)
			continue
		}

		if meta.Category == "" {
			t.Errorf("empty category for prefix: %s", prefix)
		}
		if meta.SourceModule == "" {
			t.Errorf("empty source module for prefix: %s", prefix)
		}
		if meta.CollectorType == "" {
			t.Errorf("empty collector type for prefix: %s", prefix)
		}
	}
}

func TestMetadataProvider(t *testing.T) {
	cfg := sigdef.DefaultMetadataFieldsConfig()
	provider := NewMetadataProvider(cfg, true)

	// Test known prefix
	meta := provider.GetMetadata("kube_pod")
	if meta == nil {
		t.Fatal("expected metadata for kube_pod")
	}
	if meta.Category != "Kubernetes State" {
		t.Errorf("expected 'Kubernetes State', got '%s'", meta.Category)
	}

	// Test attributes generation
	attrs := provider.GetAttributes("kube_pod")
	if len(attrs) == 0 {
		t.Error("expected attributes for kube_pod")
	}

	// Verify expected attributes
	hasCategory := false
	for _, attr := range attrs {
		if string(attr.Key) == sigdef.AttrSignalCategory {
			hasCategory = true
			if attr.Value.AsString() != "Kubernetes State" {
				t.Errorf("expected 'Kubernetes State', got '%s'", attr.Value.AsString())
			}
		}
	}
	if !hasCategory {
		t.Error("missing telegen.signal.category attribute")
	}

	// Test disabled provider
	disabledProvider := NewMetadataProvider(cfg, false)
	if disabledProvider.GetMetadata("kube_pod") != nil {
		t.Error("disabled provider should return nil metadata")
	}
}

func TestGetMetadataBySignalType(t *testing.T) {
	metricsMetadata := GetMetadataBySignalType(sigdef.SignalMetrics)
	if len(metricsMetadata) == 0 {
		t.Error("expected metrics metadata")
	}

	logsMetadata := GetMetadataBySignalType(sigdef.SignalLogs)
	if len(logsMetadata) == 0 {
		t.Error("expected logs metadata")
	}

	// Verify logs metadata is for kube_event
	for _, meta := range logsMetadata {
		if meta.Category != "Kubernetes Events" {
			t.Errorf("expected 'Kubernetes Events' category, got '%s'", meta.Category)
		}
	}
}

func TestGetMetadataByCategory(t *testing.T) {
	kubeState := GetMetadataByCategory("Kubernetes State")
	if len(kubeState) == 0 {
		t.Error("expected Kubernetes State metadata")
	}

	containerMetrics := GetMetadataByCategory("Container Metrics")
	if len(containerMetrics) == 0 {
		t.Error("expected Container Metrics metadata")
	}
}

func TestGetMetricPrefix(t *testing.T) {
	testCases := []struct {
		name     string
		expected string
	}{
		{"kube_pod_info", "kube_pod"},
		{"kube_pod_container_status_ready", "kube_pod"},
		{"kube_deployment_replicas", "kube_deployment"},
		{"container_cpu_usage_seconds_total", "container_cpu"},
		{"container_memory_working_set_bytes", "container_memory"},
		{"unknown_metric", ""},
	}

	for _, tc := range testCases {
		prefix := getMetricPrefix(tc.name)
		if prefix != tc.expected {
			t.Errorf("getMetricPrefix(%s): expected '%s', got '%s'", tc.name, tc.expected, prefix)
		}
	}
}

func TestOTLPLogRecord(t *testing.T) {
	record := OTLPLogRecord{
		Timestamp:         time.Now(),
		ObservedTimestamp: time.Now(),
		SeverityNumber:    9,
		SeverityText:      "INFO",
		Body:              "Test log message",
		Attributes: []attribute.KeyValue{
			attribute.String("k8s.event.reason", "Created"),
			attribute.String("k8s.namespace.name", "default"),
		},
	}

	if record.Body != "Test log message" {
		t.Error("unexpected body")
	}
	if len(record.Attributes) != 2 {
		t.Errorf("expected 2 attributes, got %d", len(record.Attributes))
	}
}

func TestCollectKubestateMetricsFromData_ConvertsKubeSeries(t *testing.T) {
	cfg := DefaultStreamingConfig()
	cfg.IncludeSignalMetadata = false

	exporter := &StreamingExporter{
		config: &cfg,
		logger: slog.Default(),
	}

	stats := map[string]interface{}{"store_count": 2}
	payload := []byte(`# HELP kube_pod_info Information about pod.
# TYPE kube_pod_info info
kube_pod_info{namespace="default",pod="demo-pod",uid="u-1"} 1
# HELP kube_pod_status_phase Pod phase.
# TYPE kube_pod_status_phase gauge
kube_pod_status_phase{namespace="default",pod="demo-pod",phase="Running"} 1
`)

	metrics := exporter.collectKubestateMetricsFromData(stats, payload, nil)
	if len(metrics) < 3 {
		t.Fatalf("expected at least 3 metrics (self + kube_*), got %d", len(metrics))
	}

	seen := map[string]metricdata.Metrics{}
	for _, metric := range metrics {
		seen[metric.Name] = metric
	}

	if _, ok := seen["kube_pod_info"]; !ok {
		t.Fatalf("expected kube_pod_info to be exported")
	}
	if _, ok := seen["kube_pod_status_phase"]; !ok {
		t.Fatalf("expected kube_pod_status_phase to be exported")
	}

	selfMetric, ok := seen["telegen_kubestate_stores_total"]
	if !ok {
		t.Fatalf("expected telegen_kubestate_stores_total self-telemetry metric")
	}

	gauge, ok := selfMetric.Data.(metricdata.Gauge[int64])
	if !ok || len(gauge.DataPoints) == 0 {
		t.Fatalf("expected self metric to be an int64 gauge with datapoints, got %T", selfMetric.Data)
	}
	if gauge.DataPoints[0].Value != 2 {
		t.Fatalf("expected store_count value 2, got %d", gauge.DataPoints[0].Value)
	}
}
