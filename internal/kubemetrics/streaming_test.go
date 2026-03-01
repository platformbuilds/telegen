// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// MockMetricsExporter is a mock OTEL metrics exporter for testing
type MockMetricsExporter struct {
	exported []*metricdata.ResourceMetrics
	err      error
}

func (m *MockMetricsExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if m.err != nil {
		return m.err
	}
	m.exported = append(m.exported, rm)
	return nil
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

func TestOTLPBridgeUnitGuessing(t *testing.T) {
	testCases := []struct {
		name     string
		expected string
	}{
		{"container_memory_usage_bytes", "By"},
		{"container_cpu_usage_seconds_total", "s"},
		{"kube_pod_info", "1"},
		{"request_duration_seconds", "s"},
		{"http_requests_total", "1"},
	}

	for _, tc := range testCases {
		unit := guessUnit(tc.name)
		if unit != tc.expected {
			t.Errorf("guessUnit(%s): expected %s, got %s", tc.name, tc.expected, unit)
		}
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
