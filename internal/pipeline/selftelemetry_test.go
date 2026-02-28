package pipeline

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSelfTelemetryCreation(t *testing.T) {
	config := DefaultSelfTelemetryConfig()
	st, err := NewSelfTelemetry(config, nil)
	if err != nil {
		t.Fatalf("NewSelfTelemetry failed: %v", err)
	}
	
	if st.metrics == nil {
		t.Error("metrics should not be nil")
	}
}

func TestSelfTelemetryHealthEndpoint(t *testing.T) {
	config := DefaultSelfTelemetryConfig()
	st, err := NewSelfTelemetry(config, nil)
	if err != nil {
		t.Fatalf("NewSelfTelemetry failed: %v", err)
	}

	// Test healthy state.
	st.SetHealthy(true)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	st.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "healthy") {
		t.Errorf("expected healthy in body, got %s", string(body))
	}

	// Test unhealthy state.
	st.SetHealthy(false)
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	st.mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestSelfTelemetryReadyEndpoint(t *testing.T) {
	config := DefaultSelfTelemetryConfig()
	st, err := NewSelfTelemetry(config, nil)
	if err != nil {
		t.Fatalf("NewSelfTelemetry failed: %v", err)
	}

	// Test not ready state (default).
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	st.mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	// Test ready state.
	st.SetReady(true)
	req = httptest.NewRequest(http.MethodGet, "/ready", nil)
	w = httptest.NewRecorder()
	st.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestSelfTelemetryMetricsEndpoint(t *testing.T) {
	config := DefaultSelfTelemetryConfig()
	st, err := NewSelfTelemetry(config, nil)
	if err != nil {
		t.Fatalf("NewSelfTelemetry failed: %v", err)
	}

	// Record some metrics.
	st.metrics.ObserveSignalCollected("trace", "ebpf_tracer")
	st.metrics.ObserveExportSuccess("localhost:4317", "trace")
	st.metrics.SetQueueSize("trace", 100)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	st.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	bodyStr := string(body)

	// Check for expected metrics.
	expectedMetrics := []string{
		"telegen_signals_collected_total",
		"telegen_export_success_total",
		"telegen_queue_size",
	}
	for _, m := range expectedMetrics {
		if !strings.Contains(bodyStr, m) {
			t.Errorf("expected metric %s in body", m)
		}
	}
}

func TestSelfTelemetryInfoEndpoint(t *testing.T) {
	config := DefaultSelfTelemetryConfig()
	st, err := NewSelfTelemetry(config, nil)
	if err != nil {
		t.Fatalf("NewSelfTelemetry failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	w := httptest.NewRecorder()
	st.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "3.0.0") {
		t.Errorf("expected version in body, got %s", string(body))
	}
}

func TestV3MetricsRecording(t *testing.T) {
	config := DefaultSelfTelemetryConfig()
	st, err := NewSelfTelemetry(config, nil)
	if err != nil {
		t.Fatalf("NewSelfTelemetry failed: %v", err)
	}

	m := st.Metrics()

	// Test all metric recording methods.
	tests := []struct {
		name string
		fn   func()
	}{
		{"SignalCollected", func() { m.ObserveSignalCollected("trace", "test") }},
		{"SignalDropped", func() { m.ObserveSignalDropped("trace", "overflow") }},
		{"ExportSuccess", func() { m.ObserveExportSuccess("endpoint", "trace") }},
		{"ExportFailure", func() { m.ObserveExportFailure("endpoint", "trace") }},
		{"ExportLatency", func() { m.ObserveExportLatency("endpoint", "trace", 100*time.Millisecond) }},
		{"QueueSize", func() { m.SetQueueSize("trace", 50) }},
		{"QueueLatency", func() { m.ObserveQueueLatency("trace", 10*time.Millisecond) }},
		{"CircuitBreakerState", func() { m.SetCircuitBreakerState("endpoint", 1) }},
		{"CircuitBreakerTrip", func() { m.ObserveCircuitBreakerTrip("endpoint") }},
		{"CircuitBreakerRecover", func() { m.ObserveCircuitBreakerRecover("endpoint") }},
		{"PipelineUptime", func() { m.SetPipelineUptime("v3", 5*time.Minute) }},
		{"ProcessingLatency", func() { m.ObserveProcessingLatency("normalize", 1*time.Millisecond) }},
		{"EnrichmentLatency", func() { m.ObserveEnrichmentLatency("cloud", 2*time.Millisecond) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic.
			tt.fn()
		})
	}
}

func TestSelfTelemetryServer(t *testing.T) {
	config := DefaultSelfTelemetryConfig()
	config.ListenAddress = ":0" // Let OS pick a port.
	
	st, err := NewSelfTelemetry(config, nil)
	if err != nil {
		t.Fatalf("NewSelfTelemetry failed: %v", err)
	}

	ctx := context.Background()
	
	// Note: Start uses a listener with the config address.
	// For testing, we'll just verify the server can be created and shutdown.
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	
	err = st.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown should succeed when server not started: %v", err)
	}
}

func TestDefaultSelfTelemetryConfig(t *testing.T) {
	config := DefaultSelfTelemetryConfig()

	if !config.Enabled {
		t.Error("expected enabled by default")
	}
	if config.ListenAddress != ":8888" {
		t.Errorf("expected :8888, got %s", config.ListenAddress)
	}
	if config.MetricsPath != "/metrics" {
		t.Errorf("expected /metrics, got %s", config.MetricsPath)
	}
	if config.HealthPath != "/health" {
		t.Errorf("expected /health, got %s", config.HealthPath)
	}
	if config.ReadyPath != "/ready" {
		t.Errorf("expected /ready, got %s", config.ReadyPath)
	}
	if config.Namespace != "telegen" {
		t.Errorf("expected telegen, got %s", config.Namespace)
	}
}
