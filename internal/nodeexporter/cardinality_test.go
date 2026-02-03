// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package nodeexporter

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCardinalityFilter(t *testing.T) {
	logger := slog.Default()

	// Create a mock handler that returns Prometheus metrics
	mockMetrics := `# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 123456.78
node_cpu_seconds_total{cpu="0",mode="user"} 5678.9
node_cpu_seconds_total{cpu="1",mode="idle"} 123456.78
node_cpu_seconds_total{cpu="1",mode="user"} 5678.9
# HELP node_memory_MemTotal_bytes Memory information field MemTotal_bytes.
# TYPE node_memory_MemTotal_bytes gauge
node_memory_MemTotal_bytes 16000000000
# HELP node_disk_read_bytes_total The total number of bytes read successfully.
# TYPE node_disk_read_bytes_total counter
node_disk_read_bytes_total{device="sda"} 1234567890
`
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockMetrics))
	})

	t.Run("filter disabled passes through", func(t *testing.T) {
		config := CardinalityConfig{
			Enabled: false,
		}

		filter, err := NewCardinalityFilter(mockHandler, config, logger)
		if err != nil {
			t.Fatalf("failed to create filter: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		filter.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "node_cpu_seconds_total") {
			t.Error("expected node_cpu_seconds_total in response")
		}
	})

	t.Run("exclude metrics pattern", func(t *testing.T) {
		config := CardinalityConfig{
			Enabled:        true,
			ExcludeMetrics: []string{"^node_disk_.*"},
		}

		filter, err := NewCardinalityFilter(mockHandler, config, logger)
		if err != nil {
			t.Fatalf("failed to create filter: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		filter.ServeHTTP(rec, req)

		body := rec.Body.String()
		if strings.Contains(body, "node_disk_read_bytes_total") {
			t.Error("expected node_disk_read_bytes_total to be filtered out")
		}
		if !strings.Contains(body, "node_cpu_seconds_total") {
			t.Error("expected node_cpu_seconds_total to remain")
		}
		if !strings.Contains(body, "node_memory_MemTotal_bytes") {
			t.Error("expected node_memory_MemTotal_bytes to remain")
		}
	})

	t.Run("include metrics pattern", func(t *testing.T) {
		config := CardinalityConfig{
			Enabled:        true,
			IncludeMetrics: []string{"^node_cpu_.*"},
		}

		filter, err := NewCardinalityFilter(mockHandler, config, logger)
		if err != nil {
			t.Fatalf("failed to create filter: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		filter.ServeHTTP(rec, req)

		body := rec.Body.String()
		if !strings.Contains(body, "node_cpu_seconds_total") {
			t.Error("expected node_cpu_seconds_total to remain")
		}
		if strings.Contains(body, "node_memory_MemTotal_bytes") {
			t.Error("expected node_memory_MemTotal_bytes to be filtered out")
		}
		if strings.Contains(body, "node_disk_read_bytes_total") {
			t.Error("expected node_disk_read_bytes_total to be filtered out")
		}
	})

	t.Run("drop labels", func(t *testing.T) {
		config := CardinalityConfig{
			Enabled:    true,
			DropLabels: []string{"mode"},
		}

		filter, err := NewCardinalityFilter(mockHandler, config, logger)
		if err != nil {
			t.Fatalf("failed to create filter: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		filter.ServeHTTP(rec, req)

		body := rec.Body.String()
		if strings.Contains(body, "mode=") {
			t.Error("expected 'mode' label to be dropped")
		}
		if !strings.Contains(body, "cpu=") {
			t.Error("expected 'cpu' label to remain")
		}
	})

	t.Run("max metrics limit", func(t *testing.T) {
		config := CardinalityConfig{
			Enabled:    true,
			MaxMetrics: 2, // Only allow 2 metrics total
		}

		filter, err := NewCardinalityFilter(mockHandler, config, logger)
		if err != nil {
			t.Fatalf("failed to create filter: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		filter.ServeHTTP(rec, req)

		// Count the number of metric lines (excluding comments)
		body := rec.Body.String()
		lines := strings.Split(body, "\n")
		metricCount := 0
		for _, line := range lines {
			if line != "" && !strings.HasPrefix(line, "#") {
				metricCount++
			}
		}

		if metricCount > 2 {
			t.Errorf("expected at most 2 metrics, got %d", metricCount)
		}
	})
}

func TestCardinalityFilterParseMetrics(t *testing.T) {
	logger := slog.Default()

	config := CardinalityConfig{
		Enabled: true,
	}

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	filter, err := NewCardinalityFilter(mockHandler, config, logger)
	if err != nil {
		t.Fatalf("failed to create filter: %v", err)
	}

	t.Run("parse empty metrics", func(t *testing.T) {
		buf := bytes.NewBufferString("")
		result, err := filter.filterMetrics(buf, "text/plain")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected empty result, got %d bytes", len(result))
		}
	})
}
