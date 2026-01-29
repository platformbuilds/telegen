// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusEndpoint exposes SNMP metrics via HTTP for Prometheus scraping
type PrometheusEndpoint struct {
	config   PrometheusOutputConfig
	log      *slog.Logger
	server   *http.Server
	registry *prometheus.Registry

	// Metric storage
	mu       sync.RWMutex
	gauges   map[string]*prometheus.GaugeVec
	counters map[string]*prometheus.CounterVec
	metrics  []Metric

	running bool
}

// NewPrometheusEndpoint creates a new Prometheus endpoint
func NewPrometheusEndpoint(cfg PrometheusOutputConfig, log *slog.Logger) (*PrometheusEndpoint, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "prometheus-endpoint")

	return &PrometheusEndpoint{
		config:   cfg,
		log:      log,
		registry: prometheus.NewRegistry(),
		gauges:   make(map[string]*prometheus.GaugeVec),
		counters: make(map[string]*prometheus.CounterVec),
		metrics:  make([]Metric, 0),
	}, nil
}

// Start starts the Prometheus HTTP endpoint
func (p *PrometheusEndpoint) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	p.log.Info("starting Prometheus endpoint", "address", p.config.ListenAddress, "path", p.config.Path)

	// Create HTTP mux
	mux := http.NewServeMux()

	// Add metrics handler
	path := p.config.Path
	if path == "" {
		path = "/metrics"
	}
	mux.Handle(path, promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	// Add health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create server
	p.server = &http.Server{
		Addr:    p.config.ListenAddress,
		Handler: mux,
	}

	// Start server in goroutine
	go func() {
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.log.Error("HTTP server error", "error", err)
		}
	}()

	p.running = true
	return nil
}

// Stop stops the Prometheus endpoint
func (p *PrometheusEndpoint) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.log.Info("stopping Prometheus endpoint")

	if p.server != nil {
		if err := p.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown HTTP server: %w", err)
		}
	}

	p.running = false
	return nil
}

// Update updates the metrics exposed by the endpoint
func (p *PrometheusEndpoint) Update(metrics []Metric) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, m := range metrics {
		switch m.Type {
		case MetricTypeCounter:
			p.updateCounter(m)
		default:
			p.updateGauge(m)
		}
	}
}

// updateGauge updates or creates a gauge metric
func (p *PrometheusEndpoint) updateGauge(m Metric) {
	labelNames := p.getLabelNames(m.Labels)
	key := p.metricKey(m.Name, labelNames)

	gauge, ok := p.gauges[key]
	if !ok {
		// Create new gauge
		gauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: m.Name,
			Help: m.Help,
		}, labelNames)

		if err := p.registry.Register(gauge); err != nil {
			// Metric might already exist with different labels
			p.log.Debug("failed to register gauge", "name", m.Name, "error", err)
			return
		}
		p.gauges[key] = gauge
	}

	// Set value
	labelValues := p.getLabelValues(m.Labels, labelNames)
	gauge.WithLabelValues(labelValues...).Set(m.Value)
}

// updateCounter updates or creates a counter metric
func (p *PrometheusEndpoint) updateCounter(m Metric) {
	labelNames := p.getLabelNames(m.Labels)
	key := p.metricKey(m.Name, labelNames)

	counter, ok := p.counters[key]
	if !ok {
		// Create new counter
		counter = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: m.Name,
			Help: m.Help,
		}, labelNames)

		if err := p.registry.Register(counter); err != nil {
			p.log.Debug("failed to register counter", "name", m.Name, "error", err)
			return
		}
		p.counters[key] = counter
	}

	// Add value (counters can only increase)
	labelValues := p.getLabelValues(m.Labels, labelNames)
	counter.WithLabelValues(labelValues...).Add(m.Value)
}

// getLabelNames extracts sorted label names from a label map
func (p *PrometheusEndpoint) getLabelNames(labels map[string]string) []string {
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// getLabelValues extracts label values in the same order as names
func (p *PrometheusEndpoint) getLabelValues(labels map[string]string, names []string) []string {
	values := make([]string, len(names))
	for i, name := range names {
		values[i] = labels[name]
	}
	return values
}

// metricKey creates a unique key for a metric with its label names
func (p *PrometheusEndpoint) metricKey(name string, labelNames []string) string {
	return name + "|" + strings.Join(labelNames, ",")
}

// Reset clears all registered metrics
func (p *PrometheusEndpoint) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Unregister all metrics
	for _, gauge := range p.gauges {
		p.registry.Unregister(gauge)
	}
	for _, counter := range p.counters {
		p.registry.Unregister(counter)
	}

	// Clear maps
	p.gauges = make(map[string]*prometheus.GaugeVec)
	p.counters = make(map[string]*prometheus.CounterVec)
}
