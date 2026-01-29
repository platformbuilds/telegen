// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// OTLPExporter exports SNMP metrics via OTLP
type OTLPExporter struct {
	config   OTLPOutputConfig
	log      *slog.Logger
	exporter sdkmetric.Exporter
	provider *sdkmetric.MeterProvider
	meter    metric.Meter

	// Metric instruments
	gauges   map[string]metric.Float64Gauge
	counters map[string]metric.Float64Counter

	queue   chan []Metric
	stopCh  chan struct{}
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// NewOTLPExporter creates a new OTLP exporter
func NewOTLPExporter(cfg OTLPOutputConfig, log *slog.Logger) (*OTLPExporter, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "otlp-exporter")

	return &OTLPExporter{
		config:   cfg,
		log:      log,
		gauges:   make(map[string]metric.Float64Gauge),
		counters: make(map[string]metric.Float64Counter),
		queue:    make(chan []Metric, 10000),
		stopCh:   make(chan struct{}),
	}, nil
}

// Start starts the OTLP exporter
func (e *OTLPExporter) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	e.log.Info("starting OTLP exporter", "endpoint", e.config.Endpoint, "protocol", e.config.Protocol)

	// Create exporter based on protocol
	var err error
	switch e.config.Protocol {
	case "grpc":
		err = e.createGRPCExporter(ctx)
	case "http":
		err = e.createHTTPExporter(ctx)
	default:
		err = e.createGRPCExporter(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("telegen-snmp"),
			semconv.ServiceVersion("2.0.0"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create meter provider
	e.provider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(e.exporter,
			sdkmetric.WithInterval(10*time.Second),
		)),
	)

	e.meter = e.provider.Meter("telegen.snmp")

	// Start worker
	e.wg.Add(1)
	go e.worker(ctx)

	e.running = true
	return nil
}

// Stop stops the OTLP exporter
func (e *OTLPExporter) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	e.log.Info("stopping OTLP exporter")

	close(e.stopCh)
	e.wg.Wait()

	if e.provider != nil {
		if err := e.provider.Shutdown(ctx); err != nil {
			e.log.Warn("error shutting down meter provider", "error", err)
		}
	}

	e.running = false
	return nil
}

// Export queues metrics for export
func (e *OTLPExporter) Export(ctx context.Context, metrics []Metric) error {
	select {
	case e.queue <- metrics:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("OTLP export queue full")
	}
}

// createGRPCExporter creates a gRPC OTLP exporter
func (e *OTLPExporter) createGRPCExporter(ctx context.Context) error {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(e.config.Endpoint),
	}

	if e.config.Insecure {
		opts = append(opts, otlpmetricgrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return err
	}

	e.exporter = exporter
	return nil
}

// createHTTPExporter creates an HTTP OTLP exporter
func (e *OTLPExporter) createHTTPExporter(ctx context.Context) error {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(e.config.Endpoint),
	}

	if e.config.Insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return err
	}

	e.exporter = exporter
	return nil
}

// worker processes the metric queue
func (e *OTLPExporter) worker(ctx context.Context) {
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case metrics := <-e.queue:
			e.recordMetrics(ctx, metrics)
		}
	}
}

// recordMetrics records metrics using the OTel SDK
func (e *OTLPExporter) recordMetrics(ctx context.Context, metrics []Metric) {
	for _, m := range metrics {
		attrs := e.buildAttributes(m.Labels)

		switch m.Type {
		case MetricTypeCounter:
			counter, err := e.getOrCreateCounter(m.Name, m.Help)
			if err != nil {
				e.log.Debug("failed to create counter", "name", m.Name, "error", err)
				continue
			}
			counter.Add(ctx, m.Value, metric.WithAttributes(attrs...))

		case MetricTypeGauge:
			gauge, err := e.getOrCreateGauge(m.Name, m.Help)
			if err != nil {
				e.log.Debug("failed to create gauge", "name", m.Name, "error", err)
				continue
			}
			gauge.Record(ctx, m.Value, metric.WithAttributes(attrs...))

		default:
			// Default to gauge
			gauge, err := e.getOrCreateGauge(m.Name, m.Help)
			if err != nil {
				continue
			}
			gauge.Record(ctx, m.Value, metric.WithAttributes(attrs...))
		}
	}
}

// getOrCreateGauge gets or creates a gauge instrument
func (e *OTLPExporter) getOrCreateGauge(name, description string) (metric.Float64Gauge, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if gauge, ok := e.gauges[name]; ok {
		return gauge, nil
	}

	gauge, err := e.meter.Float64Gauge(name, metric.WithDescription(description))
	if err != nil {
		return nil, err
	}

	e.gauges[name] = gauge
	return gauge, nil
}

// getOrCreateCounter gets or creates a counter instrument
func (e *OTLPExporter) getOrCreateCounter(name, description string) (metric.Float64Counter, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if counter, ok := e.counters[name]; ok {
		return counter, nil
	}

	counter, err := e.meter.Float64Counter(name, metric.WithDescription(description))
	if err != nil {
		return nil, err
	}

	e.counters[name] = counter
	return counter, nil
}

// buildAttributes converts labels to OTel attributes
func (e *OTLPExporter) buildAttributes(labels map[string]string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(labels))
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	return attrs
}

// ExportDirect exports metrics directly without using the SDK
func (e *OTLPExporter) ExportDirect(ctx context.Context, metrics []Metric) error {
	if e.exporter == nil {
		return fmt.Errorf("exporter not initialized")
	}

	// Build metric data
	scopeMetrics := make([]metricdata.ScopeMetrics, 0)
	gaugeData := make([]metricdata.DataPoint[float64], 0)
	counterData := make([]metricdata.DataPoint[float64], 0)

	for _, m := range metrics {
		attrs := attribute.NewSet(e.buildAttributes(m.Labels)...)
		dp := metricdata.DataPoint[float64]{
			Attributes: attrs,
			Time:       m.Timestamp,
			Value:      m.Value,
		}

		switch m.Type {
		case MetricTypeCounter:
			counterData = append(counterData, dp)
		default:
			gaugeData = append(gaugeData, dp)
		}
	}

	// Create scope metrics
	if len(gaugeData) > 0 || len(counterData) > 0 {
		sm := metricdata.ScopeMetrics{
			Metrics: []metricdata.Metrics{},
		}

		if len(gaugeData) > 0 {
			sm.Metrics = append(sm.Metrics, metricdata.Metrics{
				Name:        "snmp_gauge",
				Description: "SNMP gauge metrics",
				Data:        metricdata.Gauge[float64]{DataPoints: gaugeData},
			})
		}

		if len(counterData) > 0 {
			sm.Metrics = append(sm.Metrics, metricdata.Metrics{
				Name:        "snmp_counter",
				Description: "SNMP counter metrics",
				Data:        metricdata.Sum[float64]{DataPoints: counterData, IsMonotonic: true},
			})
		}

		scopeMetrics = append(scopeMetrics, sm)
	}

	rm := &metricdata.ResourceMetrics{
		ScopeMetrics: scopeMetrics,
	}

	return e.exporter.Export(ctx, rm)
}
