// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package storage

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
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/platformbuilds/telegen/internal/storagedef"
)

// OTLPExporter exports storage metrics via OTLP
type OTLPExporter struct {
	config   storagedef.OTLPConfig
	log      *slog.Logger
	exporter sdkmetric.Exporter
	provider *sdkmetric.MeterProvider
	meter    metric.Meter

	// Metric instruments cache
	gauges   map[string]metric.Float64Gauge
	counters map[string]metric.Float64Counter

	queue   chan []storagedef.Metric
	stopCh  chan struct{}
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// NewOTLPExporter creates a new OTLP exporter for storage metrics
func NewOTLPExporter(cfg storagedef.OTLPConfig, log *slog.Logger) (*OTLPExporter, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "storage-otlp-exporter")

	return &OTLPExporter{
		config:   cfg,
		log:      log,
		gauges:   make(map[string]metric.Float64Gauge),
		counters: make(map[string]metric.Float64Counter),
		queue:    make(chan []storagedef.Metric, 10000),
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

	e.log.Info("starting storage OTLP exporter",
		"endpoint", e.config.Endpoint,
		"protocol", e.config.Protocol,
	)

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
			semconv.ServiceName("telegen-storage"),
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

	e.meter = e.provider.Meter("telegen.storage")

	// Start worker
	e.wg.Add(1)
	go e.worker(ctx)

	e.running = true
	e.log.Info("storage OTLP exporter started")
	return nil
}

// Stop stops the OTLP exporter
func (e *OTLPExporter) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	e.log.Info("stopping storage OTLP exporter")

	close(e.stopCh)
	e.wg.Wait()

	if e.provider != nil {
		if err := e.provider.Shutdown(ctx); err != nil {
			e.log.Warn("error shutting down meter provider", "error", err)
		}
	}

	e.running = false
	e.log.Info("storage OTLP exporter stopped")
	return nil
}

// Export queues metrics for export
func (e *OTLPExporter) Export(ctx context.Context, metrics []storagedef.Metric) error {
	select {
	case e.queue <- metrics:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("storage OTLP export queue full")
	}
}

// createGRPCExporter creates a gRPC OTLP exporter
func (e *OTLPExporter) createGRPCExporter(ctx context.Context) error {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(e.config.Endpoint),
	}

	// Handle TLS
	if !e.config.TLS.Enabled {
		opts = append(opts, otlpmetricgrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}

	// Add compression if configured
	if e.config.Compression == "gzip" {
		opts = append(opts, otlpmetricgrpc.WithCompressor("gzip"))
	}

	// Add headers if configured
	if len(e.config.Headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(e.config.Headers))
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create gRPC exporter: %w", err)
	}

	e.exporter = exporter
	return nil
}

// createHTTPExporter creates an HTTP OTLP exporter
func (e *OTLPExporter) createHTTPExporter(ctx context.Context) error {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(e.config.Endpoint),
	}

	// Handle TLS
	if !e.config.TLS.Enabled {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	// Add compression if configured
	if e.config.Compression == "gzip" {
		opts = append(opts, otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression))
	}

	// Add headers if configured
	if len(e.config.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(e.config.Headers))
	}

	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create HTTP exporter: %w", err)
	}

	e.exporter = exporter
	return nil
}

// worker processes the metric export queue
func (e *OTLPExporter) worker(ctx context.Context) {
	defer e.wg.Done()

	for {
		select {
		case <-e.stopCh:
			// Drain remaining metrics
			for {
				select {
				case metrics := <-e.queue:
					e.processMetrics(ctx, metrics)
				default:
					return
				}
			}
		case <-ctx.Done():
			return
		case metrics := <-e.queue:
			e.processMetrics(ctx, metrics)
		}
	}
}

// processMetrics records metrics via OTEL
func (e *OTLPExporter) processMetrics(ctx context.Context, metrics []storagedef.Metric) {
	for _, m := range metrics {
		if err := e.recordMetric(ctx, m); err != nil {
			e.log.Debug("failed to record metric",
				"name", m.Name,
				"error", err,
			)
		}
	}
}

// recordMetric records a single metric
func (e *OTLPExporter) recordMetric(ctx context.Context, m storagedef.Metric) error {
	// Build attributes from labels
	attrs := make([]attribute.KeyValue, 0, len(m.Labels))
	for k, v := range m.Labels {
		attrs = append(attrs, attribute.String(k, v))
	}

	switch m.Type {
	case storagedef.MetricTypeGauge:
		gauge, err := e.getOrCreateGauge(m.Name, m.Help)
		if err != nil {
			return err
		}
		gauge.Record(ctx, m.Value, metric.WithAttributes(attrs...))

	case storagedef.MetricTypeCounter:
		counter, err := e.getOrCreateCounter(m.Name, m.Help)
		if err != nil {
			return err
		}
		counter.Add(ctx, m.Value, metric.WithAttributes(attrs...))

	default:
		// Default to gauge
		gauge, err := e.getOrCreateGauge(m.Name, m.Help)
		if err != nil {
			return err
		}
		gauge.Record(ctx, m.Value, metric.WithAttributes(attrs...))
	}

	return nil
}

// getOrCreateGauge returns or creates a gauge instrument
func (e *OTLPExporter) getOrCreateGauge(name, description string) (metric.Float64Gauge, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if gauge, ok := e.gauges[name]; ok {
		return gauge, nil
	}

	gauge, err := e.meter.Float64Gauge(name,
		metric.WithDescription(description),
	)
	if err != nil {
		return nil, err
	}

	e.gauges[name] = gauge
	return gauge, nil
}

// getOrCreateCounter returns or creates a counter instrument
func (e *OTLPExporter) getOrCreateCounter(name, description string) (metric.Float64Counter, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if counter, ok := e.counters[name]; ok {
		return counter, nil
	}

	counter, err := e.meter.Float64Counter(name,
		metric.WithDescription(description),
	)
	if err != nil {
		return nil, err
	}

	e.counters[name] = counter
	return counter, nil
}
