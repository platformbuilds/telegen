// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netinfra

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/netinfra/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Exporter exports network infrastructure metrics via OTLP
type Exporter struct {
	config   ExporterConfig
	log      *slog.Logger
	exporter sdkmetric.Exporter
	provider *sdkmetric.MeterProvider
	meter    metric.Meter

	// Metric instruments
	gauges   map[string]metric.Float64Gauge
	counters map[string]metric.Float64Counter

	queue   chan []*types.NetworkMetric
	stopCh  chan struct{}
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// ExporterConfig holds exporter configuration
type ExporterConfig struct {
	// Enabled controls whether OTLP export is active
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// Endpoint is the OTLP endpoint
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`
	// Protocol is grpc or http
	Protocol string `mapstructure:"protocol" yaml:"protocol"`
	// Insecure disables TLS
	Insecure bool `mapstructure:"insecure" yaml:"insecure"`
	// Headers to send with requests
	Headers map[string]string `mapstructure:"headers" yaml:"headers"`
	// BatchSize is the maximum number of metrics per batch
	BatchSize int `mapstructure:"batch_size" yaml:"batch_size"`
	// FlushInterval is how often to flush metrics
	FlushInterval time.Duration `mapstructure:"flush_interval" yaml:"flush_interval"`
}

// DefaultExporterConfig returns sensible default configuration
func DefaultExporterConfig() ExporterConfig {
	return ExporterConfig{
		Enabled:       true,
		Endpoint:      "localhost:4317",
		Protocol:      "grpc",
		Insecure:      true,
		BatchSize:     1000,
		FlushInterval: 10 * time.Second,
	}
}

// NewExporter creates a new OTLP exporter
func NewExporter(cfg ExporterConfig, log *slog.Logger) (*Exporter, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "netinfra-exporter")

	return &Exporter{
		config:   cfg,
		log:      log,
		gauges:   make(map[string]metric.Float64Gauge),
		counters: make(map[string]metric.Float64Counter),
		queue:    make(chan []*types.NetworkMetric, 10000),
		stopCh:   make(chan struct{}),
	}, nil
}

// Start starts the exporter
func (e *Exporter) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	if !e.config.Enabled {
		e.log.Info("OTLP export is disabled")
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
			semconv.ServiceName("telegen-netinfra"),
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
			sdkmetric.WithInterval(e.config.FlushInterval),
		)),
	)

	e.meter = e.provider.Meter("telegen.netinfra")

	// Start worker
	e.wg.Add(1)
	go e.worker(ctx)

	e.running = true
	return nil
}

// Stop stops the exporter
func (e *Exporter) Stop(ctx context.Context) error {
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
func (e *Exporter) Export(ctx context.Context, metrics []*types.NetworkMetric) error {
	if !e.config.Enabled {
		return nil
	}

	select {
	case e.queue <- metrics:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("export queue full")
	}
}

// createGRPCExporter creates a gRPC OTLP exporter
func (e *Exporter) createGRPCExporter(ctx context.Context) error {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(e.config.Endpoint),
	}

	if e.config.Insecure {
		opts = append(opts, otlpmetricgrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}

	for k, v := range e.config.Headers {
		opts = append(opts, otlpmetricgrpc.WithHeaders(map[string]string{k: v}))
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return err
	}

	e.exporter = exporter
	return nil
}

// createHTTPExporter creates an HTTP OTLP exporter
func (e *Exporter) createHTTPExporter(ctx context.Context) error {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(e.config.Endpoint),
	}

	if e.config.Insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	for k, v := range e.config.Headers {
		opts = append(opts, otlpmetrichttp.WithHeaders(map[string]string{k: v}))
	}

	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return err
	}

	e.exporter = exporter
	return nil
}

// worker processes the metric queue
func (e *Exporter) worker(ctx context.Context) {
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case metrics := <-e.queue:
			e.processMetrics(ctx, metrics)
		}
	}
}

// processMetrics processes a batch of metrics
func (e *Exporter) processMetrics(ctx context.Context, metrics []*types.NetworkMetric) {
	for _, m := range metrics {
		attrs := e.labelsToAttributes(m.Labels)

		switch m.Type {
		case types.MetricTypeGauge:
			if err := e.recordGauge(ctx, m.Name, m.Value, attrs); err != nil {
				e.log.Warn("failed to record gauge", "name", m.Name, "error", err)
			}
		case types.MetricTypeCounter:
			if err := e.recordCounter(ctx, m.Name, m.Value, attrs); err != nil {
				e.log.Warn("failed to record counter", "name", m.Name, "error", err)
			}
		}
	}
}

// recordGauge records a gauge metric
func (e *Exporter) recordGauge(ctx context.Context, name string, value float64, attrs []attribute.KeyValue) error {
	e.mu.Lock()
	gauge, ok := e.gauges[name]
	if !ok {
		var err error
		gauge, err = e.meter.Float64Gauge(name)
		if err != nil {
			e.mu.Unlock()
			return err
		}
		e.gauges[name] = gauge
	}
	e.mu.Unlock()

	gauge.Record(ctx, value, metric.WithAttributes(attrs...))
	return nil
}

// recordCounter records a counter metric
func (e *Exporter) recordCounter(ctx context.Context, name string, value float64, attrs []attribute.KeyValue) error {
	e.mu.Lock()
	counter, ok := e.counters[name]
	if !ok {
		var err error
		counter, err = e.meter.Float64Counter(name)
		if err != nil {
			e.mu.Unlock()
			return err
		}
		e.counters[name] = counter
	}
	e.mu.Unlock()

	counter.Add(ctx, value, metric.WithAttributes(attrs...))
	return nil
}

// labelsToAttributes converts metric labels to OTLP attributes
func (e *Exporter) labelsToAttributes(labels map[string]string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(labels))
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	return attrs
}
