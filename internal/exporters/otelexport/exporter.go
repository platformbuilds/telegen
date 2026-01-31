// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package otelexport provides OTel Collector-friendly export functionality.
// This package ensures all telemetry signals (metrics, traces, logs) are
// exported in a format compatible with the OpenTelemetry Collector.
package otelexport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config holds configuration for the OTel Collector exporter
type Config struct {
	// Endpoint is the OTel Collector endpoint (e.g., "localhost:4317" for gRPC)
	Endpoint string

	// Protocol is the transport protocol: "grpc" or "http"
	Protocol string

	// TLS configuration
	TLS TLSConfig

	// Headers to send with requests
	Headers map[string]string

	// Compression algorithm: "gzip" or "none"
	Compression string

	// Timeout for export operations
	Timeout time.Duration

	// Export configuration per signal type
	Traces  SignalConfig
	Metrics SignalConfig
	Logs    SignalConfig

	// Resource attributes to add to all signals
	ResourceAttributes []attribute.KeyValue

	// Service information
	ServiceName      string
	ServiceVersion   string
	ServiceNamespace string
	ServiceInstance  string
}

// SignalConfig holds configuration for a specific signal type
type SignalConfig struct {
	// Enabled controls whether this signal type is exported
	Enabled bool

	// Endpoint override for this signal (optional)
	Endpoint string

	// Headers override for this signal (optional)
	Headers map[string]string

	// BatchSize for batching exports
	BatchSize int

	// FlushInterval for periodic flushing
	FlushInterval time.Duration
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	// Enabled controls TLS usage
	Enabled bool

	// CAFile is the path to the CA certificate file
	CAFile string

	// CertFile is the path to the client certificate file
	CertFile string

	// KeyFile is the path to the client key file
	KeyFile string

	// InsecureSkipVerify disables server certificate verification
	InsecureSkipVerify bool

	// ServerName overrides the server name for TLS verification
	ServerName string
}

// Exporter exports telemetry to an OTel Collector
type Exporter struct {
	cfg Config
	log *slog.Logger

	// Providers
	tracerProvider *trace.TracerProvider
	meterProvider  *metric.MeterProvider
	loggerProvider *log.LoggerProvider

	// Resource
	resource *resource.Resource

	// gRPC connection (shared if using gRPC)
	grpcConn *grpc.ClientConn

	mu      sync.RWMutex
	running bool
}

// DefaultConfig returns a default configuration for local OTel Collector
func DefaultConfig() Config {
	return Config{
		Endpoint:    "localhost:4317",
		Protocol:    "grpc",
		Compression: "gzip",
		Timeout:     30 * time.Second,
		Traces: SignalConfig{
			Enabled:       true,
			BatchSize:     512,
			FlushInterval: 5 * time.Second,
		},
		Metrics: SignalConfig{
			Enabled:       true,
			BatchSize:     1000,
			FlushInterval: 60 * time.Second,
		},
		Logs: SignalConfig{
			Enabled:       true,
			BatchSize:     512,
			FlushInterval: 5 * time.Second,
		},
		ServiceName:      "telegen",
		ServiceVersion:   "1.0.0",
		ServiceNamespace: "telegen",
	}
}

// New creates a new OTel Collector exporter
func New(cfg Config, log *slog.Logger) (*Exporter, error) {
	if log == nil {
		log = slog.Default()
	}

	return &Exporter{
		cfg: cfg,
		log: log.With("component", "otel_exporter"),
	}, nil
}

// Start initializes and starts the exporter
func (e *Exporter) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	e.log.Info("starting OTel Collector exporter",
		"endpoint", e.cfg.Endpoint,
		"protocol", e.cfg.Protocol,
		"traces_enabled", e.cfg.Traces.Enabled,
		"metrics_enabled", e.cfg.Metrics.Enabled,
		"logs_enabled", e.cfg.Logs.Enabled,
	)

	// Build resource
	if err := e.buildResource(ctx); err != nil {
		return fmt.Errorf("failed to build resource: %w", err)
	}

	// Initialize based on protocol
	var err error
	if e.cfg.Protocol == "grpc" {
		err = e.initGRPC(ctx)
	} else {
		err = e.initHTTP(ctx)
	}

	if err != nil {
		return fmt.Errorf("failed to initialize exporter: %w", err)
	}

	e.running = true
	return nil
}

// buildResource creates the OTel resource with Telegen-specific attributes
func (e *Exporter) buildResource(ctx context.Context) error {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(e.cfg.ServiceName),
		semconv.ServiceVersion(e.cfg.ServiceVersion),
		semconv.ServiceNamespace(e.cfg.ServiceNamespace),
		attribute.String("telemetry.sdk.name", "telegen"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.version", "1.0.0"),
	}

	if e.cfg.ServiceInstance != "" {
		attrs = append(attrs, semconv.ServiceInstanceID(e.cfg.ServiceInstance))
	}

	// Add custom resource attributes
	attrs = append(attrs, e.cfg.ResourceAttributes...)

	res, err := resource.New(ctx,
		resource.WithAttributes(attrs...),
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithOS(),
		resource.WithProcess(),
		resource.WithContainer(),
	)
	if err != nil {
		return err
	}
	e.resource = res

	return nil
}

// initGRPC initializes gRPC-based exporters
func (e *Exporter) initGRPC(ctx context.Context) error {
	// Build gRPC dial options
	opts := []grpc.DialOption{}

	if e.cfg.TLS.Enabled {
		tlsCfg, err := e.buildTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to build TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Establish connection
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, e.cfg.Endpoint, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial OTel Collector: %w", err)
	}
	e.grpcConn = conn

	// Initialize trace exporter
	if e.cfg.Traces.Enabled {
		if err := e.initTraceExporterGRPC(ctx); err != nil {
			return err
		}
	}

	// Initialize metric exporter
	if e.cfg.Metrics.Enabled {
		if err := e.initMetricExporterGRPC(ctx); err != nil {
			return err
		}
	}

	// Initialize log exporter
	if e.cfg.Logs.Enabled {
		if err := e.initLogExporterGRPC(ctx); err != nil {
			return err
		}
	}

	return nil
}

// initHTTP initializes HTTP-based exporters
func (e *Exporter) initHTTP(ctx context.Context) error {
	// Initialize trace exporter
	if e.cfg.Traces.Enabled {
		if err := e.initTraceExporterHTTP(ctx); err != nil {
			return err
		}
	}

	// Initialize metric exporter
	if e.cfg.Metrics.Enabled {
		if err := e.initMetricExporterHTTP(ctx); err != nil {
			return err
		}
	}

	// Initialize log exporter
	if e.cfg.Logs.Enabled {
		if err := e.initLogExporterHTTP(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (e *Exporter) initTraceExporterGRPC(ctx context.Context) error {
	traceOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithGRPCConn(e.grpcConn),
	}

	if e.cfg.Compression == "gzip" {
		traceOpts = append(traceOpts, otlptracegrpc.WithCompressor("gzip"))
	}

	headers := e.cfg.Headers
	if len(e.cfg.Traces.Headers) > 0 {
		headers = e.cfg.Traces.Headers
	}
	if len(headers) > 0 {
		traceOpts = append(traceOpts, otlptracegrpc.WithHeaders(headers))
	}

	traceExporter, err := otlptracegrpc.New(ctx, traceOpts...)
	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}

	bsp := trace.NewBatchSpanProcessor(traceExporter,
		trace.WithBatchTimeout(e.cfg.Traces.FlushInterval),
		trace.WithMaxExportBatchSize(e.cfg.Traces.BatchSize),
	)

	e.tracerProvider = trace.NewTracerProvider(
		trace.WithResource(e.resource),
		trace.WithSpanProcessor(bsp),
	)

	return nil
}

func (e *Exporter) initTraceExporterHTTP(ctx context.Context) error {
	endpoint := e.cfg.Endpoint
	if e.cfg.Traces.Endpoint != "" {
		endpoint = e.cfg.Traces.Endpoint
	}

	traceOpts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
	}

	if !e.cfg.TLS.Enabled {
		traceOpts = append(traceOpts, otlptracehttp.WithInsecure())
	}

	if e.cfg.Compression == "gzip" {
		traceOpts = append(traceOpts, otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
	}

	headers := e.cfg.Headers
	if len(e.cfg.Traces.Headers) > 0 {
		headers = e.cfg.Traces.Headers
	}
	if len(headers) > 0 {
		traceOpts = append(traceOpts, otlptracehttp.WithHeaders(headers))
	}

	traceExporter, err := otlptracehttp.New(ctx, traceOpts...)
	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}

	bsp := trace.NewBatchSpanProcessor(traceExporter,
		trace.WithBatchTimeout(e.cfg.Traces.FlushInterval),
		trace.WithMaxExportBatchSize(e.cfg.Traces.BatchSize),
	)

	e.tracerProvider = trace.NewTracerProvider(
		trace.WithResource(e.resource),
		trace.WithSpanProcessor(bsp),
	)

	return nil
}

func (e *Exporter) initMetricExporterGRPC(ctx context.Context) error {
	metricOpts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithGRPCConn(e.grpcConn),
	}

	if e.cfg.Compression == "gzip" {
		metricOpts = append(metricOpts, otlpmetricgrpc.WithCompressor("gzip"))
	}

	headers := e.cfg.Headers
	if len(e.cfg.Metrics.Headers) > 0 {
		headers = e.cfg.Metrics.Headers
	}
	if len(headers) > 0 {
		metricOpts = append(metricOpts, otlpmetricgrpc.WithHeaders(headers))
	}

	metricExporter, err := otlpmetricgrpc.New(ctx, metricOpts...)
	if err != nil {
		return fmt.Errorf("failed to create metric exporter: %w", err)
	}

	e.meterProvider = metric.NewMeterProvider(
		metric.WithResource(e.resource),
		metric.WithReader(metric.NewPeriodicReader(metricExporter,
			metric.WithInterval(e.cfg.Metrics.FlushInterval),
		)),
	)

	return nil
}

func (e *Exporter) initMetricExporterHTTP(ctx context.Context) error {
	endpoint := e.cfg.Endpoint
	if e.cfg.Metrics.Endpoint != "" {
		endpoint = e.cfg.Metrics.Endpoint
	}

	metricOpts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(endpoint),
	}

	if !e.cfg.TLS.Enabled {
		metricOpts = append(metricOpts, otlpmetrichttp.WithInsecure())
	}

	if e.cfg.Compression == "gzip" {
		metricOpts = append(metricOpts, otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression))
	}

	headers := e.cfg.Headers
	if len(e.cfg.Metrics.Headers) > 0 {
		headers = e.cfg.Metrics.Headers
	}
	if len(headers) > 0 {
		metricOpts = append(metricOpts, otlpmetrichttp.WithHeaders(headers))
	}

	metricExporter, err := otlpmetrichttp.New(ctx, metricOpts...)
	if err != nil {
		return fmt.Errorf("failed to create metric exporter: %w", err)
	}

	e.meterProvider = metric.NewMeterProvider(
		metric.WithResource(e.resource),
		metric.WithReader(metric.NewPeriodicReader(metricExporter,
			metric.WithInterval(e.cfg.Metrics.FlushInterval),
		)),
	)

	return nil
}

func (e *Exporter) initLogExporterGRPC(ctx context.Context) error {
	logOpts := []otlploggrpc.Option{
		otlploggrpc.WithGRPCConn(e.grpcConn),
	}

	if e.cfg.Compression == "gzip" {
		logOpts = append(logOpts, otlploggrpc.WithCompressor("gzip"))
	}

	headers := e.cfg.Headers
	if len(e.cfg.Logs.Headers) > 0 {
		headers = e.cfg.Logs.Headers
	}
	if len(headers) > 0 {
		logOpts = append(logOpts, otlploggrpc.WithHeaders(headers))
	}

	logExporter, err := otlploggrpc.New(ctx, logOpts...)
	if err != nil {
		return fmt.Errorf("failed to create log exporter: %w", err)
	}

	e.loggerProvider = log.NewLoggerProvider(
		log.WithResource(e.resource),
		log.WithProcessor(log.NewBatchProcessor(logExporter,
			log.WithExportTimeout(e.cfg.Timeout),
		)),
	)

	return nil
}

func (e *Exporter) initLogExporterHTTP(ctx context.Context) error {
	endpoint := e.cfg.Endpoint
	if e.cfg.Logs.Endpoint != "" {
		endpoint = e.cfg.Logs.Endpoint
	}

	logOpts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(endpoint),
	}

	if !e.cfg.TLS.Enabled {
		logOpts = append(logOpts, otlploghttp.WithInsecure())
	}

	if e.cfg.Compression == "gzip" {
		logOpts = append(logOpts, otlploghttp.WithCompression(otlploghttp.GzipCompression))
	}

	headers := e.cfg.Headers
	if len(e.cfg.Logs.Headers) > 0 {
		headers = e.cfg.Logs.Headers
	}
	if len(headers) > 0 {
		logOpts = append(logOpts, otlploghttp.WithHeaders(headers))
	}

	logExporter, err := otlploghttp.New(ctx, logOpts...)
	if err != nil {
		return fmt.Errorf("failed to create log exporter: %w", err)
	}

	e.loggerProvider = log.NewLoggerProvider(
		log.WithResource(e.resource),
		log.WithProcessor(log.NewBatchProcessor(logExporter,
			log.WithExportTimeout(e.cfg.Timeout),
		)),
	)

	return nil
}

func (e *Exporter) buildTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: e.cfg.TLS.InsecureSkipVerify,
	}

	if e.cfg.TLS.ServerName != "" {
		cfg.ServerName = e.cfg.TLS.ServerName
	}

	// Load CA cert
	if e.cfg.TLS.CAFile != "" {
		caCert, err := os.ReadFile(e.cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		cfg.RootCAs = caCertPool
	}

	// Load client cert
	if e.cfg.TLS.CertFile != "" && e.cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(e.cfg.TLS.CertFile, e.cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// TracerProvider returns the trace provider
func (e *Exporter) TracerProvider() *trace.TracerProvider {
	return e.tracerProvider
}

// MeterProvider returns the meter provider
func (e *Exporter) MeterProvider() *metric.MeterProvider {
	return e.meterProvider
}

// LoggerProvider returns the logger provider
func (e *Exporter) LoggerProvider() *log.LoggerProvider {
	return e.loggerProvider
}

// Shutdown gracefully shuts down the exporter
func (e *Exporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	e.log.Info("shutting down OTel Collector exporter")

	var errs []error

	if e.tracerProvider != nil {
		if err := e.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace provider shutdown: %w", err))
		}
	}

	if e.meterProvider != nil {
		if err := e.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("meter provider shutdown: %w", err))
		}
	}

	if e.loggerProvider != nil {
		if err := e.loggerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("logger provider shutdown: %w", err))
		}
	}

	if e.grpcConn != nil {
		if err := e.grpcConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("gRPC connection close: %w", err))
		}
	}

	e.running = false

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}
