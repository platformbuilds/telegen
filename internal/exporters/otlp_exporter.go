// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/platformbuilds/telegen/internal/pipeline"
	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// OTLPExporter exports signals via OpenTelemetry Protocol
type OTLPExporter struct {
	name string
	cfg  OTLPConfig
	log  *slog.Logger
	st   *selftelemetry.Metrics

	// Exporters per signal type
	traceExporter *otlptrace.Exporter

	// gRPC connection (reused across signals)
	grpcConn *grpc.ClientConn

	mu      sync.RWMutex
	running bool
}

// NewOTLPExporter creates a new OTLP exporter
func NewOTLPExporter(cfg OTLPConfig, log *slog.Logger, st *selftelemetry.Metrics) (*OTLPExporter, error) {
	return &OTLPExporter{
		name: "otlp",
		cfg:  cfg,
		log:  log.With("component", "otlp_exporter"),
		st:   st,
	}, nil
}

func (e *OTLPExporter) Name() string {
	return e.name
}

func (e *OTLPExporter) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	e.log.Info("starting OTLP exporter",
		"endpoint", e.cfg.Endpoint,
		"protocol", e.cfg.Protocol,
	)

	var err error

	// Initialize based on protocol
	if e.cfg.Protocol == "grpc" {
		err = e.initGRPC(ctx)
	} else {
		err = e.initHTTP(ctx)
	}

	if err != nil {
		return fmt.Errorf("failed to initialize OTLP exporter: %w", err)
	}

	e.running = true
	return nil
}

func (e *OTLPExporter) initGRPC(ctx context.Context) error {
	opts := []grpc.DialOption{
		grpc.WithBlock(),
	}

	// Configure TLS
	if e.cfg.TLS.Enabled {
		tlsCfg, err := e.buildTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to build TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Connect
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, e.cfg.Endpoint, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial OTLP endpoint: %w", err)
	}
	e.grpcConn = conn

	// Initialize trace exporter if enabled
	if e.cfg.Traces.Enabled {
		traceOpts := []otlptracegrpc.Option{
			otlptracegrpc.WithGRPCConn(conn),
		}
		if e.cfg.Compression == "gzip" {
			traceOpts = append(traceOpts, otlptracegrpc.WithCompressor("gzip"))
		}
		if len(e.cfg.Headers) > 0 {
			traceOpts = append(traceOpts, otlptracegrpc.WithHeaders(e.cfg.Headers))
		}

		exporter, err := otlptracegrpc.New(ctx, traceOpts...)
		if err != nil {
			return fmt.Errorf("failed to create trace exporter: %w", err)
		}
		e.traceExporter = exporter
	}

	return nil
}

func (e *OTLPExporter) initHTTP(ctx context.Context) error {
	endpoint := e.cfg.Endpoint
	if e.cfg.Traces.Endpoint != "" {
		endpoint = e.cfg.Traces.Endpoint
	}

	// Initialize trace exporter if enabled
	if e.cfg.Traces.Enabled {
		traceOpts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(endpoint),
		}

		if !e.cfg.TLS.Enabled {
			traceOpts = append(traceOpts, otlptracehttp.WithInsecure())
		} else if e.cfg.TLS.InsecureSkipVerify {
			traceOpts = append(traceOpts, otlptracehttp.WithTLSClientConfig(&tls.Config{
				InsecureSkipVerify: true,
			}))
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

		exporter, err := otlptracehttp.New(ctx, traceOpts...)
		if err != nil {
			return fmt.Errorf("failed to create trace exporter: %w", err)
		}
		e.traceExporter = exporter
	}

	return nil
}

func (e *OTLPExporter) buildTLSConfig() (*tls.Config, error) {
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

func (e *OTLPExporter) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	e.log.Info("stopping OTLP exporter")

	var errs []error

	if e.traceExporter != nil {
		if err := e.traceExporter.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace exporter: %w", err))
		}
	}

	if e.grpcConn != nil {
		if err := e.grpcConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("grpc connection: %w", err))
		}
	}

	e.running = false

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}
	return nil
}

func (e *OTLPExporter) Export(ctx context.Context, signalType pipeline.SignalType, signals []pipeline.Signal) error {
	if len(signals) == 0 {
		return nil
	}

	start := time.Now()
	var err error

	switch signalType {
	case pipeline.SignalTraces:
		err = e.exportTraces(ctx, signals)
	case pipeline.SignalMetrics:
		err = e.exportMetrics(ctx, signals)
	case pipeline.SignalLogs:
		err = e.exportLogs(ctx, signals)
	case pipeline.SignalProfiles:
		err = e.exportProfiles(ctx, signals)
	default:
		return fmt.Errorf("unsupported signal type: %s", signalType)
	}

	duration := time.Since(start)
	if e.st != nil {
		e.st.ExporterLatency.WithLabelValues(e.name, string(signalType)).Observe(duration.Seconds())
	}

	return err
}

func (e *OTLPExporter) exportTraces(ctx context.Context, signals []pipeline.Signal) error {
	if e.traceExporter == nil {
		return nil
	}

	// Convert signals to trace spans
	// In a real implementation, this would convert pipeline.Signal to trace.ReadOnlySpan
	e.log.Debug("exporting traces", "count", len(signals))

	if e.st != nil {
		e.st.ExporterBatchSize.WithLabelValues(e.name, "traces").Observe(float64(len(signals)))
	}

	return nil
}

func (e *OTLPExporter) exportMetrics(ctx context.Context, signals []pipeline.Signal) error {
	if !e.cfg.Metrics.Enabled {
		return nil
	}

	e.log.Debug("exporting metrics", "count", len(signals))

	if e.st != nil {
		e.st.ExporterBatchSize.WithLabelValues(e.name, "metrics").Observe(float64(len(signals)))
	}

	return nil
}

func (e *OTLPExporter) exportLogs(ctx context.Context, signals []pipeline.Signal) error {
	if !e.cfg.Logs.Enabled {
		return nil
	}

	e.log.Debug("exporting logs", "count", len(signals))

	if e.st != nil {
		e.st.ExporterBatchSize.WithLabelValues(e.name, "logs").Observe(float64(len(signals)))
	}

	return nil
}

func (e *OTLPExporter) exportProfiles(ctx context.Context, signals []pipeline.Signal) error {
	if !e.cfg.Profiles.Enabled {
		return nil
	}

	e.log.Debug("exporting profiles", "count", len(signals))

	if e.st != nil {
		e.st.ExporterBatchSize.WithLabelValues(e.name, "profiles").Observe(float64(len(signals)))
	}

	return nil
}

func (e *OTLPExporter) SupportedSignals() []pipeline.SignalType {
	var signals []pipeline.SignalType
	if e.cfg.Traces.Enabled {
		signals = append(signals, pipeline.SignalTraces)
	}
	if e.cfg.Metrics.Enabled {
		signals = append(signals, pipeline.SignalMetrics)
	}
	if e.cfg.Logs.Enabled {
		signals = append(signals, pipeline.SignalLogs)
	}
	if e.cfg.Profiles.Enabled {
		signals = append(signals, pipeline.SignalProfiles)
	}
	return signals
}

// DebugExporter prints signals to logs for debugging
type DebugExporter struct {
	name string
	cfg  DebugConfig
	log  *slog.Logger

	mu      sync.RWMutex
	running bool
	count   int
}

// NewDebugExporter creates a new debug exporter
func NewDebugExporter(cfg DebugConfig, log *slog.Logger) *DebugExporter {
	return &DebugExporter{
		name: "debug",
		cfg:  cfg,
		log:  log.With("component", "debug_exporter"),
	}
}

func (e *DebugExporter) Name() string {
	return e.name
}

func (e *DebugExporter) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = true
	e.log.Info("starting debug exporter", "verbosity", e.cfg.Verbosity)
	return nil
}

func (e *DebugExporter) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = false
	return nil
}

func (e *DebugExporter) Export(ctx context.Context, signalType pipeline.SignalType, signals []pipeline.Signal) error {
	e.mu.Lock()
	e.count++
	count := e.count
	e.mu.Unlock()

	// Apply sampling
	if count > e.cfg.SamplingInitial && (count-e.cfg.SamplingInitial)%e.cfg.SamplingThereafter != 0 {
		return nil
	}

	// Log based on verbosity
	switch e.cfg.Verbosity {
	case "basic":
		e.log.Info("export",
			"signal", signalType,
			"count", len(signals),
		)
	case "detailed":
		for i, sig := range signals {
			e.log.Info("signal",
				"type", signalType,
				"index", i,
				"size", sig.Size(),
			)
		}
	default: // normal
		e.log.Info("export",
			"signal", signalType,
			"count", len(signals),
			"batch", count,
		)
	}

	return nil
}

func (e *DebugExporter) SupportedSignals() []pipeline.SignalType {
	return []pipeline.SignalType{
		pipeline.SignalTraces,
		pipeline.SignalMetrics,
		pipeline.SignalLogs,
		pipeline.SignalProfiles,
	}
}
