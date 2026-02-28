// Package pipeline provides the unified signal processing pipeline for Telegen V3.
package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// ExporterConfig holds configuration for the unified OTLP exporter.
type ExporterConfig struct {
	// Endpoint is the OTLP endpoint (e.g., "localhost:4317").
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Insecure disables TLS. Default: false.
	Insecure bool `yaml:"insecure" json:"insecure"`

	// Headers are additional headers to send with requests.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// Timeout for export operations. Default: 30s.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// RetryConfig controls retry behavior.
	Retry RetryConfig `yaml:"retry" json:"retry"`

	// MaxConcurrentExports limits concurrent export operations. Default: 4.
	MaxConcurrentExports int `yaml:"max_concurrent_exports" json:"max_concurrent_exports"`

	// BatchSize is the maximum number of signals per batch. Default: 1000.
	BatchSize int `yaml:"batch_size" json:"batch_size"`
}

// RetryConfig controls retry behavior.
type RetryConfig struct {
	// Enabled enables retry. Default: true.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxAttempts is the maximum number of retry attempts. Default: 3.
	MaxAttempts int `yaml:"max_attempts" json:"max_attempts"`

	// InitialInterval is the initial retry interval. Default: 1s.
	InitialInterval time.Duration `yaml:"initial_interval" json:"initial_interval"`

	// MaxInterval is the maximum retry interval. Default: 30s.
	MaxInterval time.Duration `yaml:"max_interval" json:"max_interval"`

	// Multiplier is the backoff multiplier. Default: 2.0.
	Multiplier float64 `yaml:"multiplier" json:"multiplier"`
}

// DefaultExporterConfig returns default configuration.
func DefaultExporterConfig() ExporterConfig {
	return ExporterConfig{
		Endpoint: "localhost:4317",
		Insecure: false,
		Timeout:  30 * time.Second,
		Retry: RetryConfig{
			Enabled:         true,
			MaxAttempts:     3,
			InitialInterval: 1 * time.Second,
			MaxInterval:     30 * time.Second,
			Multiplier:      2.0,
		},
		MaxConcurrentExports: 4,
		BatchSize:            1000,
	}
}

// UnifiedExporter exports all signal types (traces, logs, metrics) via OTLP.
type UnifiedExporter struct {
	config ExporterConfig

	conn *grpc.ClientConn

	// OTLP service clients.
	traceClient  OTLPTraceClient
	logClient    OTLPLogClient
	metricClient OTLPMetricClient

	// Semaphore for concurrent export limiting.
	sem chan struct{}

	// Stats.
	exportedTraces  atomic.Int64
	exportedLogs    atomic.Int64
	exportedMetrics atomic.Int64
	failedExports   atomic.Int64

	mu       sync.RWMutex
	shutdown bool
}

// OTLPTraceClient is the interface for OTLP trace export.
type OTLPTraceClient interface {
	Export(ctx context.Context, traces ptrace.Traces) error
}

// OTLPLogClient is the interface for OTLP log export.
type OTLPLogClient interface {
	Export(ctx context.Context, logs plog.Logs) error
}

// OTLPMetricClient is the interface for OTLP metric export.
type OTLPMetricClient interface {
	Export(ctx context.Context, metrics pmetric.Metrics) error
}

// NewUnifiedExporter creates a new unified OTLP exporter.
func NewUnifiedExporter(config ExporterConfig) (*UnifiedExporter, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	// Apply defaults.
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxConcurrentExports == 0 {
		config.MaxConcurrentExports = 4
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.Retry.MaxAttempts == 0 {
		config.Retry.MaxAttempts = 3
	}
	if config.Retry.InitialInterval == 0 {
		config.Retry.InitialInterval = 1 * time.Second
	}
	if config.Retry.MaxInterval == 0 {
		config.Retry.MaxInterval = 30 * time.Second
	}
	if config.Retry.Multiplier == 0 {
		config.Retry.Multiplier = 2.0
	}

	e := &UnifiedExporter{
		config: config,
		sem:    make(chan struct{}, config.MaxConcurrentExports),
	}

	return e, nil
}

// Connect establishes the gRPC connection.
func (e *UnifiedExporter) Connect(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil {
		return nil // Already connected.
	}

	var opts []grpc.DialOption

	if e.config.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
	}

	conn, err := grpc.DialContext(ctx, e.config.Endpoint, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", e.config.Endpoint, err)
	}

	e.conn = conn

	// Create OTLP clients.
	e.traceClient = &grpcTraceClient{conn: conn, timeout: e.config.Timeout}
	e.logClient = &grpcLogClient{conn: conn, timeout: e.config.Timeout}
	e.metricClient = &grpcMetricClient{conn: conn, timeout: e.config.Timeout}

	return nil
}

// Export exports a signal to the configured endpoint.
func (e *UnifiedExporter) Export(ctx context.Context, signal PipelineSignal) error {
	e.mu.RLock()
	if e.shutdown {
		e.mu.RUnlock()
		return fmt.Errorf("exporter is shut down")
	}
	e.mu.RUnlock()

	// Acquire semaphore.
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}

	var err error
	for attempt := 0; attempt <= e.config.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			// Calculate backoff.
			backoff := e.calculateBackoff(attempt)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err = e.exportOnce(ctx, signal)
		if err == nil {
			return nil
		}

		// Check if error is retryable.
		if !e.config.Retry.Enabled || !isRetryable(err) {
			break
		}
	}

	e.failedExports.Add(1)
	return err
}

// ExportBatch exports multiple signals.
func (e *UnifiedExporter) ExportBatch(ctx context.Context, signals []PipelineSignal) error {
	if len(signals) == 0 {
		return nil
	}

	// Group signals by type.
	var traces []ptrace.Traces
	var logs []plog.Logs
	var metrics []pmetric.Metrics

	for _, sig := range signals {
		switch sig.Type() {
		case SignalTypeTrace:
			if t, ok := sig.ToPData().(ptrace.Traces); ok {
				traces = append(traces, t)
			}
		case SignalTypeLog:
			if l, ok := sig.ToPData().(plog.Logs); ok {
				logs = append(logs, l)
			}
		case SignalTypeMetric:
			if m, ok := sig.ToPData().(pmetric.Metrics); ok {
				metrics = append(metrics, m)
			}
		}
	}

	// Export each type.
	var errs []error

	if len(traces) > 0 {
		merged := mergeTraces(traces)
		if err := e.exportTraces(ctx, merged); err != nil {
			errs = append(errs, err)
		}
	}

	if len(logs) > 0 {
		merged := mergeLogs(logs)
		if err := e.exportLogs(ctx, merged); err != nil {
			errs = append(errs, err)
		}
	}

	if len(metrics) > 0 {
		merged := mergeMetrics(metrics)
		if err := e.exportMetrics(ctx, merged); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("export errors: %v", errs)
	}
	return nil
}

// exportOnce performs a single export attempt.
func (e *UnifiedExporter) exportOnce(ctx context.Context, signal PipelineSignal) error {
	switch signal.Type() {
	case SignalTypeTrace:
		traces, ok := signal.ToPData().(ptrace.Traces)
		if !ok {
			return fmt.Errorf("invalid trace signal")
		}
		return e.exportTraces(ctx, traces)

	case SignalTypeLog:
		logs, ok := signal.ToPData().(plog.Logs)
		if !ok {
			return fmt.Errorf("invalid log signal")
		}
		return e.exportLogs(ctx, logs)

	case SignalTypeMetric:
		metrics, ok := signal.ToPData().(pmetric.Metrics)
		if !ok {
			return fmt.Errorf("invalid metric signal")
		}
		return e.exportMetrics(ctx, metrics)

	default:
		return fmt.Errorf("unknown signal type: %v", signal.Type())
	}
}

func (e *UnifiedExporter) exportTraces(ctx context.Context, traces ptrace.Traces) error {
	if e.traceClient == nil {
		return fmt.Errorf("trace client not initialized")
	}
	if err := e.traceClient.Export(ctx, traces); err != nil {
		return err
	}
	e.exportedTraces.Add(int64(traces.SpanCount()))
	return nil
}

func (e *UnifiedExporter) exportLogs(ctx context.Context, logs plog.Logs) error {
	if e.logClient == nil {
		return fmt.Errorf("log client not initialized")
	}
	if err := e.logClient.Export(ctx, logs); err != nil {
		return err
	}
	e.exportedLogs.Add(int64(logs.LogRecordCount()))
	return nil
}

func (e *UnifiedExporter) exportMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if e.metricClient == nil {
		return fmt.Errorf("metric client not initialized")
	}
	if err := e.metricClient.Export(ctx, metrics); err != nil {
		return err
	}
	e.exportedMetrics.Add(int64(metrics.DataPointCount()))
	return nil
}

func (e *UnifiedExporter) calculateBackoff(attempt int) time.Duration {
	backoff := e.config.Retry.InitialInterval
	for i := 1; i < attempt; i++ {
		backoff = time.Duration(float64(backoff) * e.config.Retry.Multiplier)
		if backoff > e.config.Retry.MaxInterval {
			backoff = e.config.Retry.MaxInterval
			break
		}
	}
	return backoff
}

// Shutdown gracefully shuts down the exporter.
func (e *UnifiedExporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.shutdown = true

	if e.conn != nil {
		if err := e.conn.Close(); err != nil {
			return err
		}
		e.conn = nil
	}

	return nil
}

// Stats returns export statistics.
func (e *UnifiedExporter) Stats() ExporterStats {
	return ExporterStats{
		ExportedTraces:  e.exportedTraces.Load(),
		ExportedLogs:    e.exportedLogs.Load(),
		ExportedMetrics: e.exportedMetrics.Load(),
		FailedExports:   e.failedExports.Load(),
	}
}

// ExporterStats holds export statistics.
type ExporterStats struct {
	ExportedTraces  int64
	ExportedLogs    int64
	ExportedMetrics int64
	FailedExports   int64
}

// isRetryable determines if an error is retryable.
func isRetryable(err error) bool {
	// TODO: Add proper gRPC status code checking.
	// For now, retry all errors.
	return true
}

// mergeTraces merges multiple ptrace.Traces into one.
func mergeTraces(traces []ptrace.Traces) ptrace.Traces {
	if len(traces) == 1 {
		return traces[0]
	}
	merged := ptrace.NewTraces()
	for _, t := range traces {
		t.ResourceSpans().MoveAndAppendTo(merged.ResourceSpans())
	}
	return merged
}

// mergeLogs merges multiple plog.Logs into one.
func mergeLogs(logs []plog.Logs) plog.Logs {
	if len(logs) == 1 {
		return logs[0]
	}
	merged := plog.NewLogs()
	for _, l := range logs {
		l.ResourceLogs().MoveAndAppendTo(merged.ResourceLogs())
	}
	return merged
}

// mergeMetrics merges multiple pmetric.Metrics into one.
func mergeMetrics(metrics []pmetric.Metrics) pmetric.Metrics {
	if len(metrics) == 1 {
		return metrics[0]
	}
	merged := pmetric.NewMetrics()
	for _, m := range metrics {
		m.ResourceMetrics().MoveAndAppendTo(merged.ResourceMetrics())
	}
	return merged
}

// gRPC client implementations.

type grpcTraceClient struct {
	conn    *grpc.ClientConn
	timeout time.Duration
}

func (c *grpcTraceClient) Export(ctx context.Context, traces ptrace.Traces) error {
	// In a real implementation, this would use the OTLP proto client.
	// For now, this is a placeholder.
	return nil
}

type grpcLogClient struct {
	conn    *grpc.ClientConn
	timeout time.Duration
}

func (c *grpcLogClient) Export(ctx context.Context, logs plog.Logs) error {
	return nil
}

type grpcMetricClient struct {
	conn    *grpc.ClientConn
	timeout time.Duration
}

func (c *grpcMetricClient) Export(ctx context.Context, metrics pmetric.Metrics) error {
	return nil
}
