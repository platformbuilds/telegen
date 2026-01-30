// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package otlp provides unified OTLP export for traces, metrics, logs, and profiles.
package otlp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Exporter is a unified OTLP exporter that handles all signal types.
type Exporter struct {
	cfg Config
	log *slog.Logger

	// Transport implementations
	grpc *GRPCTransport
	http *HTTPTransport

	// Batcher for batching signals before export
	batcher *Batcher

	// Retry handler
	retryer *Retryer

	mu      sync.RWMutex
	running bool
}

// Config holds the unified OTLP exporter configuration.
type Config struct {
	// Endpoint is the OTLP collector endpoint
	Endpoint string `mapstructure:"endpoint"`

	// Protocol is the transport protocol (grpc, http/protobuf, http/json)
	Protocol Protocol `mapstructure:"protocol"`

	// Headers to include in all requests
	Headers map[string]string `mapstructure:"headers"`

	// Compression type (gzip, none)
	Compression Compression `mapstructure:"compression"`

	// Timeout for requests
	Timeout time.Duration `mapstructure:"timeout"`

	// TLS configuration
	TLS TLSConfig `mapstructure:"tls"`

	// Retry configuration
	Retry RetryConfig `mapstructure:"retry"`

	// Batch configuration
	Batch BatchConfig `mapstructure:"batch"`

	// Signal-specific configurations
	Traces   SignalConfig `mapstructure:"traces"`
	Metrics  SignalConfig `mapstructure:"metrics"`
	Logs     SignalConfig `mapstructure:"logs"`
	Profiles SignalConfig `mapstructure:"profiles"`
}

// Protocol represents the OTLP transport protocol.
type Protocol string

const (
	ProtocolGRPC         Protocol = "grpc"
	ProtocolHTTPProtobuf Protocol = "http/protobuf"
	ProtocolHTTPJSON     Protocol = "http/json"
)

// String returns the string representation of the protocol.
func (p Protocol) String() string {
	return string(p)
}

// Compression represents the compression type.
type Compression string

const (
	CompressionNone Compression = "none"
	CompressionGzip Compression = "gzip"
	CompressionZstd Compression = "zstd"
)

// String returns the string representation of the compression type.
func (c Compression) String() string {
	return string(c)
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	// Enabled enables TLS
	Enabled bool `mapstructure:"enabled"`

	// CAFile is the path to the CA certificate
	CAFile string `mapstructure:"ca_file"`

	// CertFile is the path to the client certificate
	CertFile string `mapstructure:"cert_file"`

	// KeyFile is the path to the client key
	KeyFile string `mapstructure:"key_file"`

	// InsecureSkipVerify skips certificate verification
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`

	// ServerName is the expected server name for verification
	ServerName string `mapstructure:"server_name"`
}

// RetryConfig holds retry configuration.
type RetryConfig struct {
	// Enabled enables retry
	Enabled bool `mapstructure:"enabled"`

	// InitialInterval is the initial retry interval
	InitialInterval time.Duration `mapstructure:"initial_interval"`

	// MaxInterval is the maximum retry interval
	MaxInterval time.Duration `mapstructure:"max_interval"`

	// MaxElapsedTime is the maximum total retry time
	MaxElapsedTime time.Duration `mapstructure:"max_elapsed_time"`

	// Multiplier is the backoff multiplier
	Multiplier float64 `mapstructure:"multiplier"`

	// RandomizationFactor adds jitter to backoff
	RandomizationFactor float64 `mapstructure:"randomization_factor"`
}

// BatchConfig holds batch configuration.
type BatchConfig struct {
	// Enabled enables batching
	Enabled bool `mapstructure:"enabled"`

	// MaxBatchSize is the maximum number of items per batch
	MaxBatchSize int `mapstructure:"max_batch_size"`

	// MaxBatchBytes is the maximum bytes per batch
	MaxBatchBytes int `mapstructure:"max_batch_bytes"`

	// Timeout is the maximum time to wait before sending a batch
	Timeout time.Duration `mapstructure:"timeout"`

	// MaxQueueSize is the maximum number of batches to queue
	MaxQueueSize int `mapstructure:"max_queue_size"`
}

// SignalConfig holds per-signal configuration.
type SignalConfig struct {
	// Enabled enables this signal
	Enabled bool `mapstructure:"enabled"`

	// Endpoint overrides the main endpoint for this signal
	Endpoint string `mapstructure:"endpoint"`

	// Headers overrides the main headers for this signal
	Headers map[string]string `mapstructure:"headers"`

	// Temporality for metrics (delta, cumulative)
	Temporality string `mapstructure:"temporality"`
}

// DefaultConfig returns the default exporter configuration.
func DefaultConfig() Config {
	return Config{
		Endpoint:    "localhost:4317",
		Protocol:    ProtocolGRPC,
		Compression: CompressionGzip,
		Timeout:     30 * time.Second,
		TLS: TLSConfig{
			Enabled: false,
		},
		Retry: RetryConfig{
			Enabled:             true,
			InitialInterval:     5 * time.Second,
			MaxInterval:         30 * time.Second,
			MaxElapsedTime:      5 * time.Minute,
			Multiplier:          1.5,
			RandomizationFactor: 0.5,
		},
		Batch: BatchConfig{
			Enabled:       true,
			MaxBatchSize:  8192,
			MaxBatchBytes: 3 * 1024 * 1024, // 3MB
			Timeout:       5 * time.Second,
			MaxQueueSize:  5,
		},
		Traces:   SignalConfig{Enabled: true},
		Metrics:  SignalConfig{Enabled: true, Temporality: "delta"},
		Logs:     SignalConfig{Enabled: true},
		Profiles: SignalConfig{Enabled: true},
	}
}

// ConfigFromEnv creates a configuration from environment variables.
// Follows the OpenTelemetry specification for environment variable names.
func ConfigFromEnv() Config {
	cfg := DefaultConfig()

	// OTEL_EXPORTER_OTLP_ENDPOINT
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); endpoint != "" {
		cfg.Endpoint = endpoint
	}

	// OTEL_EXPORTER_OTLP_PROTOCOL
	if protocol := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"); protocol != "" {
		switch protocol {
		case "grpc":
			cfg.Protocol = ProtocolGRPC
		case "http/protobuf":
			cfg.Protocol = ProtocolHTTPProtobuf
		case "http/json":
			cfg.Protocol = ProtocolHTTPJSON
		}
	}

	// OTEL_EXPORTER_OTLP_COMPRESSION
	if compression := os.Getenv("OTEL_EXPORTER_OTLP_COMPRESSION"); compression != "" {
		switch compression {
		case "none":
			cfg.Compression = CompressionNone
		case "gzip":
			cfg.Compression = CompressionGzip
		case "zstd":
			cfg.Compression = CompressionZstd
		}
	}

	// OTEL_EXPORTER_OTLP_HEADERS
	if headers := os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"); headers != "" {
		cfg.Headers = parseHeaders(headers)
	}

	// OTEL_EXPORTER_OTLP_CERTIFICATE
	if certFile := os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"); certFile != "" {
		cfg.TLS.Enabled = true
		cfg.TLS.CertFile = certFile
	}

	return cfg
}

// parseHeaders parses a header string in the format "key1=value1,key2=value2".
func parseHeaders(s string) map[string]string {
	headers := make(map[string]string)
	if s == "" {
		return headers
	}
	// Simple parsing - in production would use proper parsing
	for _, pair := range splitComma(s) {
		if idx := indexByte(pair, '='); idx > 0 {
			headers[pair[:idx]] = pair[idx+1:]
		}
	}
	return headers
}

// splitComma splits a string by comma.
func splitComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

// indexByte returns the index of the first occurrence of c in s.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// NewExporter creates a new unified OTLP exporter.
func NewExporter(cfg Config, log *slog.Logger) (*Exporter, error) {
	if log == nil {
		log = slog.Default()
	}

	e := &Exporter{
		cfg: cfg,
		log: log.With("component", "otlp_exporter"),
	}

	// Initialize retry handler if enabled
	if cfg.Retry.Enabled {
		e.retryer = NewRetryer(cfg.Retry, log)
	}

	// Initialize batcher if enabled
	if cfg.Batch.Enabled {
		e.batcher = NewBatcher(cfg.Batch, log)
	}

	return e, nil
}

// Start initializes and starts the exporter.
func (e *Exporter) Start(ctx context.Context) error {
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

	// Initialize transport based on protocol
	switch e.cfg.Protocol {
	case ProtocolGRPC:
		e.grpc, err = NewGRPCTransport(e.cfg, e.log)
		if err != nil {
			return fmt.Errorf("failed to create gRPC transport: %w", err)
		}
		if err := e.grpc.Connect(ctx); err != nil {
			return fmt.Errorf("failed to connect gRPC transport: %w", err)
		}

	case ProtocolHTTPProtobuf, ProtocolHTTPJSON:
		e.http, err = NewHTTPTransport(e.cfg, e.log)
		if err != nil {
			return fmt.Errorf("failed to create HTTP transport: %w", err)
		}

	default:
		return fmt.Errorf("unsupported protocol: %s", e.cfg.Protocol)
	}

	// Start batcher
	if e.batcher != nil {
		e.batcher.Start(ctx, e.doExport)
	}

	e.running = true
	return nil
}

// Stop shuts down the exporter.
func (e *Exporter) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	e.log.Info("stopping OTLP exporter")

	var errs []error

	// Stop batcher (flushes pending batches)
	if e.batcher != nil {
		if err := e.batcher.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	// Close transport
	if e.grpc != nil {
		if err := e.grpc.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if e.http != nil {
		if err := e.http.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	e.running = false

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}
	return nil
}

// ExportTraces exports trace spans.
func (e *Exporter) ExportTraces(ctx context.Context, data []byte) error {
	if !e.cfg.Traces.Enabled {
		return nil
	}

	return e.export(ctx, SignalTraces, data)
}

// ExportMetrics exports metrics.
func (e *Exporter) ExportMetrics(ctx context.Context, data []byte) error {
	if !e.cfg.Metrics.Enabled {
		return nil
	}

	return e.export(ctx, SignalMetrics, data)
}

// ExportLogs exports log records.
func (e *Exporter) ExportLogs(ctx context.Context, data []byte) error {
	if !e.cfg.Logs.Enabled {
		return nil
	}

	return e.export(ctx, SignalLogs, data)
}

// ExportProfiles exports profiles.
func (e *Exporter) ExportProfiles(ctx context.Context, data []byte) error {
	if !e.cfg.Profiles.Enabled {
		return nil
	}

	return e.export(ctx, SignalProfiles, data)
}

// SignalType represents the type of signal being exported.
type SignalType string

const (
	SignalTraces   SignalType = "traces"
	SignalMetrics  SignalType = "metrics"
	SignalLogs     SignalType = "logs"
	SignalProfiles SignalType = "profiles"
)

// String returns the string representation of the signal type.
func (s SignalType) String() string {
	return string(s)
}

// export handles exporting data with batching and retry.
func (e *Exporter) export(ctx context.Context, signal SignalType, data []byte) error {
	// If batcher is enabled, queue the data
	if e.batcher != nil {
		return e.batcher.Add(ctx, signal, data)
	}

	// Otherwise, export directly
	return e.doExport(ctx, signal, data)
}

// doExport performs the actual export.
func (e *Exporter) doExport(ctx context.Context, signal SignalType, data []byte) error {
	// Wrap in retry if enabled
	if e.retryer != nil {
		return e.retryer.Do(ctx, func(ctx context.Context, attempt int) error {
			return e.sendData(ctx, signal, data)
		})
	}

	return e.sendData(ctx, signal, data)
}

// sendData sends data via the configured transport.
func (e *Exporter) sendData(ctx context.Context, signal SignalType, data []byte) error {
	switch e.cfg.Protocol {
	case ProtocolGRPC:
		if e.grpc == nil {
			return fmt.Errorf("gRPC transport not initialized")
		}
		return e.grpc.Send(ctx, signal, data)

	case ProtocolHTTPProtobuf, ProtocolHTTPJSON:
		if e.http == nil {
			return fmt.Errorf("HTTP transport not initialized")
		}
		return e.http.Send(ctx, signal, data)

	default:
		return fmt.Errorf("unsupported protocol: %s", e.cfg.Protocol)
	}
}

// Flush forces a flush of any pending batches.
func (e *Exporter) Flush(ctx context.Context) error {
	if e.batcher != nil {
		return e.batcher.Flush(ctx)
	}
	return nil
}

// SupportedSignals returns the list of supported signals.
func (e *Exporter) SupportedSignals() []SignalType {
	var signals []SignalType
	if e.cfg.Traces.Enabled {
		signals = append(signals, SignalTraces)
	}
	if e.cfg.Metrics.Enabled {
		signals = append(signals, SignalMetrics)
	}
	if e.cfg.Logs.Enabled {
		signals = append(signals, SignalLogs)
	}
	if e.cfg.Profiles.Enabled {
		signals = append(signals, SignalProfiles)
	}
	return signals
}
