// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package exporters provides unified signal export capabilities.
package exporters

import (
	"context"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// Exporter is the interface that all exporters must implement
type Exporter interface {
	// Name returns the exporter name
	Name() string
	// Start initializes the exporter
	Start(ctx context.Context) error
	// Stop shuts down the exporter
	Stop(ctx context.Context) error
	// Export exports signals to the destination
	Export(ctx context.Context, signalType sigdef.SignalType, signals []sigdef.Signal) error
	// SupportedSignals returns which signal types this exporter supports
	SupportedSignals() []sigdef.SignalType
}

// SignalExporter is an interface for signal-specific exporters
type SignalExporter interface {
	// Export exports a batch of signals
	Export(ctx context.Context, signals []sigdef.Signal) error
}

// MetricsExporter exports metrics
type MetricsExporter interface {
	SignalExporter
	// ExportMetrics exports metrics with temporality configuration
	ExportMetrics(ctx context.Context, metrics interface{}) error
}

// TracesExporter exports traces
type TracesExporter interface {
	SignalExporter
	// ExportSpans exports trace spans
	ExportSpans(ctx context.Context, spans interface{}) error
}

// LogsExporter exports logs
type LogsExporter interface {
	SignalExporter
	// ExportLogs exports log records
	ExportLogs(ctx context.Context, logs interface{}) error
}

// ProfilesExporter exports profiles
type ProfilesExporter interface {
	SignalExporter
	// ExportProfiles exports profiling data
	ExportProfiles(ctx context.Context, profiles interface{}) error
}

// Config holds unified exporter configuration
type Config struct {
	// OTLP configuration
	OTLP OTLPConfig `mapstructure:"otlp"`
	// Prometheus configuration for metrics exposure
	Prometheus PrometheusConfig `mapstructure:"prometheus"`
	// Debug configuration for debug exporter
	Debug DebugConfig `mapstructure:"debug"`
	// BatchConfig for batching before export
	Batch BatchConfig `mapstructure:"batch"`
	// RetryConfig for retry behavior
	Retry RetryConfig `mapstructure:"retry"`
}

// OTLPConfig holds OTLP exporter configuration
type OTLPConfig struct {
	// Enabled controls whether OTLP export is active
	Enabled bool `mapstructure:"enabled"`
	// Endpoint is the primary OTLP endpoint
	Endpoint string `mapstructure:"endpoint"`
	// Protocol is grpc or http
	Protocol string `mapstructure:"protocol"`
	// Headers to send with requests
	Headers map[string]string `mapstructure:"headers"`
	// Compression to use (gzip, none)
	Compression string `mapstructure:"compression"`
	// TLS configuration
	TLS TLSConfig `mapstructure:"tls"`
	// Timeout for requests
	Timeout time.Duration `mapstructure:"timeout"`
	// Per-signal configuration overrides
	Metrics  OTLPSignalConfig `mapstructure:"metrics"`
	Traces   OTLPSignalConfig `mapstructure:"traces"`
	Logs     OTLPSignalConfig `mapstructure:"logs"`
	Profiles OTLPSignalConfig `mapstructure:"profiles"`
}

// OTLPSignalConfig holds per-signal OTLP configuration
type OTLPSignalConfig struct {
	// Enabled controls whether this signal is exported
	Enabled bool `mapstructure:"enabled"`
	// Endpoint overrides the main endpoint for this signal
	Endpoint string `mapstructure:"endpoint"`
	// Headers overrides the main headers for this signal
	Headers map[string]string `mapstructure:"headers"`
}

// PrometheusConfig holds Prometheus exporter configuration
type PrometheusConfig struct {
	// Enabled controls whether Prometheus exposition is active
	Enabled bool `mapstructure:"enabled"`
	// Listen is the address to listen on
	Listen string `mapstructure:"listen"`
	// Path is the metrics path
	Path string `mapstructure:"path"`
	// Namespace for metric names
	Namespace string `mapstructure:"namespace"`
}

// DebugConfig holds debug exporter configuration
type DebugConfig struct {
	// Enabled controls whether debug export is active
	Enabled bool `mapstructure:"enabled"`
	// Verbosity level (basic, normal, detailed)
	Verbosity string `mapstructure:"verbosity"`
	// SamplingInitial is the initial number of messages to log
	SamplingInitial int `mapstructure:"sampling_initial"`
	// SamplingThereafter is how often to log messages after initial
	SamplingThereafter int `mapstructure:"sampling_thereafter"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	// Enabled controls whether TLS is enabled
	Enabled bool `mapstructure:"enabled"`
	// CAFile is the path to the CA certificate
	CAFile string `mapstructure:"ca_file"`
	// CertFile is the path to the client certificate
	CertFile string `mapstructure:"cert_file"`
	// KeyFile is the path to the client key
	KeyFile string `mapstructure:"key_file"`
	// InsecureSkipVerify skips server certificate verification
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
	// ServerName is the server name for verification
	ServerName string `mapstructure:"server_name"`
}

// BatchConfig holds batching configuration
type BatchConfig struct {
	// Enabled controls whether batching is active
	Enabled bool `mapstructure:"enabled"`
	// MaxBatchSize is the maximum number of items in a batch
	MaxBatchSize int `mapstructure:"max_batch_size"`
	// MaxBatchBytes is the maximum bytes in a batch
	MaxBatchBytes int `mapstructure:"max_batch_bytes"`
	// Timeout is the maximum time to wait for a batch
	Timeout time.Duration `mapstructure:"timeout"`
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	// Enabled controls whether retry is active
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

// DefaultConfig returns default exporter configuration
func DefaultConfig() Config {
	return Config{
		OTLP: OTLPConfig{
			Enabled:     true,
			Protocol:    "grpc",
			Compression: "gzip",
			Timeout:     30 * time.Second,
			Metrics:     OTLPSignalConfig{Enabled: true},
			Traces:      OTLPSignalConfig{Enabled: true},
			Logs:        OTLPSignalConfig{Enabled: true},
			Profiles:    OTLPSignalConfig{Enabled: false},
		},
		Prometheus: PrometheusConfig{
			Enabled:   false,
			Listen:    ":9090",
			Path:      "/metrics",
			Namespace: "telegen",
		},
		Debug: DebugConfig{
			Enabled:            false,
			Verbosity:          "normal",
			SamplingInitial:    5,
			SamplingThereafter: 200,
		},
		Batch: BatchConfig{
			Enabled:      true,
			MaxBatchSize: 1000,
			Timeout:      5 * time.Second,
		},
		Retry: RetryConfig{
			Enabled:             true,
			InitialInterval:     5 * time.Second,
			MaxInterval:         30 * time.Second,
			MaxElapsedTime:      5 * time.Minute,
			Multiplier:          1.5,
			RandomizationFactor: 0.5,
		},
	}
}
