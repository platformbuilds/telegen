// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package exporters provides a unified export factory for Telegen signals.
// All signals are exported with metadata attributes for indexing.
package exporters

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/prometheus/prompb"

	"github.com/platformbuilds/telegen/internal/exporters/remotewrite"
	"github.com/platformbuilds/telegen/internal/sigdef"
)

// UnifiedExporter provides a single interface for exporting all signal types
// to OTel Collector with consistent metadata enrichment.
type UnifiedExporter struct {
	cfg UnifiedExportConfig
	log *slog.Logger

	// Remote Write exporter for Prometheus metrics
	remoteWriter *remotewrite.OTelRemoteWriter

	mu      sync.RWMutex
	running bool
}

// UnifiedExportConfig configures the unified exporter
type UnifiedExportConfig struct {
	// OTel Collector configuration
	OTelCollector OTelCollectorExportConfig

	// Remote Write configuration (for Prometheus metrics)
	RemoteWrite RemoteWriteExportConfig

	// Whether to include signal metadata as attributes/labels
	IncludeSignalMetadata bool
}

// OTelCollectorExportConfig holds OTel Collector connection settings
type OTelCollectorExportConfig struct {
	// Endpoint for OTLP gRPC (e.g., "localhost:4317")
	GRPCEndpoint string

	// Endpoint for OTLP HTTP (e.g., "localhost:4318")
	HTTPEndpoint string

	// Protocol: "grpc" or "http"
	Protocol string

	// TLS configuration
	TLS TLSExportConfig

	// Headers to include in requests
	Headers map[string]string

	// Compression: "gzip" or "none"
	Compression string

	// Service information
	ServiceName      string
	ServiceVersion   string
	ServiceNamespace string
	ServiceInstance  string

	// Per-signal configuration
	Traces  SignalExportConfig
	Metrics SignalExportConfig
	Logs    SignalExportConfig
}

// RemoteWriteExportConfig holds Remote Write settings
type RemoteWriteExportConfig struct {
	// Enabled controls whether Remote Write is used
	Enabled bool

	// Endpoint for Remote Write (e.g., "http://localhost:19291/api/v1/push")
	Endpoint string

	// TLS configuration
	TLS TLSExportConfig

	// Headers to include in requests
	Headers map[string]string

	// TenantID for multi-tenant setups
	TenantID string

	// Compression: "snappy", "gzip", or "none"
	Compression string

	// Batch settings
	BatchSize     int
	FlushInterval time.Duration
}

// TLSExportConfig holds TLS settings for exports
type TLSExportConfig struct {
	Enabled            bool
	CAFile             string
	CertFile           string
	KeyFile            string
	InsecureSkipVerify bool
}

// SignalExportConfig holds per-signal export settings
type SignalExportConfig struct {
	Enabled       bool
	BatchSize     int
	FlushInterval time.Duration
}

// DefaultUnifiedExportConfig returns sensible defaults for local OTel Collector
func DefaultUnifiedExportConfig() UnifiedExportConfig {
	return UnifiedExportConfig{
		OTelCollector: OTelCollectorExportConfig{
			GRPCEndpoint:     "localhost:4317",
			HTTPEndpoint:     "localhost:4318",
			Protocol:         "grpc",
			Compression:      "gzip",
			ServiceName:      "telegen",
			ServiceVersion:   "1.0.0",
			ServiceNamespace: "telegen",
			Traces: SignalExportConfig{
				Enabled:       true,
				BatchSize:     512,
				FlushInterval: 5 * time.Second,
			},
			Metrics: SignalExportConfig{
				Enabled:       true,
				BatchSize:     1000,
				FlushInterval: 60 * time.Second,
			},
			Logs: SignalExportConfig{
				Enabled:       true,
				BatchSize:     512,
				FlushInterval: 5 * time.Second,
			},
		},
		RemoteWrite: RemoteWriteExportConfig{
			Enabled:       true,
			Endpoint:      "http://localhost:19291/api/v1/push",
			Compression:   "snappy",
			BatchSize:     1000,
			FlushInterval: 15 * time.Second,
		},
		IncludeSignalMetadata: true,
	}
}

// NewUnifiedExporter creates a new unified exporter
func NewUnifiedExporter(cfg UnifiedExportConfig, log *slog.Logger) (*UnifiedExporter, error) {
	if log == nil {
		log = slog.Default()
	}

	return &UnifiedExporter{
		cfg: cfg,
		log: log.With("component", "unified_exporter"),
	}, nil
}

// Start initializes and starts all exporters
func (e *UnifiedExporter) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	e.log.Info("starting unified exporter")

	// Store OTLP configuration for future use
	// OTLP exporter initialization will be added when otelexport package is ready
	endpoint := e.cfg.OTelCollector.GRPCEndpoint
	if e.cfg.OTelCollector.Protocol == "http" {
		endpoint = e.cfg.OTelCollector.HTTPEndpoint
	}
	e.log.Info("OTLP configuration stored", "endpoint", endpoint, "protocol", e.cfg.OTelCollector.Protocol)

	// Initialize Remote Write if enabled
	if e.cfg.RemoteWrite.Enabled {
		rwCfg := remotewrite.OTelCollectorConfig{
			Endpoint:              e.cfg.RemoteWrite.Endpoint,
			Compression:           e.cfg.RemoteWrite.Compression,
			TenantID:              e.cfg.RemoteWrite.TenantID,
			Headers:               e.cfg.RemoteWrite.Headers,
			Timeout:               30 * time.Second,
			BatchSize:             e.cfg.RemoteWrite.BatchSize,
			FlushInterval:         e.cfg.RemoteWrite.FlushInterval,
			MaxRetries:            3,
			RetryBackoff:          1 * time.Second,
			IncludeSignalMetadata: e.cfg.IncludeSignalMetadata,
		}

		// Configure TLS if enabled
		if e.cfg.RemoteWrite.TLS.Enabled {
			rwCfg.TLS = remotewrite.TLSConfig{
				Enable:             true,
				CAFile:             e.cfg.RemoteWrite.TLS.CAFile,
				CertFile:           e.cfg.RemoteWrite.TLS.CertFile,
				KeyFile:            e.cfg.RemoteWrite.TLS.KeyFile,
				InsecureSkipVerify: e.cfg.RemoteWrite.TLS.InsecureSkipVerify,
			}
		}

		rwExp, err := remotewrite.NewOTelRemoteWriter(rwCfg, e.log)
		if err != nil {
			return fmt.Errorf("failed to create Remote Write exporter: %w", err)
		}

		if err := rwExp.Start(ctx); err != nil {
			return fmt.Errorf("failed to start Remote Write exporter: %w", err)
		}
		e.remoteWriter = rwExp
	}

	e.running = true
	e.log.Info("unified exporter started",
		"otlp_endpoint", endpoint,
		"remote_write_enabled", e.cfg.RemoteWrite.Enabled,
	)

	return nil
}

// WriteMetrics writes metrics via Remote Write with signal metadata
func (e *UnifiedExporter) WriteMetrics(wr *prompb.WriteRequest, metadata *sigdef.SignalMetadata) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running {
		return fmt.Errorf("exporter not running")
	}

	if e.remoteWriter == nil {
		return fmt.Errorf("remote write not enabled")
	}

	return e.remoteWriter.WriteWithMetadata(wr, metadata)
}

// RemoteWriter returns the underlying Remote Write exporter for direct access
func (e *UnifiedExporter) RemoteWriter() *remotewrite.OTelRemoteWriter {
	return e.remoteWriter
}

// Shutdown gracefully shuts down all exporters
func (e *UnifiedExporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	e.log.Info("shutting down unified exporter")

	var errs []error

	if e.remoteWriter != nil {
		if err := e.remoteWriter.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("Remote Write shutdown: %w", err))
		}
	}

	e.running = false

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}
