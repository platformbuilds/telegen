// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package profiles provides OTLP profile export functionality.
package profiles

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/profiler"
)

// OTLPExporter exports profiles in OpenTelemetry format
type OTLPExporter struct {
	config    ExporterConfig
	log       *slog.Logger
	client    *http.Client
	converter *PprofConverter

	mu      sync.Mutex
	pending []*profiler.Profile
}

// ExporterConfig holds OTLP exporter configuration
type ExporterConfig struct {
	// Endpoint is the OTLP profiles endpoint
	Endpoint string `mapstructure:"endpoint"`

	// Headers to include in requests
	Headers map[string]string `mapstructure:"headers"`

	// Compression type (gzip, none)
	Compression string `mapstructure:"compression"`

	// Timeout for requests
	Timeout time.Duration `mapstructure:"timeout"`

	// BatchSize is the number of profiles to batch
	BatchSize int `mapstructure:"batch_size"`

	// Insecure allows insecure connections
	Insecure bool `mapstructure:"insecure"`
}

// DefaultExporterConfig returns default exporter configuration
func DefaultExporterConfig() ExporterConfig {
	return ExporterConfig{
		Endpoint:    "http://localhost:4318/v1/profiles",
		Compression: "gzip",
		Timeout:     30 * time.Second,
		BatchSize:   100,
	}
}

// NewOTLPExporter creates a new OTLP profiles exporter
func NewOTLPExporter(cfg ExporterConfig, log *slog.Logger) (*OTLPExporter, error) {
	return &OTLPExporter{
		config:    cfg,
		log:       log.With("component", "otlp_profiles_exporter"),
		client:    &http.Client{Timeout: cfg.Timeout},
		converter: NewPprofConverter(),
		pending:   make([]*profiler.Profile, 0),
	}, nil
}

// Export exports a profile to the OTLP endpoint
func (e *OTLPExporter) Export(ctx context.Context, profile *profiler.Profile) error {
	if profile == nil {
		return nil
	}

	e.mu.Lock()
	e.pending = append(e.pending, profile)

	// Check if we should flush
	if len(e.pending) >= e.config.BatchSize {
		profiles := e.pending
		e.pending = make([]*profiler.Profile, 0)
		e.mu.Unlock()

		return e.flush(ctx, profiles)
	}

	e.mu.Unlock()
	return nil
}

// Flush exports all pending profiles
func (e *OTLPExporter) Flush(ctx context.Context) error {
	e.mu.Lock()
	profiles := e.pending
	e.pending = make([]*profiler.Profile, 0)
	e.mu.Unlock()

	if len(profiles) == 0 {
		return nil
	}

	return e.flush(ctx, profiles)
}

// Close closes the exporter
func (e *OTLPExporter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return e.Flush(ctx)
}

// flush exports a batch of profiles
func (e *OTLPExporter) flush(ctx context.Context, profiles []*profiler.Profile) error {
	if len(profiles) == 0 {
		return nil
	}

	e.log.Debug("exporting profiles", "count", len(profiles))

	// Convert to OTLP format
	data, err := e.convertToOTLP(profiles)
	if err != nil {
		return fmt.Errorf("failed to convert profiles: %w", err)
	}

	// Compress if configured
	body := data
	contentEncoding := ""
	if e.config.Compression == "gzip" {
		compressed, err := e.compress(data)
		if err != nil {
			return fmt.Errorf("failed to compress profiles: %w", err)
		}
		body = compressed
		contentEncoding = "gzip"
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}

	// Add custom headers
	for k, v := range e.config.Headers {
		req.Header.Set(k, v)
	}

	// Send request
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send profiles: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("export failed with status %d: %s", resp.StatusCode, string(body))
	}

	e.log.Debug("profiles exported successfully", "count", len(profiles))
	return nil
}

// convertToOTLP converts profiles to OTLP format
func (e *OTLPExporter) convertToOTLP(profiles []*profiler.Profile) ([]byte, error) {
	// Build OTLP profiles request
	// This is a simplified implementation - full implementation would use
	// opentelemetry-proto-go package

	var buf bytes.Buffer

	for _, profile := range profiles {
		// Convert each profile to pprof format first
		pprofData, err := e.converter.ToPprof(profile)
		if err != nil {
			e.log.Warn("failed to convert profile", "type", profile.Type, "error", err)
			continue
		}

		buf.Write(pprofData)
	}

	return buf.Bytes(), nil
}

// compress compresses data using gzip
func (e *OTLPExporter) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	if _, err := gz.Write(data); err != nil {
		return nil, err
	}

	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// OTLPProfile represents an OpenTelemetry profile
type OTLPProfile struct {
	ProfileID              []byte
	StartTimeUnixNano      uint64
	EndTimeUnixNano        uint64
	Attributes             []KeyValue
	DroppedAttributesCount uint32
	OriginalPayloadFormat  string
	OriginalPayload        []byte
}

// KeyValue represents a key-value pair
type KeyValue struct {
	Key   string
	Value interface{}
}

// ResourceProfiles represents profiles from a single resource
type ResourceProfiles struct {
	Resource      Resource
	ScopeProfiles []ScopeProfiles
	SchemaURL     string
}

// Resource represents a resource
type Resource struct {
	Attributes             []KeyValue
	DroppedAttributesCount uint32
}

// ScopeProfiles represents profiles from a single instrumentation scope
type ScopeProfiles struct {
	Scope     InstrumentationScope
	Profiles  []OTLPProfile
	SchemaURL string
}

// InstrumentationScope represents the scope that produced the profiles
type InstrumentationScope struct {
	Name       string
	Version    string
	Attributes []KeyValue
}
