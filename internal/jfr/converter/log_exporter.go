// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package converter provides JFR to JSON and OTLP conversion functionality.
package converter

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

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

// OTLPLogExporter exports JFR profile events as OTLP Logs
type OTLPLogExporter struct {
	config       OTLPLogExporterConfig
	log          *slog.Logger
	client       *http.Client
	logConverter *LogConverter

	mu      sync.Mutex
	pending []*ProfileEvent
}

// OTLPLogExporterConfig holds configuration for the OTLP log exporter
type OTLPLogExporterConfig struct {
	// Endpoint is the OTLP logs endpoint (e.g., http://localhost:4318/v1/logs)
	Endpoint string

	// Headers to include in requests
	Headers map[string]string

	// Compression type (gzip, none)
	Compression string

	// Timeout for requests
	Timeout time.Duration

	// BatchSize is the number of log records to batch before sending
	BatchSize int

	// FlushInterval is how often to flush logs even if batch is not full
	FlushInterval time.Duration

	// IncludeStackTrace includes full stack trace in log body
	IncludeStackTrace bool

	// IncludeRawJSON includes the full JSON representation in log body
	IncludeRawJSON bool

	// Service metadata
	ServiceName   string
	Namespace     string
	PodName       string
	ContainerName string
	NodeName      string
	ClusterName   string
}

// DefaultOTLPLogExporterConfig returns default configuration
func DefaultOTLPLogExporterConfig() OTLPLogExporterConfig {
	return OTLPLogExporterConfig{
		Endpoint:          "http://localhost:4318/v1/logs",
		Compression:       "gzip",
		Timeout:           30 * time.Second,
		BatchSize:         100,
		FlushInterval:     10 * time.Second,
		IncludeStackTrace: true,
		IncludeRawJSON:    true,
	}
}

// NewOTLPLogExporter creates a new OTLP log exporter for JFR events
func NewOTLPLogExporter(cfg OTLPLogExporterConfig, log *slog.Logger) (*OTLPLogExporter, error) {
	if log == nil {
		log = slog.Default()
	}

	logConverter := NewLogConverter(LogExportConfig{
		ServiceName:   cfg.ServiceName,
		Namespace:     cfg.Namespace,
		PodName:       cfg.PodName,
		ContainerName: cfg.ContainerName,
		NodeName:      cfg.NodeName,
		ClusterName:   cfg.ClusterName,
	})

	return &OTLPLogExporter{
		config:       cfg,
		log:          log.With("component", "jfr_otlp_log_exporter"),
		client:       &http.Client{Timeout: cfg.Timeout},
		logConverter: logConverter,
		pending:      make([]*ProfileEvent, 0, cfg.BatchSize),
	}, nil
}

// Export exports a profile event as an OTLP log
func (e *OTLPLogExporter) Export(ctx context.Context, event *ProfileEvent) error {
	if event == nil {
		return nil
	}

	e.mu.Lock()
	e.pending = append(e.pending, event)

	// Check if we should flush
	if len(e.pending) >= e.config.BatchSize {
		events := e.pending
		e.pending = make([]*ProfileEvent, 0, e.config.BatchSize)
		e.mu.Unlock()

		return e.flush(ctx, events)
	}

	e.mu.Unlock()
	return nil
}

// ExportBatch exports multiple profile events as OTLP logs
func (e *OTLPLogExporter) ExportBatch(ctx context.Context, events []*ProfileEvent) error {
	if len(events) == 0 {
		return nil
	}

	return e.flush(ctx, events)
}

// Flush exports all pending events
func (e *OTLPLogExporter) Flush(ctx context.Context) error {
	e.mu.Lock()
	events := e.pending
	e.pending = make([]*ProfileEvent, 0, e.config.BatchSize)
	e.mu.Unlock()

	if len(events) == 0 {
		return nil
	}

	return e.flush(ctx, events)
}

// Close closes the exporter and flushes pending events
func (e *OTLPLogExporter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.Flush(ctx)
}

// flush exports a batch of profile events as OTLP logs
func (e *OTLPLogExporter) flush(ctx context.Context, events []*ProfileEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Split into smaller batches to avoid request body too large errors
	batchSize := e.config.BatchSize
	if batchSize <= 0 {
		batchSize = 10 // Default to 10 events per batch
	}

	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}
		chunk := events[i:end]

		if err := e.flushChunk(ctx, chunk); err != nil {
			return err
		}
	}

	return nil
}

// flushChunk exports a single chunk of profile events as OTLP logs
func (e *OTLPLogExporter) flushChunk(ctx context.Context, events []*ProfileEvent) error {
	if len(events) == 0 {
		return nil
	}

	e.log.Debug("exporting JFR events as OTLP logs", "count", len(events))

	// Convert to OTLP Logs format
	logs := e.logConverter.ConvertToLogs(events)

	// Marshal to OTLP protobuf
	marshaler := plogotlp.NewExportRequestFromLogs(logs)
	data, err := marshaler.MarshalProto()
	if err != nil {
		return fmt.Errorf("failed to marshal logs to protobuf: %w", err)
	}

	// Compress if configured
	body := data
	contentEncoding := ""
	if e.config.Compression == "gzip" {
		compressed, err := e.compress(data)
		if err != nil {
			return fmt.Errorf("failed to compress logs: %w", err)
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
		return fmt.Errorf("failed to send OTLP logs request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("OTLP logs export failed with status %d: %s", resp.StatusCode, string(body))
	}

	e.log.Debug("successfully exported JFR events as OTLP logs",
		"count", len(events),
		"status", resp.StatusCode,
	)

	return nil
}

// compress compresses data using gzip
func (e *OTLPLogExporter) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)

	if _, err := gw.Write(data); err != nil {
		return nil, err
	}

	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ExportLogs exports plog.Logs directly (implements LogExporter interface)
func (e *OTLPLogExporter) ExportLogs(ctx context.Context, logs plog.Logs) error {
	// Marshal to OTLP protobuf
	marshaler := plogotlp.NewExportRequestFromLogs(logs)
	data, err := marshaler.MarshalProto()
	if err != nil {
		return fmt.Errorf("failed to marshal logs to protobuf: %w", err)
	}

	// Compress if configured
	body := data
	contentEncoding := ""
	if e.config.Compression == "gzip" {
		compressed, err := e.compress(data)
		if err != nil {
			return fmt.Errorf("failed to compress logs: %w", err)
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
		return fmt.Errorf("failed to send OTLP logs request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("OTLP logs export failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
