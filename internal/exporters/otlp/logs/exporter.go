// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package logs

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

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

// Exporter exports profile events as OTLP Logs
type Exporter struct {
	config    ExporterConfig
	log       *slog.Logger
	client    *http.Client
	converter *Converter

	mu      sync.Mutex
	pending []*ProfileEvent
}

// NewExporter creates a new OTLP log exporter for profile events
func NewExporter(cfg ExporterConfig, log *slog.Logger) (*Exporter, error) {
	if log == nil {
		log = slog.Default()
	}

	return &Exporter{
		config:    cfg,
		log:       log.With("component", "otlp_logs_exporter"),
		client:    &http.Client{Timeout: cfg.Timeout},
		converter: NewConverter(cfg),
		pending:   make([]*ProfileEvent, 0, cfg.BatchSize),
	}, nil
}

// Export exports a profile event as an OTLP log
func (e *Exporter) Export(ctx context.Context, event *ProfileEvent) error {
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
func (e *Exporter) ExportBatch(ctx context.Context, events []*ProfileEvent) error {
	if len(events) == 0 {
		return nil
	}

	return e.flush(ctx, events)
}

// Flush exports all pending events
func (e *Exporter) Flush(ctx context.Context) error {
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
func (e *Exporter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.Flush(ctx)
}

// flush exports a batch of profile events as OTLP logs
func (e *Exporter) flush(ctx context.Context, events []*ProfileEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Split into smaller batches to avoid request body too large errors
	batchSize := e.config.BatchSize
	if batchSize <= 0 {
		batchSize = 10
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
func (e *Exporter) flushChunk(ctx context.Context, events []*ProfileEvent) error {
	if len(events) == 0 {
		return nil
	}

	e.log.Debug("exporting profile events as OTLP logs", "count", len(events))

	// Convert to OTLP Logs format
	logs := e.converter.ConvertToLogs(events)

	// Marshal to OTLP protobuf
	marshaler := plogotlp.NewExportRequestFromLogs(logs)
	data, err := marshaler.MarshalProto()
	if err != nil {
		return fmt.Errorf("failed to marshal logs to protobuf: %w", err)
	}

	// Compress if configured
	var body io.Reader
	contentEncoding := ""
	if e.config.Compression == "gzip" {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			return fmt.Errorf("failed to compress logs: %w", err)
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("failed to close gzip writer: %w", err)
		}
		body = &buf
		contentEncoding = "gzip"
	} else {
		body = bytes.NewReader(data)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", e.config.Endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	for k, v := range e.config.Headers {
		req.Header.Set(k, v)
	}

	// Send request
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send logs: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to export logs: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	e.log.Debug("exported profile events", "count", len(events), "status", resp.StatusCode)
	return nil
}
