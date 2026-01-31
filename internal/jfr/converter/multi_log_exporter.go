// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package converter provides JFR to JSON and OTLP conversion functionality.
package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MultiLogExporter exports JFR profile events to multiple destinations:
// stdout, disk file, and/or OTLP endpoint
type MultiLogExporter struct {
	config       MultiLogExporterConfig
	log          *slog.Logger
	logConverter *LogConverter

	// OTLP exporter (optional)
	otlpExporter *OTLPLogExporter

	// Disk output
	diskFile    *os.File
	diskMu      sync.Mutex
	diskSize    int64
	diskFileNum int

	mu      sync.Mutex
	pending []*ProfileEvent
}

// MultiLogExporterConfig holds configuration for multi-destination log export
type MultiLogExporterConfig struct {
	// Stdout output
	StdoutEnabled bool
	StdoutFormat  string // "json" or "text"
	StdoutWriter  io.Writer

	// Disk output
	DiskEnabled    bool
	DiskPath       string
	DiskRotateSize int64 // bytes
	DiskMaxFiles   int

	// OTLP output
	OTLPEnabled bool
	OTLPConfig  OTLPLogExporterConfig

	// Common settings
	BatchSize     int
	FlushInterval time.Duration

	// Service metadata
	ServiceName   string
	Namespace     string
	PodName       string
	ContainerName string
	NodeName      string
	ClusterName   string
}

// DefaultMultiLogExporterConfig returns default configuration
func DefaultMultiLogExporterConfig() MultiLogExporterConfig {
	return MultiLogExporterConfig{
		StdoutEnabled:  false,
		StdoutFormat:   "json",
		DiskEnabled:    false,
		DiskRotateSize: 100 * 1024 * 1024, // 100MB
		DiskMaxFiles:   5,
		OTLPEnabled:    true,
		OTLPConfig:     DefaultOTLPLogExporterConfig(),
		BatchSize:      100,
		FlushInterval:  10 * time.Second,
	}
}

// NewMultiLogExporter creates a new multi-destination log exporter
func NewMultiLogExporter(cfg MultiLogExporterConfig, log *slog.Logger) (*MultiLogExporter, error) {
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

	exporter := &MultiLogExporter{
		config:       cfg,
		log:          log.With("component", "jfr_multi_log_exporter"),
		logConverter: logConverter,
		pending:      make([]*ProfileEvent, 0, cfg.BatchSize),
	}

	// Set default stdout writer
	if cfg.StdoutWriter == nil {
		exporter.config.StdoutWriter = os.Stdout
	}

	// Initialize OTLP exporter if enabled
	if cfg.OTLPEnabled {
		otlpExporter, err := NewOTLPLogExporter(cfg.OTLPConfig, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
		exporter.otlpExporter = otlpExporter
	}

	// Initialize disk output if enabled
	if cfg.DiskEnabled && cfg.DiskPath != "" {
		if err := exporter.initDiskOutput(); err != nil {
			return nil, fmt.Errorf("failed to initialize disk output: %w", err)
		}
	}

	exporter.log.Info("multi-log exporter initialized",
		"stdout", cfg.StdoutEnabled,
		"disk", cfg.DiskEnabled,
		"diskPath", cfg.DiskPath,
		"otlp", cfg.OTLPEnabled,
	)

	return exporter, nil
}

// initDiskOutput initializes disk file output
func (e *MultiLogExporter) initDiskOutput() error {
	// Create directory if needed
	dir := filepath.Dir(e.config.DiskPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open file for appending
	f, err := os.OpenFile(e.config.DiskPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	e.diskFile = f

	// Get current file size
	info, err := f.Stat()
	if err == nil {
		e.diskSize = info.Size()
	}

	return nil
}

// Export exports a profile event to all configured destinations
func (e *MultiLogExporter) Export(ctx context.Context, event *ProfileEvent) error {
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

// ExportBatch exports multiple profile events to all configured destinations
func (e *MultiLogExporter) ExportBatch(ctx context.Context, events []*ProfileEvent) error {
	if len(events) == 0 {
		return nil
	}

	return e.flush(ctx, events)
}

// Flush exports all pending events
func (e *MultiLogExporter) Flush(ctx context.Context) error {
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
func (e *MultiLogExporter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Flush(ctx); err != nil {
		e.log.Error("failed to flush on close", "error", err)
	}

	// Close disk file
	if e.diskFile != nil {
		e.diskMu.Lock()
		e.diskFile.Close()
		e.diskMu.Unlock()
	}

	// Close OTLP exporter
	if e.otlpExporter != nil {
		e.otlpExporter.Close()
	}

	return nil
}

// flush exports events to all configured destinations
func (e *MultiLogExporter) flush(ctx context.Context, events []*ProfileEvent) error {
	if len(events) == 0 {
		return nil
	}

	var errs []error

	// Export to stdout if enabled
	if e.config.StdoutEnabled {
		if err := e.writeToStdout(events); err != nil {
			errs = append(errs, fmt.Errorf("stdout: %w", err))
		}
	}

	// Export to disk if enabled
	if e.config.DiskEnabled && e.diskFile != nil {
		if err := e.writeToDisk(events); err != nil {
			errs = append(errs, fmt.Errorf("disk: %w", err))
		}
	}

	// Export to OTLP if enabled
	if e.config.OTLPEnabled && e.otlpExporter != nil {
		if err := e.otlpExporter.ExportBatch(ctx, events); err != nil {
			errs = append(errs, fmt.Errorf("otlp: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("export errors: %v", errs)
	}

	e.log.Debug("flushed JFR logs to destinations",
		"count", len(events),
		"stdout", e.config.StdoutEnabled,
		"disk", e.config.DiskEnabled,
		"otlp", e.config.OTLPEnabled,
	)

	return nil
}

// writeToStdout writes events to stdout
func (e *MultiLogExporter) writeToStdout(events []*ProfileEvent) error {
	for _, event := range events {
		if event == nil {
			continue
		}

		output := e.formatEvent(event)
		if _, err := fmt.Fprintln(e.config.StdoutWriter, output); err != nil {
			return err
		}
	}
	return nil
}

// writeToDisk writes events to disk file
func (e *MultiLogExporter) writeToDisk(events []*ProfileEvent) error {
	e.diskMu.Lock()
	defer e.diskMu.Unlock()

	for _, event := range events {
		if event == nil {
			continue
		}

		output := e.formatEvent(event)
		line := output + "\n"
		n, err := e.diskFile.WriteString(line)
		if err != nil {
			return err
		}
		e.diskSize += int64(n)

		// Check for rotation
		if e.config.DiskRotateSize > 0 && e.diskSize >= e.config.DiskRotateSize {
			if err := e.rotateDiskFile(); err != nil {
				e.log.Error("failed to rotate disk file", "error", err)
			}
		}
	}

	return nil
}

// rotateDiskFile rotates the disk log file
func (e *MultiLogExporter) rotateDiskFile() error {
	// Close current file
	if err := e.diskFile.Close(); err != nil {
		return err
	}

	// Rotate existing files
	for i := e.config.DiskMaxFiles - 1; i > 0; i-- {
		oldPath := fmt.Sprintf("%s.%d", e.config.DiskPath, i)
		newPath := fmt.Sprintf("%s.%d", e.config.DiskPath, i+1)
		os.Rename(oldPath, newPath)
	}

	// Rename current file to .1
	os.Rename(e.config.DiskPath, e.config.DiskPath+".1")

	// Delete oldest file if over limit
	oldestPath := fmt.Sprintf("%s.%d", e.config.DiskPath, e.config.DiskMaxFiles+1)
	os.Remove(oldestPath)

	// Create new file
	f, err := os.OpenFile(e.config.DiskPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	e.diskFile = f
	e.diskSize = 0
	e.diskFileNum++

	e.log.Info("rotated disk log file", "path", e.config.DiskPath, "rotationNum", e.diskFileNum)

	return nil
}

// formatEvent formats a profile event for text output
func (e *MultiLogExporter) formatEvent(event *ProfileEvent) string {
	if e.config.StdoutFormat == "text" {
		return fmt.Sprintf("[%s] %s - %s (samples=%d, state=%s)",
			time.Now().Format(time.RFC3339),
			event.EventType,
			event.ThreadName,
			event.TotalSamples,
			event.State,
		)
	}

	// JSON format (default)
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to marshal event: %s"}`, err)
	}
	return string(data)
}
