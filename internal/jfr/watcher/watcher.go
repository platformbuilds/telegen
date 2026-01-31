// Package watcher provides file watching functionality for JFR files.
package watcher

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/exporters/otlp/profiles"
	"github.com/platformbuilds/telegen/internal/jfr/converter"
	"go.uber.org/zap"
)

// ProfileExporter interface for exporting profiles directly
type ProfileExporter interface {
	ExportProfiles(ctx context.Context, profs []*profiles.Profile) error
	Flush(ctx context.Context) error
}

// LogExporter interface for exporting JFR events as logs
type LogExporter interface {
	ExportBatch(ctx context.Context, events []*converter.ProfileEvent) error
	Flush(ctx context.Context) error
}

// Options configures the watcher
type Options struct {
	InputDir     string
	OutputDir    string
	PollInterval time.Duration
	Workers      int
	Converter    *converter.Converter
	Logger       *zap.Logger

	// Direct export options
	DirectExport   bool
	SkipFileOutput bool
	Exporter       ProfileExporter
	ProfileChan    chan<- *profiles.Profile // Optional channel for streaming profiles

	// Log export options
	LogExportEnabled bool
	LogExporter      LogExporter
}

// Watcher watches for JFR files and processes them
type Watcher struct {
	opts           Options
	logger         *zap.Logger
	processedFiles sync.Map // map[string]string (path -> hash)
	workQueue      chan string
	jfrConverter   *profiles.JFRConverter
}

// New creates a new Watcher
func New(opts Options) *Watcher {
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.Logger == nil {
		opts.Logger, _ = zap.NewProduction()
	}

	// Create JFR converter for direct export
	var jfrConv *profiles.JFRConverter
	if opts.DirectExport {
		convOpts := profiles.JFRConverterOptions{}
		if opts.Converter != nil {
			convOpts.ServiceName = opts.Converter.ServiceName()
			convOpts.PodName = opts.Converter.PodName()
			convOpts.Namespace = opts.Converter.Namespace()
			convOpts.NodeName = opts.Converter.NodeName()
		}
		jfrConv = profiles.NewJFRConverterWithOptions(convOpts)
	}

	return &Watcher{
		opts:         opts,
		logger:       opts.Logger,
		workQueue:    make(chan string, 100),
		jfrConverter: jfrConv,
	}
}

// Run starts the watcher and blocks until context is cancelled
func (w *Watcher) Run(ctx context.Context) error {
	// Ensure input directory exists
	if err := os.MkdirAll(w.opts.InputDir, 0755); err != nil {
		return fmt.Errorf("failed to create input directory: %w", err)
	}

	// Only create output directory if we're writing files
	if !w.opts.SkipFileOutput || !w.opts.DirectExport {
		if err := os.MkdirAll(w.opts.OutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	w.logger.Info("Watcher starting",
		zap.String("inputDir", w.opts.InputDir),
		zap.String("outputDir", w.opts.OutputDir),
		zap.Duration("pollInterval", w.opts.PollInterval),
		zap.Int("workers", w.opts.Workers),
		zap.Bool("directExport", w.opts.DirectExport),
		zap.Bool("skipFileOutput", w.opts.SkipFileOutput),
	)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < w.opts.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			w.worker(ctx, workerID)
		}(i)
	}

	// Polling loop
	ticker := time.NewTicker(w.opts.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Watcher shutting down")
			close(w.workQueue)
			wg.Wait()
			return ctx.Err()
		case <-ticker.C:
			w.scanForFiles()
		}
	}
}

func (w *Watcher) scanForFiles() {
	err := filepath.WalkDir(w.opts.InputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".jfr") {
			return nil
		}

		// Check if file is still being written (modified in last 2 seconds)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if time.Since(info.ModTime()) < 2*time.Second {
			return nil
		}

		// Check if already processed
		hash, err := w.fileHash(path)
		if err != nil {
			w.logger.Warn("Failed to hash file", zap.String("path", path), zap.Error(err))
			return nil
		}
		if existingHash, ok := w.processedFiles.Load(path); ok {
			if existingHash.(string) == hash {
				return nil // Already processed, no changes
			}
		}

		// Queue for processing
		select {
		case w.workQueue <- path:
			w.logger.Debug("Queued file for processing", zap.String("path", path))
		default:
			w.logger.Warn("Work queue full, skipping file", zap.String("path", path))
		}

		return nil
	})
	if err != nil {
		w.logger.Error("Failed to scan directory", zap.Error(err))
	}
}

func (w *Watcher) worker(ctx context.Context, id int) {
	w.logger.Debug("Worker started", zap.Int("id", id))
	for {
		select {
		case <-ctx.Done():
			return
		case path, ok := <-w.workQueue:
			if !ok {
				return
			}
			w.processFile(ctx, path)
		}
	}
}

func (w *Watcher) processFile(ctx context.Context, jfrPath string) {
	logger := w.logger.With(zap.String("file", filepath.Base(jfrPath)))
	logger.Info("Processing JFR file")

	start := time.Now()

	// Convert JFR to events
	result, err := w.opts.Converter.Convert(ctx, jfrPath)
	if err != nil {
		logger.Error("Failed to convert JFR file", zap.Error(err))
		return
	}

	if len(result.Events) == 0 {
		logger.Warn("No profile events found in JFR file")
		// Still mark as processed
		if hash, err := w.fileHash(jfrPath); err == nil {
			w.processedFiles.Store(jfrPath, hash)
		}
		return
	}

	var outputPath string
	var exportedProfiles int
	var exportedLogs int

	// Direct export to OTLP Profiles if enabled
	if w.opts.DirectExport && w.jfrConverter != nil {
		exportedProfiles, err = w.exportProfilesDirect(ctx, result, logger)
		if err != nil {
			logger.Error("Failed to export profiles directly", zap.Error(err))
			// Fall through to file output if not skipping
		}
	}

	// Export as OTLP Logs if enabled
	if w.opts.LogExportEnabled && w.opts.LogExporter != nil {
		exportedLogs, err = w.exportLogsOTLP(ctx, result, logger)
		if err != nil {
			logger.Error("Failed to export logs", zap.Error(err))
		}
	}

	// Write JSON file output (unless skipped)
	if !w.opts.SkipFileOutput || !w.opts.DirectExport {
		// Generate output filename
		baseName := strings.TrimSuffix(filepath.Base(jfrPath), ".jfr")
		timestamp := time.Now().Format("20060102_150405")
		outputPath = filepath.Join(w.opts.OutputDir, fmt.Sprintf("%s_%s.json", baseName, timestamp))

		// Write JSON
		if err := w.opts.Converter.WriteJSON(result.Events, outputPath); err != nil {
			logger.Error("Failed to write JSON output", zap.Error(err))
			return
		}
	}

	// Mark as processed
	if hash, err := w.fileHash(jfrPath); err == nil {
		w.processedFiles.Store(jfrPath, hash)
	}

	logger.Info("Successfully processed JFR file",
		zap.Int("events", len(result.Events)),
		zap.Int64("samples", result.TotalSamples),
		zap.String("output", outputPath),
		zap.Int("exportedProfiles", exportedProfiles),
		zap.Int("exportedLogs", exportedLogs),
		zap.Bool("directExport", w.opts.DirectExport),
		zap.Bool("logExport", w.opts.LogExportEnabled),
		zap.Duration("duration", time.Since(start)),
	)
}

// exportLogsOTLP exports profile events as OTLP Logs
func (w *Watcher) exportLogsOTLP(ctx context.Context, result *converter.ConvertResult, logger *zap.Logger) (int, error) {
	if w.opts.LogExporter == nil {
		return 0, fmt.Errorf("log exporter not initialized")
	}

	if len(result.Events) == 0 {
		return 0, nil
	}

	// Export events as logs
	if err := w.opts.LogExporter.ExportBatch(ctx, result.Events); err != nil {
		return 0, fmt.Errorf("failed to export logs: %w", err)
	}

	logger.Debug("Exported JFR events as OTLP logs",
		zap.Int("eventCount", len(result.Events)),
	)

	return len(result.Events), nil
}

// exportProfilesDirect converts events to OTLP profiles and exports them
func (w *Watcher) exportProfilesDirect(ctx context.Context, result *converter.ConvertResult, logger *zap.Logger) (int, error) {
	if w.jfrConverter == nil {
		return 0, fmt.Errorf("JFR converter not initialized")
	}

	// Convert ProfileEvents to JFREvents for the OTLP converter
	jfrEvents := make([]*profiles.JFREvent, 0, len(result.Events))
	for _, evt := range result.Events {
		jfrEvent := convertProfileEventToJFREvent(evt)
		if jfrEvent != nil {
			jfrEvents = append(jfrEvents, jfrEvent)
		}
	}

	if len(jfrEvents) == 0 {
		return 0, nil
	}

	// Convert to OTLP profiles
	otlpProfiles, err := w.jfrConverter.ConvertEvents(jfrEvents)
	if err != nil {
		return 0, fmt.Errorf("failed to convert to OTLP profiles: %w", err)
	}

	if len(otlpProfiles) == 0 {
		return 0, nil
	}

	// Stream to channel if configured
	if w.opts.ProfileChan != nil {
		for _, p := range otlpProfiles {
			select {
			case w.opts.ProfileChan <- p:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
	}

	// Export via exporter if configured
	if w.opts.Exporter != nil {
		if err := w.opts.Exporter.ExportProfiles(ctx, otlpProfiles); err != nil {
			return 0, fmt.Errorf("failed to export profiles: %w", err)
		}
	}

	logger.Debug("Exported profiles directly",
		zap.Int("profileCount", len(otlpProfiles)),
		zap.Int("eventCount", len(jfrEvents)),
	)

	return len(otlpProfiles), nil
}

// convertProfileEventToJFREvent converts a converter.ProfileEvent to profiles.JFREvent
func convertProfileEventToJFREvent(evt *converter.ProfileEvent) *profiles.JFREvent {
	if evt == nil {
		return nil
	}

	jfrEvent := &profiles.JFREvent{
		Type:         evt.EventType,
		ProfileType:  evt.ProfileType,
		ThreadName:   evt.ThreadName,
		ThreadID:     evt.ThreadID,
		SampleWeight: evt.SampleWeight,
		DurationNs:   evt.DurationNs,
		State:        evt.State,
	}

	// Parse timestamp
	if t, err := time.Parse(time.RFC3339Nano, evt.Timestamp); err == nil {
		jfrEvent.StartTime = t
	} else {
		jfrEvent.StartTime = time.Now()
	}

	// Parse stack trace from JSON
	if evt.StackTrace != "" {
		var frames []converter.StackFrame
		if err := parseStackTrace(evt.StackTrace, &frames); err == nil && len(frames) > 0 {
			jfrEvent.StackFrames = make([]profiles.JFRStackFrame, 0, len(frames))
			for _, f := range frames {
				jfrEvent.StackFrames = append(jfrEvent.StackFrames, profiles.JFRStackFrame{
					Class:  f.Class,
					Method: f.Method,
					File:   f.File,
					Line:   f.Line,
					BCI:    f.BCI,
				})
			}
		}
	}

	return jfrEvent
}

// parseStackTrace parses the JSON stack trace string
func parseStackTrace(stackJSON string, frames *[]converter.StackFrame) error {
	if stackJSON == "" {
		return nil
	}
	return json.Unmarshal([]byte(stackJSON), frames)
}

func (w *Watcher) fileHash(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	// Use size + mtime as a quick hash
	data := fmt.Sprintf("%s:%d:%d", path, info.Size(), info.ModTime().UnixNano())
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash), nil
}

// Stats returns current watcher statistics
type Stats struct {
	ProcessedFiles int
	QueuedFiles    int
}

// GetStats returns current statistics
func (w *Watcher) GetStats() Stats {
	var count int
	w.processedFiles.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return Stats{
		ProcessedFiles: count,
		QueuedFiles:    len(w.workQueue),
	}
}
