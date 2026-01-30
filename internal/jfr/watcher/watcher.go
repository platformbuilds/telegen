// Package watcher provides file watching functionality for JFR files.
package watcher

import (
	"context"
	"crypto/md5"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/jfr/converter"
	"go.uber.org/zap"
)

// Options configures the watcher
type Options struct {
	InputDir     string
	OutputDir    string
	PollInterval time.Duration
	Workers      int
	Converter    *converter.Converter
	Logger       *zap.Logger
}

// Watcher watches for JFR files and processes them
type Watcher struct {
	opts           Options
	logger         *zap.Logger
	processedFiles sync.Map // map[string]string (path -> hash)
	workQueue      chan string
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
	return &Watcher{
		opts:      opts,
		logger:    opts.Logger,
		workQueue: make(chan string, 100),
	}
}

// Run starts the watcher and blocks until context is cancelled
func (w *Watcher) Run(ctx context.Context) error {
	// Ensure directories exist
	if err := os.MkdirAll(w.opts.InputDir, 0755); err != nil {
		return fmt.Errorf("failed to create input directory: %w", err)
	}
	if err := os.MkdirAll(w.opts.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	w.logger.Info("Watcher starting",
		zap.String("inputDir", w.opts.InputDir),
		zap.String("outputDir", w.opts.OutputDir),
		zap.Duration("pollInterval", w.opts.PollInterval),
		zap.Int("workers", w.opts.Workers),
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

	// Generate output filename
	baseName := strings.TrimSuffix(filepath.Base(jfrPath), ".jfr")
	timestamp := time.Now().Format("20060102_150405")
	outputPath := filepath.Join(w.opts.OutputDir, fmt.Sprintf("%s_%s.json", baseName, timestamp))

	// Write JSON
	if err := w.opts.Converter.WriteJSON(result.Events, outputPath); err != nil {
		logger.Error("Failed to write JSON output", zap.Error(err))
		return
	}

	// Mark as processed
	if hash, err := w.fileHash(jfrPath); err == nil {
		w.processedFiles.Store(jfrPath, hash)
	}

	logger.Info("Successfully processed JFR file",
		zap.Int("events", len(result.Events)),
		zap.Int64("samples", result.TotalSamples),
		zap.String("output", outputPath),
		zap.Duration("duration", time.Since(start)),
	)
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
