// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ExportFunc is the function called to export batched data.
type ExportFunc func(ctx context.Context, signal SignalType, data []byte) error

// Batcher batches data before export.
type Batcher struct {
	cfg BatchConfig
	log *slog.Logger

	mu       sync.Mutex
	batches  map[SignalType]*batch
	exportFn ExportFunc

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// batch holds a single batch of data.
type batch struct {
	signal SignalType
	data   [][]byte
	size   int
	timer  *time.Timer
}

// NewBatcher creates a new batcher.
func NewBatcher(cfg BatchConfig, log *slog.Logger) *Batcher {
	return &Batcher{
		cfg:     cfg,
		log:     log.With("component", "batcher"),
		batches: make(map[SignalType]*batch),
		stopCh:  make(chan struct{}),
	}
}

// Start starts the batcher with the export function.
func (b *Batcher) Start(ctx context.Context, exportFn ExportFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.exportFn = exportFn
	b.log.Info("batcher started",
		"max_batch_size", b.cfg.MaxBatchSize,
		"max_batch_bytes", b.cfg.MaxBatchBytes,
		"timeout", b.cfg.Timeout,
	)
}

// Stop stops the batcher and flushes remaining batches.
func (b *Batcher) Stop(ctx context.Context) error {
	close(b.stopCh)

	// Flush all pending batches
	if err := b.Flush(ctx); err != nil {
		b.log.Warn("error flushing batches during shutdown", "error", err)
	}

	b.wg.Wait()
	return nil
}

// Add adds data to the batch for the specified signal.
func (b *Batcher) Add(ctx context.Context, signal SignalType, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Get or create batch for this signal
	bat, ok := b.batches[signal]
	if !ok {
		bat = &batch{
			signal: signal,
			data:   make([][]byte, 0, b.cfg.MaxBatchSize),
		}
		b.batches[signal] = bat
	}

	// Check if this single item exceeds max bytes
	if len(data) > b.cfg.MaxBatchBytes {
		// Export single item directly
		b.log.Debug("single item exceeds max batch bytes, exporting directly",
			"signal", signal,
			"size", len(data),
		)
		return b.exportLocked(ctx, signal, [][]byte{data})
	}

	// Check if adding this item would exceed limits
	if len(bat.data) >= b.cfg.MaxBatchSize || bat.size+len(data) > b.cfg.MaxBatchBytes {
		// Flush current batch first
		if err := b.flushBatchLocked(ctx, signal); err != nil {
			return err
		}
		bat = b.batches[signal]
		if bat == nil {
			bat = &batch{
				signal: signal,
				data:   make([][]byte, 0, b.cfg.MaxBatchSize),
			}
			b.batches[signal] = bat
		}
	}

	// Add to batch
	bat.data = append(bat.data, data)
	bat.size += len(data)

	// Start timer if this is the first item
	if len(bat.data) == 1 && b.cfg.Timeout > 0 {
		bat.timer = time.AfterFunc(b.cfg.Timeout, func() {
			b.flushOnTimeout(signal)
		})
	}

	return nil
}

// flushOnTimeout flushes a batch when the timeout fires.
func (b *Batcher) flushOnTimeout(signal SignalType) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bat, ok := b.batches[signal]
	if !ok || len(bat.data) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.Timeout)
	defer cancel()

	if err := b.flushBatchLocked(ctx, signal); err != nil {
		b.log.Warn("error flushing batch on timeout", "signal", signal, "error", err)
	}
}

// flushBatchLocked flushes a batch for a specific signal. Must hold mu.
func (b *Batcher) flushBatchLocked(ctx context.Context, signal SignalType) error {
	bat, ok := b.batches[signal]
	if !ok || len(bat.data) == 0 {
		return nil
	}

	// Stop timer
	if bat.timer != nil {
		bat.timer.Stop()
		bat.timer = nil
	}

	// Get data to export
	data := bat.data
	bat.data = make([][]byte, 0, b.cfg.MaxBatchSize)
	bat.size = 0

	return b.exportLocked(ctx, signal, data)
}

// exportLocked exports data. Must hold mu.
func (b *Batcher) exportLocked(ctx context.Context, signal SignalType, data [][]byte) error {
	if len(data) == 0 {
		return nil
	}

	// Combine data into single payload
	combined := combineData(data)

	b.log.Debug("exporting batch",
		"signal", signal,
		"items", len(data),
		"bytes", len(combined),
	)

	if b.exportFn == nil {
		return fmt.Errorf("export function not set")
	}

	// Export in background to not block Add
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		if err := b.exportFn(ctx, signal, combined); err != nil {
			b.log.Warn("batch export failed", "signal", signal, "error", err)
		}
	}()

	return nil
}

// Flush flushes all pending batches.
func (b *Batcher) Flush(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var errs []error
	for signal := range b.batches {
		if err := b.flushBatchLocked(ctx, signal); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("flush errors: %v", errs)
	}
	return nil
}

// FlushSignal flushes the batch for a specific signal.
func (b *Batcher) FlushSignal(ctx context.Context, signal SignalType) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.flushBatchLocked(ctx, signal)
}

// combineData combines multiple data slices into one.
// This is a simple concatenation - in practice, you'd want to
// properly merge protobuf messages or JSON arrays.
func combineData(data [][]byte) []byte {
	// Calculate total size
	totalSize := 0
	for _, d := range data {
		totalSize += len(d)
	}

	// Combine
	combined := make([]byte, 0, totalSize)
	for _, d := range data {
		combined = append(combined, d...)
	}

	return combined
}

// QueuedItems returns the number of items queued across all signals.
func (b *Batcher) QueuedItems() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	total := 0
	for _, bat := range b.batches {
		total += len(bat.data)
	}
	return total
}

// QueuedBytes returns the total bytes queued across all signals.
func (b *Batcher) QueuedBytes() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	total := 0
	for _, bat := range b.batches {
		total += bat.size
	}
	return total
}
