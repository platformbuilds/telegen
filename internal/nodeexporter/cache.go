// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package nodeexporter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// MetricCache provides caching for collected metrics to reduce collection overhead.
// It implements a time-based cache with configurable TTL and supports concurrent access.
type MetricCache struct {
	mu          sync.RWMutex
	cache       []*dto.MetricFamily
	lastCollect time.Time
	ttl         time.Duration
	registry    *prometheus.Registry
	logger      *slog.Logger
	stats       CacheStats
}

// CacheStats holds statistics about cache performance.
type CacheStats struct {
	Hits       int64
	Misses     int64
	Evictions  int64
	LastUpdate time.Time
}

// DefaultCacheConfig returns default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled: true,
		TTL:     5 * time.Second,
	}
}

// NewMetricCache creates a new metric cache.
func NewMetricCache(registry *prometheus.Registry, ttl time.Duration, logger *slog.Logger) *MetricCache {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}

	return &MetricCache{
		registry: registry,
		ttl:      ttl,
		logger:   logger,
	}
}

// Gather returns cached metrics if valid, otherwise collects fresh metrics.
func (c *MetricCache) Gather() ([]*dto.MetricFamily, error) {
	// Try to return cached data first
	c.mu.RLock()
	if c.cache != nil && time.Since(c.lastCollect) < c.ttl {
		c.stats.Hits++
		result := c.cache
		c.mu.RUnlock()
		return result, nil
	}
	c.mu.RUnlock()

	// Cache miss - need to collect
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if c.cache != nil && time.Since(c.lastCollect) < c.ttl {
		c.stats.Hits++
		return c.cache, nil
	}

	c.stats.Misses++
	if c.cache != nil {
		c.stats.Evictions++
	}

	// Collect fresh metrics
	metrics, err := c.registry.Gather()
	if err != nil {
		return nil, err
	}

	c.cache = metrics
	c.lastCollect = time.Now()
	c.stats.LastUpdate = c.lastCollect

	c.logger.Debug("metric cache refreshed",
		"families", len(metrics),
		"hits", c.stats.Hits,
		"misses", c.stats.Misses)

	return metrics, nil
}

// Invalidate clears the cache, forcing a fresh collection on next Gather.
func (c *MetricCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = nil
	c.stats.Evictions++
}

// Stats returns current cache statistics.
func (c *MetricCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// HitRate returns the cache hit rate as a percentage.
func (c *MetricCache) HitRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.stats.Hits + c.stats.Misses
	if total == 0 {
		return 0
	}
	return float64(c.stats.Hits) / float64(total) * 100
}

// BatchProcessor handles batching of metrics for efficient export.
type BatchProcessor struct {
	batchSize    int
	flushTimeout time.Duration
	buffer       []*dto.MetricFamily
	bufferMu     sync.Mutex
	flushFn      func(context.Context, []*dto.MetricFamily) error
	logger       *slog.Logger

	// Stats
	batchesSent int64
	metricsSent int64
}

// BatchConfig holds configuration for batch processing.
type BatchConfig struct {
	// Size is the maximum number of metric families per batch
	Size int `yaml:"size"`

	// FlushTimeout is the maximum time to wait before flushing an incomplete batch
	FlushTimeout time.Duration `yaml:"flush_timeout"`

	// MaxRetries is the maximum number of retry attempts for failed batches
	MaxRetries int `yaml:"max_retries"`

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration `yaml:"retry_delay"`
}

// DefaultBatchConfig returns default batch configuration.
func DefaultBatchConfig() BatchConfig {
	return BatchConfig{
		Size:         100,
		FlushTimeout: 5 * time.Second,
		MaxRetries:   3,
		RetryDelay:   1 * time.Second,
	}
}

// NewBatchProcessor creates a new batch processor.
func NewBatchProcessor(
	batchSize int,
	flushTimeout time.Duration,
	flushFn func(context.Context, []*dto.MetricFamily) error,
	logger *slog.Logger,
) *BatchProcessor {
	if batchSize <= 0 {
		batchSize = 100
	}
	if flushTimeout <= 0 {
		flushTimeout = 5 * time.Second
	}

	return &BatchProcessor{
		batchSize:    batchSize,
		flushTimeout: flushTimeout,
		buffer:       make([]*dto.MetricFamily, 0, batchSize),
		flushFn:      flushFn,
		logger:       logger,
	}
}

// Add adds metrics to the buffer and flushes if batch size is reached.
func (b *BatchProcessor) Add(ctx context.Context, families []*dto.MetricFamily) error {
	b.bufferMu.Lock()
	defer b.bufferMu.Unlock()

	b.buffer = append(b.buffer, families...)

	// Flush if we've reached batch size
	if len(b.buffer) >= b.batchSize {
		return b.flushLocked(ctx)
	}

	return nil
}

// Flush forces a flush of the current buffer.
func (b *BatchProcessor) Flush(ctx context.Context) error {
	b.bufferMu.Lock()
	defer b.bufferMu.Unlock()
	return b.flushLocked(ctx)
}

// flushLocked flushes the buffer (caller must hold lock).
func (b *BatchProcessor) flushLocked(ctx context.Context) error {
	if len(b.buffer) == 0 {
		return nil
	}

	// Send the batch
	if err := b.flushFn(ctx, b.buffer); err != nil {
		b.logger.Error("failed to flush batch", "size", len(b.buffer), "err", err)
		return err
	}

	b.batchesSent++
	b.metricsSent += int64(len(b.buffer))

	b.logger.Debug("batch flushed",
		"size", len(b.buffer),
		"total_batches", b.batchesSent,
		"total_metrics", b.metricsSent)

	// Reset buffer
	b.buffer = make([]*dto.MetricFamily, 0, b.batchSize)

	return nil
}

// Stats returns batch processor statistics.
func (b *BatchProcessor) Stats() (batches, metrics int64) {
	b.bufferMu.Lock()
	defer b.bufferMu.Unlock()
	return b.batchesSent, b.metricsSent
}

// AdaptiveBatcher adjusts batch size based on export performance.
type AdaptiveBatcher struct {
	minBatchSize    int
	maxBatchSize    int
	currentSize     int
	targetLatency   time.Duration
	adjustInterval  time.Duration
	lastAdjust      time.Time
	recentLatencies []time.Duration
	mu              sync.Mutex
	logger          *slog.Logger
}

// NewAdaptiveBatcher creates a new adaptive batcher.
func NewAdaptiveBatcher(minSize, maxSize int, targetLatency time.Duration, logger *slog.Logger) *AdaptiveBatcher {
	if minSize <= 0 {
		minSize = 10
	}
	if maxSize <= minSize {
		maxSize = minSize * 10
	}

	return &AdaptiveBatcher{
		minBatchSize:    minSize,
		maxBatchSize:    maxSize,
		currentSize:     (minSize + maxSize) / 2,
		targetLatency:   targetLatency,
		adjustInterval:  30 * time.Second,
		recentLatencies: make([]time.Duration, 0, 10),
		logger:          logger,
	}
}

// RecordLatency records an export latency for adaptive sizing.
func (a *AdaptiveBatcher) RecordLatency(latency time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.recentLatencies = append(a.recentLatencies, latency)
	if len(a.recentLatencies) > 10 {
		a.recentLatencies = a.recentLatencies[1:]
	}

	// Adjust if enough time has passed
	if time.Since(a.lastAdjust) > a.adjustInterval {
		a.adjust()
	}
}

// CurrentSize returns the current recommended batch size.
func (a *AdaptiveBatcher) CurrentSize() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.currentSize
}

// adjust adjusts the batch size based on recent latencies.
func (a *AdaptiveBatcher) adjust() {
	if len(a.recentLatencies) < 3 {
		return
	}

	// Calculate average latency
	var total time.Duration
	for _, l := range a.recentLatencies {
		total += l
	}
	avgLatency := total / time.Duration(len(a.recentLatencies))

	oldSize := a.currentSize

	// If latency is too high, decrease batch size
	if avgLatency > a.targetLatency*2 {
		a.currentSize = max(a.minBatchSize, a.currentSize*3/4)
	} else if avgLatency > a.targetLatency {
		a.currentSize = max(a.minBatchSize, a.currentSize-10)
	} else if avgLatency < a.targetLatency/2 {
		// If latency is well below target, increase batch size
		a.currentSize = min(a.maxBatchSize, a.currentSize*5/4)
	} else if avgLatency < a.targetLatency*3/4 {
		a.currentSize = min(a.maxBatchSize, a.currentSize+10)
	}

	a.lastAdjust = time.Now()
	a.recentLatencies = a.recentLatencies[:0]

	if oldSize != a.currentSize {
		a.logger.Debug("batch size adjusted",
			"old_size", oldSize,
			"new_size", a.currentSize,
			"avg_latency", avgLatency,
			"target_latency", a.targetLatency)
	}
}
