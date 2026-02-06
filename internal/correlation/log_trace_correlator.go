// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"context"
	"sync"
	"time"
)

// TraceContextProvider allows log parsers to look up trace context
// for logs where trace context wasn't embedded in the log content.
//
// This bridges the gap between:
// - eBPF log_enricher: knows PID:TID → TraceContext at syscall time
// - filelog parser: reads logs from files, knows container + timestamp
//
// The correlator maintains a time-windowed cache indexed by container ID
// and approximate timestamp, allowing filelog to enrich plain-text logs.
type TraceContextProvider interface {
	// LookupTraceContext finds trace context for a log entry.
	//
	// Parameters:
	//   - containerID: K8s container ID (from log file path or metadata)
	//   - logTimestamp: When the log was written (from parsed timestamp)
	//   - tolerance: Time window for matching (e.g., 1s for log timestamp skew)
	//
	// Returns:
	//   - traceID: W3C trace ID (32 hex chars) or empty if not found
	//   - spanID: W3C span ID (16 hex chars) or empty if not found
	//   - found: true if a matching trace context was found
	LookupTraceContext(containerID string, logTimestamp time.Time, tolerance time.Duration) (traceID, spanID string, found bool)
}

// LogTraceEntry represents a cached trace context entry.
type LogTraceEntry struct {
	ContainerID string
	Timestamp   time.Time
	TraceID     TraceID
	SpanID      SpanID
	TraceFlags  TraceFlags
	ExpiresAt   time.Time
}

// LogTraceCorrelator maintains a time-windowed cache of trace contexts
// indexed by container ID for correlation with file-based log collection.
//
// Architecture:
//
//	┌─────────────────────────────────────────────────────────────────────┐
//	│                    eBPF log_enricher                                │
//	│                                                                     │
//	│  kprobe/ksys_write intercepts:                                      │
//	│    - PID/TID of writing process                                     │
//	│    - Log content                                                    │
//	│    - Active trace context from BPF map                              │
//	│                                                                     │
//	│  Calls: correlator.RecordTraceContext(containerID, timestamp,       │
//	│                                        traceID, spanID)             │
//	└─────────────────────────────────────────────────────────────────────┘
//	                              │
//	                              ▼
//	┌─────────────────────────────────────────────────────────────────────┐
//	│                   LogTraceCorrelator                                │
//	│                                                                     │
//	│  Time-windowed cache:                                               │
//	│                                                                     │
//	│  containerID:timestamp_bucket → {TraceID, SpanID, ExpiresAt}        │
//	│                                                                     │
//	│  ┌─────────────────────────────────────────────────────────────┐   │
//	│  │ "abc123:1704067200" → {trace: "a1b2...", span: "c3d4..."}   │   │
//	│  │ "abc123:1704067201" → {trace: "e5f6...", span: "g7h8..."}   │   │
//	│  │ "def456:1704067200" → {trace: "i9j0...", span: "k1l2..."}   │   │
//	│  └─────────────────────────────────────────────────────────────┘   │
//	│                                                                     │
//	│  Eviction: entries expire after TTL (default: 30s)                  │
//	└─────────────────────────────────────────────────────────────────────┘
//	                              │
//	                              ▼
//	┌─────────────────────────────────────────────────────────────────────┐
//	│                    filelog Pipeline                                 │
//	│                                                                     │
//	│  1. Read log line from /var/log/pods/{ns}_{pod}_{uid}/{container}/  │
//	│  2. Parse container runtime format (Docker JSON, CRI-O, containerd) │
//	│  3. Extract log timestamp                                           │
//	│  4. Call: correlator.LookupTraceContext(containerID, timestamp, 1s) │
//	│  5. If found, set TraceID/SpanID on ParsedLog                       │
//	│  6. Convert to OTLP LogRecord with trace correlation                │
//	└─────────────────────────────────────────────────────────────────────┘
type LogTraceCorrelator struct {
	mu      sync.RWMutex
	entries map[string]*LogTraceEntry // key: containerID:timestamp_bucket

	// Configuration
	bucketSize time.Duration // Timestamp bucketing granularity (default: 100ms)
	ttl        time.Duration // How long to keep entries (default: 30s)
	maxEntries int           // Maximum entries to prevent memory issues

	// Shutdown
	ctx    context.Context
	cancel context.CancelFunc

	// Metrics
	hits       int64
	misses     int64
	evictions  int64
	recordings int64
}

// LogTraceCorrelatorConfig configures the correlator.
type LogTraceCorrelatorConfig struct {
	// BucketSize is the timestamp bucketing granularity.
	// Smaller values are more precise but use more memory.
	// Default: 100ms
	BucketSize time.Duration

	// TTL is how long to keep trace context entries.
	// Should be longer than the max delay between log write and file read.
	// Default: 30s
	TTL time.Duration

	// MaxEntries limits memory usage.
	// Default: 100000
	MaxEntries int
}

// DefaultLogTraceCorrelatorConfig returns sensible defaults.
func DefaultLogTraceCorrelatorConfig() LogTraceCorrelatorConfig {
	return LogTraceCorrelatorConfig{
		BucketSize: 100 * time.Millisecond,
		TTL:        30 * time.Second,
		MaxEntries: 100000,
	}
}

// NewLogTraceCorrelator creates a new correlator with the given config.
func NewLogTraceCorrelator(cfg LogTraceCorrelatorConfig) *LogTraceCorrelator {
	if cfg.BucketSize == 0 {
		cfg.BucketSize = 100 * time.Millisecond
	}
	if cfg.TTL == 0 {
		cfg.TTL = 30 * time.Second
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 100000
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &LogTraceCorrelator{
		entries:    make(map[string]*LogTraceEntry),
		bucketSize: cfg.BucketSize,
		ttl:        cfg.TTL,
		maxEntries: cfg.MaxEntries,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Start background eviction
	go c.evictionLoop()

	return c
}

// RecordTraceContext records trace context for a container at a given time.
// Called by log_enricher when it intercepts a log write.
func (c *LogTraceCorrelator) RecordTraceContext(
	containerID string,
	timestamp time.Time,
	traceID TraceID,
	spanID SpanID,
	traceFlags TraceFlags,
) {
	if !traceID.IsValid() || !spanID.IsValid() {
		return
	}

	key := c.makeKey(containerID, timestamp)
	entry := &LogTraceEntry{
		ContainerID: containerID,
		Timestamp:   timestamp,
		TraceID:     traceID,
		SpanID:      spanID,
		TraceFlags:  traceFlags,
		ExpiresAt:   time.Now().Add(c.ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest if at capacity
	if len(c.entries) >= c.maxEntries {
		c.evictOldestLocked()
	}

	c.entries[key] = entry
	c.recordings++
}

// LookupTraceContext implements TraceContextProvider.
func (c *LogTraceCorrelator) LookupTraceContext(
	containerID string,
	logTimestamp time.Time,
	tolerance time.Duration,
) (traceID, spanID string, found bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Try exact bucket first
	key := c.makeKey(containerID, logTimestamp)
	if entry, ok := c.entries[key]; ok && time.Now().Before(entry.ExpiresAt) {
		c.hits++
		return entry.TraceID.String(), entry.SpanID.String(), true
	}

	// Try adjacent buckets within tolerance
	numBuckets := int(tolerance / c.bucketSize)
	for i := 1; i <= numBuckets; i++ {
		// Check earlier bucket
		earlier := logTimestamp.Add(-time.Duration(i) * c.bucketSize)
		key = c.makeKey(containerID, earlier)
		if entry, ok := c.entries[key]; ok && time.Now().Before(entry.ExpiresAt) {
			c.hits++
			return entry.TraceID.String(), entry.SpanID.String(), true
		}

		// Check later bucket
		later := logTimestamp.Add(time.Duration(i) * c.bucketSize)
		key = c.makeKey(containerID, later)
		if entry, ok := c.entries[key]; ok && time.Now().Before(entry.ExpiresAt) {
			c.hits++
			return entry.TraceID.String(), entry.SpanID.String(), true
		}
	}

	c.misses++
	return "", "", false
}

// makeKey creates a cache key from container ID and bucketed timestamp.
func (c *LogTraceCorrelator) makeKey(containerID string, ts time.Time) string {
	bucket := ts.UnixNano() / int64(c.bucketSize)
	return containerID + ":" + string(rune(bucket))
}

// evictionLoop periodically removes expired entries.
func (c *LogTraceCorrelator) evictionLoop() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

// evictExpired removes all expired entries.
func (c *LogTraceCorrelator) evictExpired() {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			c.evictions++
		}
	}
}

// evictOldestLocked removes the oldest entry. Must hold write lock.
func (c *LogTraceCorrelator) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
		c.evictions++
	}
}

// Stats returns correlator statistics.
func (c *LogTraceCorrelator) Stats() (entries, hits, misses, evictions, recordings int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return int64(len(c.entries)), c.hits, c.misses, c.evictions, c.recordings
}

// Stop stops the background eviction loop and cleans up resources.
func (c *LogTraceCorrelator) Stop() {
	c.cancel()
}

// Global correlator instance for use across packages
var globalCorrelator *LogTraceCorrelator
var globalCorrelatorOnce sync.Once

// GetGlobalLogTraceCorrelator returns the global correlator instance.
// Creates one with default config if not already initialized.
func GetGlobalLogTraceCorrelator() *LogTraceCorrelator {
	globalCorrelatorOnce.Do(func() {
		globalCorrelator = NewLogTraceCorrelator(DefaultLogTraceCorrelatorConfig())
	})
	return globalCorrelator
}

// SetGlobalLogTraceCorrelator sets the global correlator instance.
// Should be called early in application startup.
func SetGlobalLogTraceCorrelator(c *LogTraceCorrelator) {
	globalCorrelator = c
}
