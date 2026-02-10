// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// SymbolMetrics tracks symbol resolution metrics
type SymbolMetrics struct {
	// Resolution outcomes
	resolved   atomic.Uint64
	unresolved atomic.Uint64

	// By source
	resolvedGo     atomic.Uint64
	resolvedELF    atomic.Uint64
	resolvedJIT    atomic.Uint64
	resolvedKernel atomic.Uint64
	resolvedDWARF  atomic.Uint64

	// Cache metrics
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64

	// Performance
	resolutionTime atomic.Int64 // nanoseconds

	// Errors
	errors atomic.Uint64

	// Prometheus metrics (optional)
	promResolved   *prometheus.CounterVec
	promCache      *prometheus.CounterVec
	promLatency    prometheus.Histogram
	promCacheSize  prometheus.Gauge
	promRegistered bool
}

// NewSymbolMetrics creates a new symbol metrics tracker
func NewSymbolMetrics() *SymbolMetrics {
	return &SymbolMetrics{}
}

// RegisterPrometheus registers metrics with Prometheus
func (m *SymbolMetrics) RegisterPrometheus(namespace string) error {
	if m.promRegistered {
		return nil
	}

	m.promResolved = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "profiler_symbols_resolved_total",
			Help:      "Total number of symbols resolved by source",
		},
		[]string{"source", "status"},
	)

	m.promCache = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "profiler_symbol_cache_total",
			Help:      "Symbol cache hit/miss counters",
		},
		[]string{"result"},
	)

	m.promLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "profiler_symbol_resolution_duration_seconds",
			Help:      "Time spent resolving symbols",
			Buckets:   prometheus.ExponentialBuckets(0.000001, 2, 20), // 1μs to ~1s
		},
	)

	m.promCacheSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "profiler_symbol_cache_size",
			Help:      "Current size of symbol cache",
		},
	)

	if err := prometheus.Register(m.promResolved); err != nil {
		return err
	}
	if err := prometheus.Register(m.promCache); err != nil {
		return err
	}
	if err := prometheus.Register(m.promLatency); err != nil {
		return err
	}
	if err := prometheus.Register(m.promCacheSize); err != nil {
		return err
	}

	m.promRegistered = true
	return nil
}

// RecordResolved records a successful symbol resolution
func (m *SymbolMetrics) RecordResolved(source string) {
	m.resolved.Add(1)

	switch source {
	case "go":
		m.resolvedGo.Add(1)
	case "elf":
		m.resolvedELF.Add(1)
	case "jit":
		m.resolvedJIT.Add(1)
	case "kernel":
		m.resolvedKernel.Add(1)
	case "dwarf":
		m.resolvedDWARF.Add(1)
	}

	if m.promResolved != nil {
		m.promResolved.WithLabelValues(source, "resolved").Inc()
	}
}

// RecordUnresolved records a failed symbol resolution
func (m *SymbolMetrics) RecordUnresolved() {
	m.unresolved.Add(1)
	if m.promResolved != nil {
		m.promResolved.WithLabelValues("none", "unresolved").Inc()
	}
}

// RecordCacheHit records a cache hit
func (m *SymbolMetrics) RecordCacheHit() {
	m.cacheHits.Add(1)
	if m.promCache != nil {
		m.promCache.WithLabelValues("hit").Inc()
	}
}

// RecordCacheMiss records a cache miss
func (m *SymbolMetrics) RecordCacheMiss() {
	m.cacheMisses.Add(1)
	if m.promCache != nil {
		m.promCache.WithLabelValues("miss").Inc()
	}
}

// RecordResolutionTime records time spent resolving a symbol
func (m *SymbolMetrics) RecordResolutionTime(duration time.Duration) {
	m.resolutionTime.Add(duration.Nanoseconds())
	if m.promLatency != nil {
		m.promLatency.Observe(duration.Seconds())
	}
}

// RecordError records a symbol resolution error
func (m *SymbolMetrics) RecordError() {
	m.errors.Add(1)
}

// UpdateCacheSize updates the cache size gauge
func (m *SymbolMetrics) UpdateCacheSize(size int) {
	if m.promCacheSize != nil {
		m.promCacheSize.Set(float64(size))
	}
}

// Stats returns current metrics statistics
func (m *SymbolMetrics) Stats() SymbolStats {
	return SymbolStats{
		Resolved:       m.resolved.Load(),
		Unresolved:     m.unresolved.Load(),
		ResolvedGo:     m.resolvedGo.Load(),
		ResolvedELF:    m.resolvedELF.Load(),
		ResolvedJIT:    m.resolvedJIT.Load(),
		ResolvedKernel: m.resolvedKernel.Load(),
		ResolvedDWARF:  m.resolvedDWARF.Load(),
		CacheHits:      m.cacheHits.Load(),
		CacheMisses:    m.cacheMisses.Load(),
		Errors:         m.errors.Load(),
		AvgTimeNs:      m.avgResolutionTime(),
	}
}

func (m *SymbolMetrics) avgResolutionTime() int64 {
	totalTime := m.resolutionTime.Load()
	totalResolved := m.resolved.Load()
	if totalResolved == 0 {
		return 0
	}
	return totalTime / int64(totalResolved)
}

// SymbolStats holds symbol resolution statistics
type SymbolStats struct {
	Resolved       uint64
	Unresolved     uint64
	ResolvedGo     uint64
	ResolvedELF    uint64
	ResolvedJIT    uint64
	ResolvedKernel uint64
	ResolvedDWARF  uint64
	CacheHits      uint64
	CacheMisses    uint64
	Errors         uint64
	AvgTimeNs      int64
}
