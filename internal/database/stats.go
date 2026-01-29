// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"hash/fnv"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// QueryStats holds aggregated statistics for database queries.
type QueryStats struct {
	TotalQueries  uint64
	TotalErrors   uint64
	TotalDuration time.Duration
	MinDuration   time.Duration
	MaxDuration   time.Duration
	ErrorRate     float64
	ByDatabase    map[DatabaseType]*DatabaseStats
}

// DatabaseStats holds statistics for a specific database type.
type DatabaseStats struct {
	Type          DatabaseType
	QueryCount    uint64
	ErrorCount    uint64
	TotalDuration time.Duration
	ByQueryType   map[QueryType]*QueryTypeStats
}

// QueryTypeStats holds statistics for a specific query type.
type QueryTypeStats struct {
	Type          QueryType
	Count         uint64
	ErrorCount    uint64
	TotalDuration time.Duration
}

// QueryPatternStats holds statistics for a normalized query pattern.
type QueryPatternStats struct {
	Pattern       string
	DatabaseType  DatabaseType
	QueryType     QueryType
	Count         uint64
	ErrorCount    uint64
	TotalDuration time.Duration
	MinDuration   time.Duration
	MaxDuration   time.Duration
	P50           time.Duration
	P95           time.Duration
	P99           time.Duration
	LastSeen      time.Time

	// Reservoir sampling for percentile calculation
	samples     []time.Duration
	sampleCount uint64
}

// StatsAggregatorConfig holds configuration for the stats aggregator.
type StatsAggregatorConfig struct {
	// MaxPatterns is the maximum number of query patterns to track.
	MaxPatterns int

	// SampleSize is the reservoir sample size for percentile calculation.
	SampleSize int

	// FlushInterval is how often stats are flushed.
	FlushInterval time.Duration
}

// DefaultStatsConfig returns the default stats aggregator configuration.
func DefaultStatsConfig() StatsAggregatorConfig {
	return StatsAggregatorConfig{
		MaxPatterns:   10000,
		SampleSize:    1000,
		FlushInterval: 30 * time.Second,
	}
}

// StatsAggregator aggregates query statistics by normalized query pattern.
type StatsAggregator struct {
	config   StatsAggregatorConfig
	patterns map[uint64]*QueryPatternStats
	mu       sync.RWMutex

	// Global counters
	totalQueries atomic.Uint64
	totalErrors  atomic.Uint64
}

// NewStatsAggregator creates a new stats aggregator.
func NewStatsAggregator(config StatsAggregatorConfig) *StatsAggregator {
	return &StatsAggregator{
		config:   config,
		patterns: make(map[uint64]*QueryPatternStats),
	}
}

// Record records a database event.
func (sa *StatsAggregator) Record(event *DatabaseEvent) {
	sa.totalQueries.Add(1)
	if event.ErrorCode != 0 {
		sa.totalErrors.Add(1)
	}

	// Use normalized query if available, otherwise use original
	pattern := event.NormalizedQuery
	if pattern == "" {
		pattern = event.Query
	}

	hash := hashPattern(pattern, event.DatabaseType, event.QueryType)

	sa.mu.Lock()
	defer sa.mu.Unlock()

	stats, exists := sa.patterns[hash]
	if !exists {
		// Check if we've hit the max patterns limit
		if len(sa.patterns) >= sa.config.MaxPatterns {
			// Evict least recently used pattern
			sa.evictLRU()
		}

		stats = &QueryPatternStats{
			Pattern:      pattern,
			DatabaseType: event.DatabaseType,
			QueryType:    event.QueryType,
			MinDuration:  event.Latency,
			samples:      make([]time.Duration, 0, sa.config.SampleSize),
		}
		sa.patterns[hash] = stats
	}

	// Update statistics
	stats.Count++
	stats.TotalDuration += event.Latency
	stats.LastSeen = event.Timestamp

	if event.ErrorCode != 0 {
		stats.ErrorCount++
	}

	if event.Latency < stats.MinDuration {
		stats.MinDuration = event.Latency
	}
	if event.Latency > stats.MaxDuration {
		stats.MaxDuration = event.Latency
	}

	// Reservoir sampling for percentiles
	stats.sampleCount++
	if len(stats.samples) < sa.config.SampleSize {
		stats.samples = append(stats.samples, event.Latency)
	} else {
		// Replace with probability SampleSize/sampleCount
		idx := stats.sampleCount % uint64(sa.config.SampleSize)
		stats.samples[idx] = event.Latency
	}
}

// evictLRU removes the least recently used pattern.
func (sa *StatsAggregator) evictLRU() {
	var oldestHash uint64
	var oldestTime time.Time
	first := true

	for hash, stats := range sa.patterns {
		if first || stats.LastSeen.Before(oldestTime) {
			oldestHash = hash
			oldestTime = stats.LastSeen
			first = false
		}
	}

	if !first {
		delete(sa.patterns, oldestHash)
	}
}

// hashPattern computes a hash for a query pattern.
func hashPattern(pattern string, dbType DatabaseType, queryType QueryType) uint64 {
	h := fnv.New64a()
	h.Write([]byte(pattern))
	h.Write([]byte{byte(dbType), byte(queryType)})
	return h.Sum64()
}

// GetStats returns the current aggregated statistics.
func (sa *StatsAggregator) GetStats() *QueryStats {
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	stats := &QueryStats{
		TotalQueries: sa.totalQueries.Load(),
		TotalErrors:  sa.totalErrors.Load(),
		ByDatabase:   make(map[DatabaseType]*DatabaseStats),
	}

	if stats.TotalQueries > 0 {
		stats.ErrorRate = float64(stats.TotalErrors) / float64(stats.TotalQueries)
	}

	first := true
	for _, ps := range sa.patterns {
		stats.TotalDuration += ps.TotalDuration

		if first || ps.MinDuration < stats.MinDuration {
			stats.MinDuration = ps.MinDuration
		}
		if ps.MaxDuration > stats.MaxDuration {
			stats.MaxDuration = ps.MaxDuration
		}
		first = false

		// Aggregate by database type
		dbStats, ok := stats.ByDatabase[ps.DatabaseType]
		if !ok {
			dbStats = &DatabaseStats{
				Type:        ps.DatabaseType,
				ByQueryType: make(map[QueryType]*QueryTypeStats),
			}
			stats.ByDatabase[ps.DatabaseType] = dbStats
		}

		dbStats.QueryCount += ps.Count
		dbStats.ErrorCount += ps.ErrorCount
		dbStats.TotalDuration += ps.TotalDuration

		// Aggregate by query type
		qtStats, ok := dbStats.ByQueryType[ps.QueryType]
		if !ok {
			qtStats = &QueryTypeStats{Type: ps.QueryType}
			dbStats.ByQueryType[ps.QueryType] = qtStats
		}

		qtStats.Count += ps.Count
		qtStats.ErrorCount += ps.ErrorCount
		qtStats.TotalDuration += ps.TotalDuration
	}

	return stats
}

// GetPatternStats returns statistics for a specific query pattern.
func (sa *StatsAggregator) GetPatternStats(pattern string, dbType DatabaseType, queryType QueryType) *QueryPatternStats {
	hash := hashPattern(pattern, dbType, queryType)

	sa.mu.RLock()
	defer sa.mu.RUnlock()

	stats, exists := sa.patterns[hash]
	if !exists {
		return nil
	}

	// Calculate percentiles
	result := &QueryPatternStats{
		Pattern:       stats.Pattern,
		DatabaseType:  stats.DatabaseType,
		QueryType:     stats.QueryType,
		Count:         stats.Count,
		ErrorCount:    stats.ErrorCount,
		TotalDuration: stats.TotalDuration,
		MinDuration:   stats.MinDuration,
		MaxDuration:   stats.MaxDuration,
		LastSeen:      stats.LastSeen,
	}

	if len(stats.samples) > 0 {
		sorted := make([]time.Duration, len(stats.samples))
		copy(sorted, stats.samples)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

		result.P50 = sorted[len(sorted)*50/100]
		result.P95 = sorted[len(sorted)*95/100]
		if len(sorted) > 0 {
			result.P99 = sorted[len(sorted)*99/100]
		}
	}

	return result
}

// GetTopNByDuration returns the top N patterns by total duration.
func (sa *StatsAggregator) GetTopNByDuration(n int) []*QueryPatternStats {
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	all := make([]*QueryPatternStats, 0, len(sa.patterns))
	for _, stats := range sa.patterns {
		ps := &QueryPatternStats{
			Pattern:       stats.Pattern,
			DatabaseType:  stats.DatabaseType,
			QueryType:     stats.QueryType,
			Count:         stats.Count,
			ErrorCount:    stats.ErrorCount,
			TotalDuration: stats.TotalDuration,
			MinDuration:   stats.MinDuration,
			MaxDuration:   stats.MaxDuration,
			LastSeen:      stats.LastSeen,
		}
		all = append(all, ps)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].TotalDuration > all[j].TotalDuration
	})

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// GetTopNByCount returns the top N patterns by execution count.
func (sa *StatsAggregator) GetTopNByCount(n int) []*QueryPatternStats {
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	all := make([]*QueryPatternStats, 0, len(sa.patterns))
	for _, stats := range sa.patterns {
		ps := &QueryPatternStats{
			Pattern:       stats.Pattern,
			DatabaseType:  stats.DatabaseType,
			QueryType:     stats.QueryType,
			Count:         stats.Count,
			ErrorCount:    stats.ErrorCount,
			TotalDuration: stats.TotalDuration,
			MinDuration:   stats.MinDuration,
			MaxDuration:   stats.MaxDuration,
			LastSeen:      stats.LastSeen,
		}
		all = append(all, ps)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Count > all[j].Count
	})

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// GetTopNByErrorRate returns the top N patterns by error rate.
func (sa *StatsAggregator) GetTopNByErrorRate(n int) []*QueryPatternStats {
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	all := make([]*QueryPatternStats, 0, len(sa.patterns))
	for _, stats := range sa.patterns {
		if stats.Count == 0 {
			continue
		}
		ps := &QueryPatternStats{
			Pattern:       stats.Pattern,
			DatabaseType:  stats.DatabaseType,
			QueryType:     stats.QueryType,
			Count:         stats.Count,
			ErrorCount:    stats.ErrorCount,
			TotalDuration: stats.TotalDuration,
			MinDuration:   stats.MinDuration,
			MaxDuration:   stats.MaxDuration,
			LastSeen:      stats.LastSeen,
		}
		all = append(all, ps)
	}

	sort.Slice(all, func(i, j int) bool {
		rateI := float64(all[i].ErrorCount) / float64(all[i].Count)
		rateJ := float64(all[j].ErrorCount) / float64(all[j].Count)
		return rateI > rateJ
	})

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// Reset clears all statistics.
func (sa *StatsAggregator) Reset() {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	sa.patterns = make(map[uint64]*QueryPatternStats)
	sa.totalQueries.Store(0)
	sa.totalErrors.Store(0)
}
