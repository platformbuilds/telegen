// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package llm provides LLM token metrics collection for AI observability.
// Task: ML-013 - LLM Latency Breakdown
package llm

import (
	"math"
	"sync"
	"time"
)

// LatencyTracker tracks detailed latency breakdown for LLM requests
type LatencyTracker struct {
	mu sync.RWMutex

	// Per-model latency statistics
	stats map[string]*LatencyStats

	// Histogram buckets (in milliseconds)
	buckets []float64

	// Enable detailed percentile tracking
	enablePercentiles bool
}

// LatencyStats holds latency statistics for a model
type LatencyStats struct {
	// Model identifier
	Model    string
	Provider string

	// Time to First Token (TTFT) - critical for streaming UX
	TTFT LatencyDistribution

	// Inter-Token Latency (ITL) - time between tokens in streaming
	ITL LatencyDistribution

	// End-to-End Latency - total request time
	EndToEnd LatencyDistribution

	// Breakdown by phase
	QueueTime     LatencyDistribution // Time waiting in queue
	InferenceTime LatencyDistribution // Actual inference time
	NetworkTime   LatencyDistribution // Network overhead

	// Tokens per second statistics
	TokensPerSecond TokenRateStats

	// Request timing histograms
	TTFTHistogram map[float64]uint64
	E2EHistogram  map[float64]uint64

	// Sample count
	SampleCount uint64
}

// LatencyDistribution holds latency distribution statistics
type LatencyDistribution struct {
	// Count of samples
	Count uint64

	// Sum for average calculation
	Sum float64

	// Min and max
	Min float64
	Max float64

	// Running statistics for variance calculation
	M2 float64 // Sum of squared differences from mean

	// Percentiles (if enabled)
	P50 float64
	P90 float64
	P95 float64
	P99 float64
}

// TokenRateStats holds token generation rate statistics
type TokenRateStats struct {
	// Count of samples
	Count uint64

	// Sum for average
	Sum float64

	// Min and max
	Min float64
	Max float64

	// Average
	Avg float64
}

// LatencyEvent represents a single latency measurement
type LatencyEvent struct {
	// Request identification
	RequestID string
	Model     string
	Provider  string

	// Timing measurements (all in milliseconds)
	TTFTMs      float64 // Time to first token
	ITLAvgMs    float64 // Average inter-token latency
	EndToEndMs  float64 // Total request time
	QueueTimeMs float64 // Time in queue
	InferenceMs float64 // Inference time
	NetworkMs   float64 // Network overhead

	// Token count for rate calculation
	TokenCount uint32

	// Whether this was a streaming request
	IsStreaming bool

	// Timestamp
	Timestamp time.Time
}

// Default histogram buckets (in milliseconds)
var DefaultLatencyBuckets = []float64{
	10, 25, 50, 75, 100, 150, 200, 250, 300, 400, 500,
	750, 1000, 1500, 2000, 3000, 5000, 10000, 30000,
}

// NewLatencyTracker creates a new latency tracker
func NewLatencyTracker(enablePercentiles bool, customBuckets []float64) *LatencyTracker {
	buckets := customBuckets
	if len(buckets) == 0 {
		buckets = DefaultLatencyBuckets
	}

	return &LatencyTracker{
		stats:             make(map[string]*LatencyStats),
		buckets:           buckets,
		enablePercentiles: enablePercentiles,
	}
}

// Record records a latency event
func (lt *LatencyTracker) Record(event LatencyEvent) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	key := event.Provider + "/" + event.Model
	stats, ok := lt.stats[key]
	if !ok {
		stats = &LatencyStats{
			Model:         event.Model,
			Provider:      event.Provider,
			TTFTHistogram: make(map[float64]uint64),
			E2EHistogram:  make(map[float64]uint64),
		}
		// Initialize min values
		stats.TTFT.Min = math.MaxFloat64
		stats.ITL.Min = math.MaxFloat64
		stats.EndToEnd.Min = math.MaxFloat64
		stats.QueueTime.Min = math.MaxFloat64
		stats.InferenceTime.Min = math.MaxFloat64
		stats.NetworkTime.Min = math.MaxFloat64
		stats.TokensPerSecond.Min = math.MaxFloat64
		lt.stats[key] = stats
	}

	stats.SampleCount++

	// Update TTFT distribution
	if event.TTFTMs > 0 {
		updateDistribution(&stats.TTFT, event.TTFTMs)
		lt.updateHistogram(stats.TTFTHistogram, event.TTFTMs)
	}

	// Update ITL distribution
	if event.ITLAvgMs > 0 {
		updateDistribution(&stats.ITL, event.ITLAvgMs)
	}

	// Update end-to-end distribution
	if event.EndToEndMs > 0 {
		updateDistribution(&stats.EndToEnd, event.EndToEndMs)
		lt.updateHistogram(stats.E2EHistogram, event.EndToEndMs)
	}

	// Update phase breakdowns
	if event.QueueTimeMs > 0 {
		updateDistribution(&stats.QueueTime, event.QueueTimeMs)
	}
	if event.InferenceMs > 0 {
		updateDistribution(&stats.InferenceTime, event.InferenceMs)
	}
	if event.NetworkMs > 0 {
		updateDistribution(&stats.NetworkTime, event.NetworkMs)
	}

	// Update tokens per second
	if event.EndToEndMs > 0 && event.TokenCount > 0 {
		tokensPerSec := float64(event.TokenCount) / (event.EndToEndMs / 1000.0)
		updateTokenRate(&stats.TokensPerSecond, tokensPerSec)
	}
}

// updateDistribution updates a latency distribution with a new value
func updateDistribution(dist *LatencyDistribution, value float64) {
	dist.Count++
	dist.Sum += value

	if value < dist.Min {
		dist.Min = value
	}
	if value > dist.Max {
		dist.Max = value
	}

	// Welford's online algorithm for variance
	delta := value - (dist.Sum / float64(dist.Count))
	dist.M2 += delta * delta
}

// updateTokenRate updates token rate statistics
func updateTokenRate(stats *TokenRateStats, value float64) {
	stats.Count++
	stats.Sum += value

	if value < stats.Min {
		stats.Min = value
	}
	if value > stats.Max {
		stats.Max = value
	}

	stats.Avg = stats.Sum / float64(stats.Count)
}

// updateHistogram updates a histogram with a value
func (lt *LatencyTracker) updateHistogram(histogram map[float64]uint64, value float64) {
	// Find the appropriate bucket
	bucket := lt.buckets[len(lt.buckets)-1] // Default to last bucket
	for _, b := range lt.buckets {
		if value <= b {
			bucket = b
			break
		}
	}
	histogram[bucket]++
}

// GetStats returns latency statistics for a model
func (lt *LatencyTracker) GetStats(model, provider string) *LatencyStats {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	key := provider + "/" + model
	if stats, ok := lt.stats[key]; ok {
		// Return a copy
		copy := *stats
		return &copy
	}
	return nil
}

// GetAllStats returns all latency statistics
func (lt *LatencyTracker) GetAllStats() map[string]*LatencyStats {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	result := make(map[string]*LatencyStats, len(lt.stats))
	for k, v := range lt.stats {
		copy := *v
		result[k] = &copy
	}
	return result
}

// GetAverage returns the average for a distribution
func (dist *LatencyDistribution) GetAverage() float64 {
	if dist.Count == 0 {
		return 0
	}
	return dist.Sum / float64(dist.Count)
}

// GetVariance returns the variance for a distribution
func (dist *LatencyDistribution) GetVariance() float64 {
	if dist.Count < 2 {
		return 0
	}
	return dist.M2 / float64(dist.Count-1)
}

// GetStdDev returns the standard deviation for a distribution
func (dist *LatencyDistribution) GetStdDev() float64 {
	return math.Sqrt(dist.GetVariance())
}

// LatencySLO represents latency SLO definitions
type LatencySLO struct {
	// SLO name
	Name string

	// Target latency in milliseconds
	TargetMs float64

	// Target percentile (e.g., 95 for p95)
	Percentile float64

	// Metric type
	MetricType LatencyMetricType
}

// LatencyMetricType represents which latency metric to use
type LatencyMetricType int

const (
	LatencyMetricTTFT      LatencyMetricType = 0
	LatencyMetricE2E       LatencyMetricType = 1
	LatencyMetricITL       LatencyMetricType = 2
	LatencyMetricInference LatencyMetricType = 3
)

// SLOCompliance holds SLO compliance information
type SLOCompliance struct {
	// SLO definition
	SLO LatencySLO

	// Current value
	CurrentValue float64

	// Whether SLO is met
	IsMet bool

	// Percentage within SLO
	CompliancePercent float64

	// Number of violations
	ViolationCount uint64

	// Total samples
	TotalSamples uint64
}

// CheckSLO checks if a latency distribution meets an SLO
func CheckSLO(stats *LatencyStats, slo LatencySLO) *SLOCompliance {
	var dist *LatencyDistribution

	switch slo.MetricType {
	case LatencyMetricTTFT:
		dist = &stats.TTFT
	case LatencyMetricE2E:
		dist = &stats.EndToEnd
	case LatencyMetricITL:
		dist = &stats.ITL
	case LatencyMetricInference:
		dist = &stats.InferenceTime
	default:
		dist = &stats.EndToEnd
	}

	// For now, use average as the value (percentiles would need reservoir sampling)
	currentValue := dist.GetAverage()

	compliance := &SLOCompliance{
		SLO:          slo,
		CurrentValue: currentValue,
		IsMet:        currentValue <= slo.TargetMs,
		TotalSamples: dist.Count,
	}

	// Estimate compliance percentage from distribution
	if dist.Count > 0 && dist.Max > 0 {
		if currentValue <= slo.TargetMs {
			compliance.CompliancePercent = 100.0
		} else {
			// Estimate based on how far we are from target
			ratio := slo.TargetMs / currentValue
			compliance.CompliancePercent = ratio * 100
			if compliance.CompliancePercent > 100 {
				compliance.CompliancePercent = 100
			}
		}
	}

	return compliance
}
