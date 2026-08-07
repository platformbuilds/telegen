// Package limits provides data quality controls including cardinality,
// rate limiting, and attribute limits for Telegen V3 pipeline.
package limits

import (
	"context"
	"fmt"
	"hash"
	"hash/fnv"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// CardinalityLimiter prevents cardinality explosion by limiting unique
// series per metric based on attribute combinations.
type CardinalityLimiter struct {
	config CardinalityConfig
	log    *slog.Logger

	// State
	mu              sync.RWMutex
	metrics         map[string]*metricCardinality // metric name -> cardinality state
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
	globalSeries    atomic.Int64
	limitedAttrSet  map[string]struct{}
	excludedAttrSet map[string]struct{}

	// Stats
	droppedSeries  atomic.Int64
	totalSeries    atomic.Int64
	limitedMetrics sync.Map // string -> struct{}
}

// CardinalityConfig configures cardinality limiting.
type CardinalityConfig struct {
	// Enabled toggles the limiter.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// GlobalLimit is the maximum unique series across all metrics.
	GlobalLimit int `yaml:"global_limit" json:"global_limit"`

	// DefaultPerMetricLimit is the default per-metric series limit.
	DefaultPerMetricLimit int `yaml:"default_per_metric_limit" json:"default_per_metric_limit"`

	// MetricLimits allows per-metric overrides.
	MetricLimits map[string]int `yaml:"metric_limits,omitempty" json:"metric_limits,omitempty"`

	// LimitedAttributes are attributes to consider for cardinality.
	// If empty, all attributes contribute to cardinality.
	LimitedAttributes []string `yaml:"limited_attributes,omitempty" json:"limited_attributes,omitempty"`

	// ExcludedAttributes are never considered for cardinality.
	ExcludedAttributes []string `yaml:"excluded_attributes,omitempty" json:"excluded_attributes,omitempty"`

	// Action on limit: "drop" or "sample"
	Action string `yaml:"action" json:"action"`

	// SampleRate is used when action is "sample" (0.0-1.0).
	SampleRate float64 `yaml:"sample_rate,omitempty" json:"sample_rate,omitempty"`

	// TTL for series tracking (to allow recovery after limit).
	TTL time.Duration `yaml:"ttl" json:"ttl"`

	// ReportInterval for logging cardinality stats.
	ReportInterval time.Duration `yaml:"report_interval" json:"report_interval"`
}

// DefaultCardinalityConfig returns sensible defaults.
func DefaultCardinalityConfig() CardinalityConfig {
	return CardinalityConfig{
		Enabled:               true,
		GlobalLimit:           100000,
		DefaultPerMetricLimit: 10000,
		Action:                "drop",
		TTL:                   30 * time.Minute,
		ReportInterval:        5 * time.Minute,
	}
}

// metricCardinality tracks per-metric series.
type metricCardinality struct {
	name    string
	limit   int
	series  map[uint64]int64 // hash -> last seen timestamp
	dropped int64
	mu      sync.RWMutex
}

// NewCardinalityLimiter creates a new cardinality limiter.
func NewCardinalityLimiter(config CardinalityConfig, log *slog.Logger) *CardinalityLimiter {
	if log == nil {
		log = slog.Default()
	}

	if config.TTL == 0 {
		config.TTL = 30 * time.Minute
	}
	if config.ReportInterval == 0 {
		config.ReportInterval = 5 * time.Minute
	}

	return &CardinalityLimiter{
		config:          config,
		log:             log.With("component", "cardinality-limiter"),
		metrics:         make(map[string]*metricCardinality),
		limitedAttrSet:  toAttrSet(config.LimitedAttributes),
		excludedAttrSet: toAttrSet(config.ExcludedAttributes),
	}
}

// Start begins cardinality tracking.
func (l *CardinalityLimiter) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return nil
	}

	l.ctx, l.cancel = context.WithCancel(ctx)
	l.running = true

	// Start background maintenance
	go l.maintenanceLoop()

	l.log.Info("started cardinality limiter",
		"global_limit", l.config.GlobalLimit,
		"per_metric_limit", l.config.DefaultPerMetricLimit,
	)

	return nil
}

// Stop stops the limiter.
func (l *CardinalityLimiter) Stop(ctx context.Context) error {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return nil
	}
	l.cancel()
	l.running = false
	l.mu.Unlock()

	l.log.Info("stopped cardinality limiter",
		"total_series", l.totalSeries.Load(),
		"dropped_series", l.droppedSeries.Load(),
	)

	return nil
}

// ProcessMetrics filters metrics exceeding cardinality limits.
func (l *CardinalityLimiter) ProcessMetrics(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	if !l.config.Enabled {
		return md, nil
	}

	// Process each resource
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			l.processScope(sm)
		}
	}

	return md, nil
}

// processScope processes metrics in a scope.
func (l *CardinalityLimiter) processScope(sm pmetric.ScopeMetrics) {
	// We need to iterate backwards for safe removal
	metrics := sm.Metrics()
	for i := metrics.Len() - 1; i >= 0; i-- {
		metric := metrics.At(i)
		l.processMetric(metric)
	}
}

// processMetric processes a single metric.
func (l *CardinalityLimiter) processMetric(metric pmetric.Metric) {
	name := metric.Name()
	mc := l.getOrCreateMetricCardinality(name)

	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		l.filterDataPoints(mc, metric.Gauge().DataPoints())
	case pmetric.MetricTypeSum:
		l.filterDataPoints(mc, metric.Sum().DataPoints())
	case pmetric.MetricTypeHistogram:
		l.filterHistogramDataPoints(mc, metric.Histogram().DataPoints())
	case pmetric.MetricTypeSummary:
		l.filterSummaryDataPoints(mc, metric.Summary().DataPoints())
	case pmetric.MetricTypeExponentialHistogram:
		l.filterExponentialHistogramDataPoints(mc, metric.ExponentialHistogram().DataPoints())
	}
}

// getOrCreateMetricCardinality gets or creates cardinality tracking for a metric.
func (l *CardinalityLimiter) getOrCreateMetricCardinality(name string) *metricCardinality {
	l.mu.RLock()
	mc, exists := l.metrics[name]
	l.mu.RUnlock()

	if exists {
		return mc
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check
	if mc, exists = l.metrics[name]; exists {
		return mc
	}

	limit := l.config.DefaultPerMetricLimit
	if customLimit, ok := l.config.MetricLimits[name]; ok {
		limit = customLimit
	}

	mc = &metricCardinality{
		name:   name,
		limit:  limit,
		series: make(map[uint64]int64),
	}
	l.metrics[name] = mc

	return mc
}

// filterDataPoints filters number data points based on cardinality.
func (l *CardinalityLimiter) filterDataPoints(mc *metricCardinality, dps pmetric.NumberDataPointSlice) {
	if dps.Len() == 0 {
		return
	}
	now := time.Now().UnixNano()
	allowedByHash := make(map[uint64]bool, dps.Len())
	keep := make([]bool, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		hash := l.hashAttributes(dp.Attributes())
		allowed, known := allowedByHash[hash]
		if !known {
			allowed = l.allowSeries(mc, hash, now)
			allowedByHash[hash] = allowed
		}
		keep[i] = allowed
		if !allowed {
			l.droppedSeries.Add(1)
			l.limitedMetrics.Store(mc.name, struct{}{})
		} else {
			l.totalSeries.Add(1)
		}
	}
	idx := 0
	dps.RemoveIf(func(_ pmetric.NumberDataPoint) bool {
		drop := !keep[idx]
		idx++
		return drop
	})
}

// filterHistogramDataPoints filters histogram data points.
func (l *CardinalityLimiter) filterHistogramDataPoints(mc *metricCardinality, dps pmetric.HistogramDataPointSlice) {
	if dps.Len() == 0 {
		return
	}
	now := time.Now().UnixNano()
	allowedByHash := make(map[uint64]bool, dps.Len())
	keep := make([]bool, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		hash := l.hashAttributes(dp.Attributes())
		allowed, known := allowedByHash[hash]
		if !known {
			allowed = l.allowSeries(mc, hash, now)
			allowedByHash[hash] = allowed
		}
		keep[i] = allowed
		if !allowed {
			l.droppedSeries.Add(1)
			l.limitedMetrics.Store(mc.name, struct{}{})
		} else {
			l.totalSeries.Add(1)
		}
	}
	idx := 0
	dps.RemoveIf(func(_ pmetric.HistogramDataPoint) bool {
		drop := !keep[idx]
		idx++
		return drop
	})
}

// filterSummaryDataPoints filters summary data points.
func (l *CardinalityLimiter) filterSummaryDataPoints(mc *metricCardinality, dps pmetric.SummaryDataPointSlice) {
	if dps.Len() == 0 {
		return
	}
	now := time.Now().UnixNano()
	allowedByHash := make(map[uint64]bool, dps.Len())
	keep := make([]bool, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		hash := l.hashAttributes(dp.Attributes())
		allowed, known := allowedByHash[hash]
		if !known {
			allowed = l.allowSeries(mc, hash, now)
			allowedByHash[hash] = allowed
		}
		keep[i] = allowed
		if !allowed {
			l.droppedSeries.Add(1)
			l.limitedMetrics.Store(mc.name, struct{}{})
		} else {
			l.totalSeries.Add(1)
		}
	}
	idx := 0
	dps.RemoveIf(func(_ pmetric.SummaryDataPoint) bool {
		drop := !keep[idx]
		idx++
		return drop
	})
}

// filterExponentialHistogramDataPoints filters exponential histogram data points.
func (l *CardinalityLimiter) filterExponentialHistogramDataPoints(mc *metricCardinality, dps pmetric.ExponentialHistogramDataPointSlice) {
	if dps.Len() == 0 {
		return
	}
	now := time.Now().UnixNano()
	allowedByHash := make(map[uint64]bool, dps.Len())
	keep := make([]bool, dps.Len())
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		hash := l.hashAttributes(dp.Attributes())
		allowed, known := allowedByHash[hash]
		if !known {
			allowed = l.allowSeries(mc, hash, now)
			allowedByHash[hash] = allowed
		}
		keep[i] = allowed
		if !allowed {
			l.droppedSeries.Add(1)
			l.limitedMetrics.Store(mc.name, struct{}{})
		} else {
			l.totalSeries.Add(1)
		}
	}
	idx := 0
	dps.RemoveIf(func(_ pmetric.ExponentialHistogramDataPoint) bool {
		drop := !keep[idx]
		idx++
		return drop
	})
}

// allowSeries checks if a series is allowed based on cardinality limits.
func (l *CardinalityLimiter) allowSeries(mc *metricCardinality, hash uint64, now int64) bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Check if series already exists
	if _, exists := mc.series[hash]; exists {
		mc.series[hash] = now
		return true
	}

	// Check per-metric limit
	if len(mc.series) >= mc.limit {
		mc.dropped++
		return false
	}

	// Reserve one slot in the global cardinality budget.
	if !l.reserveGlobalSeriesSlot() {
		mc.dropped++
		return false
	}

	// Allow and track
	mc.series[hash] = now
	return true
}

// hashAttributes creates a hash of selected attributes.
func (l *CardinalityLimiter) hashAttributes(attrs pcommon.Map) uint64 {
	h := fnv.New64a()
	attrs.Range(func(k string, v pcommon.Value) bool {
		if !l.shouldHashAttribute(k) {
			return true
		}
		if _, err := h.Write([]byte(k)); err != nil {
			return false
		}
		_, _ = h.Write([]byte{'='})
		hashAttributeValue(h, v)
		_, _ = h.Write([]byte{','})
		return true
	})
	return h.Sum64()
}

// maintenanceLoop periodically cleans up stale series.
func (l *CardinalityLimiter) maintenanceLoop() {
	ticker := time.NewTicker(l.config.TTL / 2)
	reportTicker := time.NewTicker(l.config.ReportInterval)
	defer ticker.Stop()
	defer reportTicker.Stop()

	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			l.cleanupStaleSeries()
		case <-reportTicker.C:
			l.reportStats()
		}
	}
}

// cleanupStaleSeries removes series not seen within TTL.
func (l *CardinalityLimiter) cleanupStaleSeries() {
	cutoff := time.Now().Add(-l.config.TTL).UnixNano()

	l.mu.RLock()
	metrics := make([]*metricCardinality, 0, len(l.metrics))
	for _, mc := range l.metrics {
		metrics = append(metrics, mc)
	}
	l.mu.RUnlock()

	for _, mc := range metrics {
		mc.mu.Lock()
		removed := int64(0)
		for hash, lastSeen := range mc.series {
			if lastSeen < cutoff {
				delete(mc.series, hash)
				removed++
			}
		}
		mc.mu.Unlock()
		if removed > 0 {
			l.globalSeries.Add(-removed)
		}
	}
}

// reportStats logs cardinality statistics.
func (l *CardinalityLimiter) reportStats() {
	totalSeries := 0
	var limited []string

	l.mu.RLock()
	for name, mc := range l.metrics {
		mc.mu.RLock()
		totalSeries += len(mc.series)
		if mc.dropped > 0 {
			limited = append(limited, fmt.Sprintf("%s(%d)", name, mc.dropped))
		}
		mc.mu.RUnlock()
	}
	l.mu.RUnlock()

	if len(limited) > 0 {
		l.log.Warn("cardinality limits reached",
			"limited_metrics", strings.Join(limited, ", "),
		)
	}

	l.log.Debug("cardinality stats",
		"total_series", totalSeries,
		"dropped", l.droppedSeries.Load(),
	)
}

// Stats returns current cardinality statistics.
func (l *CardinalityLimiter) Stats() CardinalityStats {
	totalSeries := 0
	metricStats := make(map[string]MetricCardinalityStats)

	l.mu.RLock()
	for name, mc := range l.metrics {
		mc.mu.RLock()
		metricStats[name] = MetricCardinalityStats{
			Name:    name,
			Series:  len(mc.series),
			Limit:   mc.limit,
			Dropped: mc.dropped,
		}
		totalSeries += len(mc.series)
		mc.mu.RUnlock()
	}
	l.mu.RUnlock()

	return CardinalityStats{
		TotalSeries:   totalSeries,
		GlobalLimit:   l.config.GlobalLimit,
		DroppedSeries: l.droppedSeries.Load(),
		Metrics:       metricStats,
	}
}

// CardinalityStats holds cardinality statistics.
type CardinalityStats struct {
	TotalSeries   int                               `json:"total_series"`
	GlobalLimit   int                               `json:"global_limit"`
	DroppedSeries int64                             `json:"dropped_series"`
	Metrics       map[string]MetricCardinalityStats `json:"metrics"`
}

// MetricCardinalityStats holds per-metric cardinality stats.
type MetricCardinalityStats struct {
	Name    string `json:"name"`
	Series  int    `json:"series"`
	Limit   int    `json:"limit"`
	Dropped int64  `json:"dropped"`
}

func toAttrSet(keys []string) map[string]struct{} {
	if len(keys) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		set[key] = struct{}{}
	}
	return set
}

func (l *CardinalityLimiter) shouldHashAttribute(key string) bool {
	if len(l.excludedAttrSet) > 0 {
		if _, excluded := l.excludedAttrSet[key]; excluded {
			return false
		}
	}
	if len(l.limitedAttrSet) == 0 {
		return true
	}
	_, included := l.limitedAttrSet[key]
	return included
}

func (l *CardinalityLimiter) reserveGlobalSeriesSlot() bool {
	if l.config.GlobalLimit <= 0 {
		return true
	}
	limit := int64(l.config.GlobalLimit)
	for {
		current := l.globalSeries.Load()
		if current >= limit {
			return false
		}
		if l.globalSeries.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func hashAttributeValue(h hash.Hash64, v pcommon.Value) {
	var buf [32]byte
	switch v.Type() {
	case pcommon.ValueTypeStr:
		if _, err := h.Write([]byte(v.Str())); err != nil {
			return
		}
	case pcommon.ValueTypeInt:
		b := strconv.AppendInt(buf[:0], v.Int(), 10)
		_, _ = h.Write(b)
	case pcommon.ValueTypeDouble:
		b := strconv.AppendFloat(buf[:0], v.Double(), 'g', -1, 64)
		_, _ = h.Write(b)
	case pcommon.ValueTypeBool:
		if v.Bool() {
			_, _ = h.Write([]byte("true"))
		} else {
			_, _ = h.Write([]byte("false"))
		}
	case pcommon.ValueTypeMap:
		v.Map().Range(func(k string, nested pcommon.Value) bool {
			if _, err := h.Write([]byte(k)); err != nil {
				return false
			}
			_, _ = h.Write([]byte{':'})
			hashAttributeValue(h, nested)
			_, _ = h.Write([]byte{';'})
			return true
		})
	case pcommon.ValueTypeSlice:
		slice := v.Slice()
		for i := 0; i < slice.Len(); i++ {
			hashAttributeValue(h, slice.At(i))
			_, _ = h.Write([]byte{'|'})
		}
	default:
		_, _ = h.Write([]byte(v.AsString()))
	}
}
