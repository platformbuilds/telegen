// Rate limiter controls data ingestion rates to prevent overwhelming backends.
package limits

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// RateLimiter provides rate limiting across signal types.
type RateLimiter struct {
	config RateLimiterConfig
	log    *slog.Logger

	// Limiters per signal type
	metricLimiter *tokenBucket
	traceLimiter  *tokenBucket
	logLimiter    *tokenBucket

	// State
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc

	// Stats
	metricsDropped  atomic.Int64
	metricsAccepted atomic.Int64
	tracesDropped   atomic.Int64
	tracesAccepted  atomic.Int64
	logsDropped     atomic.Int64
	logsAccepted    atomic.Int64
}

// RateLimiterConfig configures rate limiting.
type RateLimiterConfig struct {
	// Enabled toggles rate limiting.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Metrics rate limit configuration.
	Metrics RateLimitSignalConfig `yaml:"metrics" json:"metrics"`

	// Traces rate limit configuration.
	Traces RateLimitSignalConfig `yaml:"traces" json:"traces"`

	// Logs rate limit configuration.
	Logs RateLimitSignalConfig `yaml:"logs" json:"logs"`

	// BurstMultiplier for token bucket burst capacity.
	BurstMultiplier float64 `yaml:"burst_multiplier" json:"burst_multiplier"`

	// ReportInterval for logging rate limit stats.
	ReportInterval time.Duration `yaml:"report_interval" json:"report_interval"`
}

// RateLimitSignalConfig configures rate limits for a signal type.
type RateLimitSignalConfig struct {
	// Enabled toggles limiting for this signal.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// DataPointsPerSecond limits data points/records per second.
	DataPointsPerSecond int `yaml:"data_points_per_second" json:"data_points_per_second"`

	// BytesPerSecond limits bytes per second (0 = no limit).
	BytesPerSecond int `yaml:"bytes_per_second,omitempty" json:"bytes_per_second,omitempty"`

	// DropPolicy: "head" (drop oldest), "tail" (drop newest), "random"
	DropPolicy string `yaml:"drop_policy" json:"drop_policy"`
}

// DefaultRateLimiterConfig returns sensible defaults.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		Enabled: true,
		Metrics: RateLimitSignalConfig{
			Enabled:             true,
			DataPointsPerSecond: 100000,
			DropPolicy:          "tail",
		},
		Traces: RateLimitSignalConfig{
			Enabled:             true,
			DataPointsPerSecond: 10000,
			DropPolicy:          "tail",
		},
		Logs: RateLimitSignalConfig{
			Enabled:             true,
			DataPointsPerSecond: 50000,
			DropPolicy:          "tail",
		},
		BurstMultiplier: 2.0,
		ReportInterval:  5 * time.Minute,
	}
}

// tokenBucket implements a token bucket rate limiter.
type tokenBucket struct {
	rate       float64   // tokens per second
	burst      float64   // max tokens
	tokens     float64   // current tokens
	lastUpdate time.Time // last token update
	mu         sync.Mutex
}

// newTokenBucket creates a new token bucket.
func newTokenBucket(rate float64, burstMultiplier float64) *tokenBucket {
	burst := rate * burstMultiplier
	return &tokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     burst, // Start full
		lastUpdate: time.Now(),
	}
}

// tryConsume attempts to consume n tokens, returns true if allowed.
func (tb *tokenBucket) tryConsume(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.lastUpdate = now

	// Add tokens based on elapsed time
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}

	// Try to consume
	if float64(n) <= tb.tokens {
		tb.tokens -= float64(n)
		return true
	}

	return false
}

// available returns available tokens.
func (tb *tokenBucket) available() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()

	tokens := tb.tokens + elapsed*tb.rate
	if tokens > tb.burst {
		tokens = tb.burst
	}

	return int(tokens)
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(config RateLimiterConfig, log *slog.Logger) *RateLimiter {
	if log == nil {
		log = slog.Default()
	}

	if config.BurstMultiplier == 0 {
		config.BurstMultiplier = 2.0
	}
	if config.ReportInterval == 0 {
		config.ReportInterval = 5 * time.Minute
	}

	rl := &RateLimiter{
		config: config,
		log:    log.With("component", "rate-limiter"),
	}

	// Create token buckets
	if config.Metrics.Enabled {
		rl.metricLimiter = newTokenBucket(
			float64(config.Metrics.DataPointsPerSecond),
			config.BurstMultiplier,
		)
	}
	if config.Traces.Enabled {
		rl.traceLimiter = newTokenBucket(
			float64(config.Traces.DataPointsPerSecond),
			config.BurstMultiplier,
		)
	}
	if config.Logs.Enabled {
		rl.logLimiter = newTokenBucket(
			float64(config.Logs.DataPointsPerSecond),
			config.BurstMultiplier,
		)
	}

	return rl
}

// Start begins rate limiting.
func (rl *RateLimiter) Start(ctx context.Context) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.running {
		return nil
	}

	rl.ctx, rl.cancel = context.WithCancel(ctx)
	rl.running = true

	go rl.reportLoop()

	rl.log.Info("started rate limiter",
		"metrics_rate", rl.config.Metrics.DataPointsPerSecond,
		"traces_rate", rl.config.Traces.DataPointsPerSecond,
		"logs_rate", rl.config.Logs.DataPointsPerSecond,
	)

	return nil
}

// Stop stops rate limiting.
func (rl *RateLimiter) Stop(ctx context.Context) error {
	rl.mu.Lock()
	if !rl.running {
		rl.mu.Unlock()
		return nil
	}
	rl.cancel()
	rl.running = false
	rl.mu.Unlock()

	rl.log.Info("stopped rate limiter",
		"metrics_accepted", rl.metricsAccepted.Load(),
		"metrics_dropped", rl.metricsDropped.Load(),
		"traces_accepted", rl.tracesAccepted.Load(),
		"traces_dropped", rl.tracesDropped.Load(),
		"logs_accepted", rl.logsAccepted.Load(),
		"logs_dropped", rl.logsDropped.Load(),
	)

	return nil
}

// ProcessMetrics applies rate limiting to metrics.
func (rl *RateLimiter) ProcessMetrics(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	if !rl.config.Enabled || !rl.config.Metrics.Enabled || rl.metricLimiter == nil {
		return md, nil
	}

	// Count data points
	count := rl.countMetricDataPoints(md)

	// Check rate limit
	if rl.metricLimiter.tryConsume(count) {
		rl.metricsAccepted.Add(int64(count))
		return md, nil
	}

	// Rate limited - determine how many we can accept
	available := rl.metricLimiter.available()
	if available <= 0 {
		rl.metricsDropped.Add(int64(count))
		return pmetric.NewMetrics(), nil // Drop all
	}

	// Partial acceptance - drop excess
	result, dropped := rl.trimMetrics(md, available)
	rl.metricsAccepted.Add(int64(available))
	rl.metricsDropped.Add(int64(dropped))
	rl.metricLimiter.tryConsume(available)

	return result, nil
}

// ProcessTraces applies rate limiting to traces.
func (rl *RateLimiter) ProcessTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	if !rl.config.Enabled || !rl.config.Traces.Enabled || rl.traceLimiter == nil {
		return td, nil
	}

	// Count spans
	count := rl.countSpans(td)

	// Check rate limit
	if rl.traceLimiter.tryConsume(count) {
		rl.tracesAccepted.Add(int64(count))
		return td, nil
	}

	// Rate limited
	available := rl.traceLimiter.available()
	if available <= 0 {
		rl.tracesDropped.Add(int64(count))
		return ptrace.NewTraces(), nil
	}

	// Partial acceptance
	result, dropped := rl.trimTraces(td, available)
	rl.tracesAccepted.Add(int64(available))
	rl.tracesDropped.Add(int64(dropped))
	rl.traceLimiter.tryConsume(available)

	return result, nil
}

// ProcessLogs applies rate limiting to logs.
func (rl *RateLimiter) ProcessLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	if !rl.config.Enabled || !rl.config.Logs.Enabled || rl.logLimiter == nil {
		return ld, nil
	}

	// Count log records
	count := rl.countLogRecords(ld)

	// Check rate limit
	if rl.logLimiter.tryConsume(count) {
		rl.logsAccepted.Add(int64(count))
		return ld, nil
	}

	// Rate limited
	available := rl.logLimiter.available()
	if available <= 0 {
		rl.logsDropped.Add(int64(count))
		return plog.NewLogs(), nil
	}

	// Partial acceptance
	result, dropped := rl.trimLogs(ld, available)
	rl.logsAccepted.Add(int64(available))
	rl.logsDropped.Add(int64(dropped))
	rl.logLimiter.tryConsume(available)

	return result, nil
}

// countMetricDataPoints counts total data points.
func (rl *RateLimiter) countMetricDataPoints(md pmetric.Metrics) int {
	count := 0
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			for k := 0; k < sm.Metrics().Len(); k++ {
				metric := sm.Metrics().At(k)
				count += rl.countDataPoints(metric)
			}
		}
	}
	return count
}

// countDataPoints counts data points in a single metric.
func (rl *RateLimiter) countDataPoints(metric pmetric.Metric) int {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		return metric.Gauge().DataPoints().Len()
	case pmetric.MetricTypeSum:
		return metric.Sum().DataPoints().Len()
	case pmetric.MetricTypeHistogram:
		return metric.Histogram().DataPoints().Len()
	case pmetric.MetricTypeSummary:
		return metric.Summary().DataPoints().Len()
	case pmetric.MetricTypeExponentialHistogram:
		return metric.ExponentialHistogram().DataPoints().Len()
	}
	return 0
}

// countSpans counts total spans.
func (rl *RateLimiter) countSpans(td ptrace.Traces) int {
	count := 0
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rs := td.ResourceSpans().At(i)
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)
			count += ss.Spans().Len()
		}
	}
	return count
}

// countLogRecords counts total log records.
func (rl *RateLimiter) countLogRecords(ld plog.Logs) int {
	count := 0
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			count += sl.LogRecords().Len()
		}
	}
	return count
}

// trimMetrics reduces metrics to fit within limit.
func (rl *RateLimiter) trimMetrics(md pmetric.Metrics, limit int) (pmetric.Metrics, int) {
	result := pmetric.NewMetrics()
	kept := 0
	dropped := 0

	for i := 0; i < md.ResourceMetrics().Len() && kept < limit; i++ {
		srcRM := md.ResourceMetrics().At(i)
		dstRM := result.ResourceMetrics().AppendEmpty()
		srcRM.Resource().CopyTo(dstRM.Resource())

		for j := 0; j < srcRM.ScopeMetrics().Len() && kept < limit; j++ {
			srcSM := srcRM.ScopeMetrics().At(j)
			dstSM := dstRM.ScopeMetrics().AppendEmpty()
			srcSM.Scope().CopyTo(dstSM.Scope())

			for k := 0; k < srcSM.Metrics().Len() && kept < limit; k++ {
				srcMetric := srcSM.Metrics().At(k)
				dpCount := rl.countDataPoints(srcMetric)

				if kept+dpCount <= limit {
					dstMetric := dstSM.Metrics().AppendEmpty()
					srcMetric.CopyTo(dstMetric)
					kept += dpCount
				} else {
					dropped += dpCount
				}
			}
		}
	}

	// Count remaining dropped
	total := rl.countMetricDataPoints(md)
	dropped = total - kept

	return result, dropped
}

// trimTraces reduces traces to fit within limit.
func (rl *RateLimiter) trimTraces(td ptrace.Traces, limit int) (ptrace.Traces, int) {
	result := ptrace.NewTraces()
	kept := 0

	for i := 0; i < td.ResourceSpans().Len() && kept < limit; i++ {
		srcRS := td.ResourceSpans().At(i)
		dstRS := result.ResourceSpans().AppendEmpty()
		srcRS.Resource().CopyTo(dstRS.Resource())

		for j := 0; j < srcRS.ScopeSpans().Len() && kept < limit; j++ {
			srcSS := srcRS.ScopeSpans().At(j)
			dstSS := dstRS.ScopeSpans().AppendEmpty()
			srcSS.Scope().CopyTo(dstSS.Scope())

			for k := 0; k < srcSS.Spans().Len() && kept < limit; k++ {
				srcSpan := srcSS.Spans().At(k)
				dstSpan := dstSS.Spans().AppendEmpty()
				srcSpan.CopyTo(dstSpan)
				kept++
			}
		}
	}

	total := rl.countSpans(td)
	return result, total - kept
}

// trimLogs reduces logs to fit within limit.
func (rl *RateLimiter) trimLogs(ld plog.Logs, limit int) (plog.Logs, int) {
	result := plog.NewLogs()
	kept := 0

	for i := 0; i < ld.ResourceLogs().Len() && kept < limit; i++ {
		srcRL := ld.ResourceLogs().At(i)
		dstRL := result.ResourceLogs().AppendEmpty()
		srcRL.Resource().CopyTo(dstRL.Resource())

		for j := 0; j < srcRL.ScopeLogs().Len() && kept < limit; j++ {
			srcSL := srcRL.ScopeLogs().At(j)
			dstSL := dstRL.ScopeLogs().AppendEmpty()
			srcSL.Scope().CopyTo(dstSL.Scope())

			for k := 0; k < srcSL.LogRecords().Len() && kept < limit; k++ {
				srcLog := srcSL.LogRecords().At(k)
				dstLog := dstSL.LogRecords().AppendEmpty()
				srcLog.CopyTo(dstLog)
				kept++
			}
		}
	}

	total := rl.countLogRecords(ld)
	return result, total - kept
}

// reportLoop periodically reports rate limit stats.
func (rl *RateLimiter) reportLoop() {
	ticker := time.NewTicker(rl.config.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.reportStats()
		}
	}
}

// reportStats logs rate limit statistics.
func (rl *RateLimiter) reportStats() {
	dropped := rl.metricsDropped.Load() + rl.tracesDropped.Load() + rl.logsDropped.Load()

	if dropped > 0 {
		rl.log.Warn("rate limits reached",
			"metrics_dropped", rl.metricsDropped.Load(),
			"traces_dropped", rl.tracesDropped.Load(),
			"logs_dropped", rl.logsDropped.Load(),
		)
	}

	rl.log.Debug("rate limit stats",
		"metrics_accepted", rl.metricsAccepted.Load(),
		"metrics_dropped", rl.metricsDropped.Load(),
		"traces_accepted", rl.tracesAccepted.Load(),
		"traces_dropped", rl.tracesDropped.Load(),
		"logs_accepted", rl.logsAccepted.Load(),
		"logs_dropped", rl.logsDropped.Load(),
	)
}

// Stats returns rate limiter statistics.
func (rl *RateLimiter) Stats() RateLimiterStats {
	return RateLimiterStats{
		MetricsAccepted: rl.metricsAccepted.Load(),
		MetricsDropped:  rl.metricsDropped.Load(),
		TracesAccepted:  rl.tracesAccepted.Load(),
		TracesDropped:   rl.tracesDropped.Load(),
		LogsAccepted:    rl.logsAccepted.Load(),
		LogsDropped:     rl.logsDropped.Load(),
		MetricsAvailable: func() int {
			if rl.metricLimiter != nil {
				return rl.metricLimiter.available()
			}
			return 0
		}(),
		TracesAvailable: func() int {
			if rl.traceLimiter != nil {
				return rl.traceLimiter.available()
			}
			return 0
		}(),
		LogsAvailable: func() int {
			if rl.logLimiter != nil {
				return rl.logLimiter.available()
			}
			return 0
		}(),
	}
}

// RateLimiterStats holds rate statistics.
type RateLimiterStats struct {
	MetricsAccepted  int64 `json:"metrics_accepted"`
	MetricsDropped   int64 `json:"metrics_dropped"`
	MetricsAvailable int   `json:"metrics_available"`
	TracesAccepted   int64 `json:"traces_accepted"`
	TracesDropped    int64 `json:"traces_dropped"`
	TracesAvailable  int   `json:"traces_available"`
	LogsAccepted     int64 `json:"logs_accepted"`
	LogsDropped      int64 `json:"logs_dropped"`
	LogsAvailable    int   `json:"logs_available"`
}

// String returns a summary string.
func (s RateLimiterStats) String() string {
	return fmt.Sprintf(
		"metrics=%d/%d traces=%d/%d logs=%d/%d",
		s.MetricsAccepted, s.MetricsDropped,
		s.TracesAccepted, s.TracesDropped,
		s.LogsAccepted, s.LogsDropped,
	)
}
