// Package pipeline provides V3 unified pipeline integration.
package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/platformbuilds/telegen/internal/pipeline/adapters"
	"github.com/platformbuilds/telegen/internal/pipeline/limits"
	"github.com/platformbuilds/telegen/internal/pipeline/transform"
)

// V3IntegrationConfig configures the V3 integration layer.
type V3IntegrationConfig struct {
	// Enabled enables V3 pipeline routing. Default: true.
	Enabled bool `yaml:"enabled"`

	// Limits configuration for data quality.
	Limits *V3LimitsConfig `yaml:"limits,omitempty"`

	// Transform configuration for signal transformation.
	Transform *transform.TransformConfig `yaml:"transform,omitempty"`

	// PIIRedaction configuration for PII detection and masking.
	PIIRedaction *transform.PIIRedactionConfig `yaml:"pii_redaction,omitempty"`
}

// V3LimitsConfig configures all limit types.
type V3LimitsConfig struct {
	Cardinality *limits.CardinalityConfig   `yaml:"cardinality,omitempty"`
	Rate        *limits.RateLimiterConfig   `yaml:"rate,omitempty"`
	Attributes  *limits.AttributeLimiterConfig `yaml:"attributes,omitempty"`
}

// DefaultV3IntegrationConfig returns defaults.
func DefaultV3IntegrationConfig() V3IntegrationConfig {
	return V3IntegrationConfig{
		Enabled: true,
	}
}

// V3Integration bridges V2 collectors to V3 pipeline.
// This is the key component that enables 100% V2→V3 coverage.
type V3Integration struct {
	config V3IntegrationConfig
	logger *slog.Logger
	mu     sync.RWMutex

	// V3 pipeline (if standalone mode)
	v3Pipeline *V3Pipeline

	// Adapters for each collector type
	adapters map[adapters.CollectorType]adapters.CollectorAdapter

	// Data quality limiters
	cardinalityLimiter *limits.CardinalityLimiter
	rateLimiter        *limits.RateLimiter
	attributeLimiter   *limits.AttributeLimiter

	// Transformation
	transformEngine *transform.TransformEngine
	piiMatcher      *transform.PIIMatcher

	// Fallback sink (for V2 compatibility)
	fallbackTraces  func(context.Context, ptrace.Traces) error
	fallbackLogs    func(context.Context, plog.Logs) error
	fallbackMetrics func(context.Context, pmetric.Metrics) error
}

// NewV3Integration creates a V3 integration layer.
func NewV3Integration(config V3IntegrationConfig, logger *slog.Logger) (*V3Integration, error) {
	if logger == nil {
		logger = slog.Default()
	}

	v := &V3Integration{
		config:   config,
		logger:   logger,
		adapters: make(map[adapters.CollectorType]adapters.CollectorAdapter),
	}

	// Initialize limiters if configured
	if config.Limits != nil {
		if config.Limits.Cardinality != nil {
			v.cardinalityLimiter = limits.NewCardinalityLimiter(*config.Limits.Cardinality, nil)
		}
		if config.Limits.Rate != nil {
			v.rateLimiter = limits.NewRateLimiter(*config.Limits.Rate, nil)
		}
		if config.Limits.Attributes != nil {
			v.attributeLimiter = limits.NewAttributeLimiter(*config.Limits.Attributes, nil)
		}
	}

	// Initialize transformation if configured
	if config.Transform != nil && config.Transform.Enabled {
		engine, err := transform.NewTransformEngine(*config.Transform, nil)
		if err != nil {
			return nil, err
		}
		v.transformEngine = engine
	}

	// Initialize PII redaction if configured
	if config.PIIRedaction != nil && config.PIIRedaction.Enabled {
		matcher, err := transform.NewPIIMatcher(*config.PIIRedaction)
		if err != nil {
			return nil, err
		}
		v.piiMatcher = matcher
	}

	return v, nil
}

// SetV3Pipeline connects to a standalone V3 pipeline.
func (v *V3Integration) SetV3Pipeline(p *V3Pipeline) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.v3Pipeline = p
}

// SetFallbackSinks sets V2 fallback sinks for graceful degradation.
func (v *V3Integration) SetFallbackSinks(
	traces func(context.Context, ptrace.Traces) error,
	logs func(context.Context, plog.Logs) error,
	metrics func(context.Context, pmetric.Metrics) error,
) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fallbackTraces = traces
	v.fallbackLogs = logs
	v.fallbackMetrics = metrics
}

// RegisterAdapter registers a collector adapter.
func (v *V3Integration) RegisterAdapter(adapter adapters.CollectorAdapter) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.adapters[adapter.Type()] = adapter
}

// ============================================================
// Signal Routing - These are called by V2 collectors
// ============================================================

// RouteTraces routes traces from V2 collectors through V3 pipeline.
// Call this from V2 tracer instead of direct export.
func (v *V3Integration) RouteTraces(ctx context.Context, traces ptrace.Traces) error {
	if !v.config.Enabled {
		return v.fallbackTraces(ctx, traces)
	}

	// Apply rate limiting
	if v.rateLimiter != nil {
		var err error
		traces, err = v.rateLimiter.ProcessTraces(ctx, traces)
		if err != nil || traces.SpanCount() == 0 {
			return err
		}
	}

	// Apply transformation
	if v.transformEngine != nil {
		var err error
		traces, err = v.transformEngine.ProcessTraces(ctx, traces)
		if err != nil {
			v.logger.Warn("trace transformation error", "error", err)
		}
	}

	// Apply PII redaction
	if v.piiMatcher != nil {
		v.piiMatcher.RedactTraces(traces)
	}

	// Route to V3 pipeline
	v.mu.RLock()
	pipeline := v.v3Pipeline
	v.mu.RUnlock()

	if pipeline != nil {
		return pipeline.SendTraces(ctx, traces)
	}

	// Fallback to V2
	if v.fallbackTraces != nil {
		return v.fallbackTraces(ctx, traces)
	}

	return nil
}

// RouteLogs routes logs from V2 collectors through V3 pipeline.
func (v *V3Integration) RouteLogs(ctx context.Context, logs plog.Logs) error {
	if !v.config.Enabled {
		return v.fallbackLogs(ctx, logs)
	}

	// Apply rate limiting
	if v.rateLimiter != nil {
		var err error
		logs, err = v.rateLimiter.ProcessLogs(ctx, logs)
		if err != nil || logs.LogRecordCount() == 0 {
			return err
		}
	}

	// Apply transformation
	if v.transformEngine != nil {
		var err error
		logs, err = v.transformEngine.ProcessLogs(ctx, logs)
		if err != nil {
			v.logger.Warn("log transformation error", "error", err)
		}
	}

	// Apply PII redaction
	if v.piiMatcher != nil {
		v.piiMatcher.RedactLogs(logs)
	}

	// Route to V3 pipeline
	v.mu.RLock()
	pipeline := v.v3Pipeline
	v.mu.RUnlock()

	if pipeline != nil {
		return pipeline.SendLogs(ctx, logs)
	}

	// Fallback to V2
	if v.fallbackLogs != nil {
		return v.fallbackLogs(ctx, logs)
	}

	return nil
}

// RouteMetrics routes metrics from V2 collectors through V3 pipeline.
func (v *V3Integration) RouteMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if !v.config.Enabled {
		return v.fallbackMetrics(ctx, metrics)
	}

	// Apply cardinality limiting
	if v.cardinalityLimiter != nil {
		var err error
		metrics, err = v.cardinalityLimiter.ProcessMetrics(ctx, metrics)
		if err != nil || metrics.DataPointCount() == 0 {
			return err
		}
	}

	// Apply rate limiting
	if v.rateLimiter != nil {
		var err error
		metrics, err = v.rateLimiter.ProcessMetrics(ctx, metrics)
		if err != nil || metrics.DataPointCount() == 0 {
			return err
		}
	}

	// Apply attribute limiting
	if v.attributeLimiter != nil {
		metrics, _ = v.attributeLimiter.ProcessMetrics(ctx, metrics)
	}

	// Apply transformation
	if v.transformEngine != nil {
		var err error
		metrics, err = v.transformEngine.ProcessMetrics(ctx, metrics)
		if err != nil {
			v.logger.Warn("metric transformation error", "error", err)
		}
	}

	// Apply PII redaction
	if v.piiMatcher != nil {
		v.piiMatcher.RedactMetrics(metrics)
	}

	// Route to V3 pipeline
	v.mu.RLock()
	pipeline := v.v3Pipeline
	v.mu.RUnlock()

	if pipeline != nil {
		return pipeline.SendMetrics(ctx, metrics)
	}

	// Fallback to V2
	if v.fallbackMetrics != nil {
		return v.fallbackMetrics(ctx, metrics)
	}

	return nil
}

// ============================================================
// V2 Collector Hooks - Inject into existing collectors
// ============================================================

// TraceHook returns a function that can be injected into V2 tracer.
func (v *V3Integration) TraceHook() func(ctx context.Context, traces ptrace.Traces) error {
	return v.RouteTraces
}

// LogHook returns a function that can be injected into V2 log collectors.
func (v *V3Integration) LogHook() func(ctx context.Context, logs plog.Logs) error {
	return v.RouteLogs
}

// MetricHook returns a function that can be injected into V2 metric collectors.
func (v *V3Integration) MetricHook() func(ctx context.Context, metrics pmetric.Metrics) error {
	return v.RouteMetrics
}

// ============================================================
// Stats
// ============================================================

// V3IntegrationStats provides integration statistics.
type V3IntegrationStats struct {
	Enabled           bool                   `json:"enabled"`
	AdapterCount      int                    `json:"adapter_count"`
	CardinalityStats  interface{}            `json:"cardinality_stats,omitempty"`
	RateLimiterStats  interface{}            `json:"rate_limiter_stats,omitempty"`
	TransformStats    interface{}            `json:"transform_stats,omitempty"`
	PIIRedactionStats interface{}            `json:"pii_redaction_stats,omitempty"`
}

// Stats returns current integration statistics.
func (v *V3Integration) Stats() V3IntegrationStats {
	v.mu.RLock()
	defer v.mu.RUnlock()

	stats := V3IntegrationStats{
		Enabled:      v.config.Enabled,
		AdapterCount: len(v.adapters),
	}

	if v.cardinalityLimiter != nil {
		stats.CardinalityStats = v.cardinalityLimiter.Stats()
	}
	if v.rateLimiter != nil {
		stats.RateLimiterStats = v.rateLimiter.Stats()
	}
	if v.piiMatcher != nil {
		stats.PIIRedactionStats = v.piiMatcher.Stats()
	}

	return stats
}
