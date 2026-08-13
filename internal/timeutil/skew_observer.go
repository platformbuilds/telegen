package timeutil

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// SkewObserver tracks and emits clock skew metrics via OTLP.
// It provides:
//   - Clock skew gauge (sign-preserving: negative = collector lags)
//   - Timestamp fallback counter (incremented when source timestamp is missing)
//
// Usage:
//
//	observer := NewSkewObserver(meterProvider, "vmware")
//	// After resolving source timestamp:
//	if resolved.Valid {
//	    observer.RecordSkew(ctx, time.Now(), resolved.Time)
//	} else {
//	    observer.RecordFallback(ctx)
//	}
type SkewObserver struct {
	collectorName     string
	skewGauge         metric.Float64Gauge
	fallbackCounter   metric.Int64Counter
	warnThresholdSec  float64
	logger            SkewLogger
}

// SkewLogger is the minimal logging interface required by SkewObserver.
// Implementations can provide *slog.Logger, *zerolog.Logger, etc.
type SkewLogger interface {
	Warn(msg string, keyvals ...interface{})
}

// SkewObserverConfig holds configuration for a SkewObserver.
type SkewObserverConfig struct {
	CollectorName     string      // Required: collector name for metric labels
	MeterProvider     metric.MeterProvider // Required: OTLP meter provider
	WarnThresholdSec  float64     // Optional: warn when abs(skew) exceeds this (default: 300s = 5m)
	Logger            SkewLogger  // Optional: logger for threshold warnings
}

// NewSkewObserver creates a new SkewObserver with the given config.
func NewSkewObserver(cfg SkewObserverConfig) (*SkewObserver, error) {
	if cfg.WarnThresholdSec == 0 {
		cfg.WarnThresholdSec = 300.0 // Default: 5 minutes
	}

	meter := cfg.MeterProvider.Meter("github.com/mirastacklabs-ai/telegen/timeutil")

	skewGauge, err := meter.Float64Gauge(
		"collector_clock_skew_seconds",
		metric.WithDescription("Clock skew between collector and source system (negative = collector lags)"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	fallbackCounter, err := meter.Int64Counter(
		"collector_timestamp_fallback_total",
		metric.WithDescription("Count of metrics where source timestamp was missing and fallback was used"),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, err
	}

	return &SkewObserver{
		collectorName:    cfg.CollectorName,
		skewGauge:        skewGauge,
		fallbackCounter:  fallbackCounter,
		warnThresholdSec: cfg.WarnThresholdSec,
		logger:           cfg.Logger,
	}, nil
}

// RecordSkew computes and emits clock skew between collector and source timestamps.
// Skew is sign-preserving:
//   - Negative: collector clock lags behind source
//   - Positive: collector clock leads source
//   - Zero: clocks agree
//
// If abs(skew) exceeds the configured threshold and a logger is provided, a warning is logged.
func (o *SkewObserver) RecordSkew(ctx context.Context, collectorClock time.Time, sourceTimestamp time.Time) {
	skewSec := ComputeSkew(collectorClock, sourceTimestamp)

	attrs := []attribute.KeyValue{
		attribute.String("collector", o.collectorName),
	}

	o.skewGauge.Record(ctx, skewSec, metric.WithAttributes(attrs...))

	// Warn if threshold exceeded
	if o.logger != nil && SkewExceedsThreshold(skewSec, o.warnThresholdSec) {
		o.logger.Warn("clock skew exceeds threshold",
			"collector", o.collectorName,
			"skew_sec", skewSec,
			"threshold_sec", o.warnThresholdSec,
			"collector_clock", FormatTimestamp(collectorClock),
			"source_timestamp", FormatTimestamp(sourceTimestamp),
		)
	}
}

// RecordFallback increments the fallback counter, indicating that a source timestamp
// was missing or invalid and time.Now() was used instead.
func (o *SkewObserver) RecordFallback(ctx context.Context) {
	attrs := []attribute.KeyValue{
		attribute.String("collector", o.collectorName),
	}

	o.fallbackCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordSkewBatch computes skew against the newest timestamp in a batch and emits once.
// Use this when processing batches of metrics that share a common collection cycle.
//
// If the batch is empty or all timestamps are zero, this is equivalent to RecordFallback.
func (o *SkewObserver) RecordSkewBatch(ctx context.Context, collectorClock time.Time, timestamps []time.Time) {
	if len(timestamps) == 0 {
		o.RecordFallback(ctx)
		return
	}

	// Find the newest non-zero timestamp
	var newestSource time.Time
	for _, ts := range timestamps {
		if !ts.IsZero() && (newestSource.IsZero() || ts.After(newestSource)) {
			newestSource = ts
		}
	}

	if newestSource.IsZero() {
		// All timestamps were zero
		o.RecordFallback(ctx)
		return
	}

	o.RecordSkew(ctx, collectorClock, newestSource)
}
