// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package timeutil

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Provenance signal names. These travel the OTLP export path alongside the
// domain metrics, deliberately NOT through internal/selftelemetry: that
// registry only surfaces on the local :19090 scrape endpoint and has no
// Prometheus-to-OTLP bridge, so a gauge added there would never reach
// VictoriaMetrics.
const (
	// MetricClockSkewSeconds is the collector clock minus the newest source
	// timestamp in a batch. Negative means the collector lags the source.
	MetricClockSkewSeconds = "collector_clock_skew_seconds"

	// MetricTimestampFallbackTotal counts metrics in a batch whose source
	// timestamp was missing or zero, so a collection instant stood in.
	MetricTimestampFallbackTotal = "collector_timestamp_fallback_total"
)

// DefaultClockSkewWarn is the threshold past which a batch's skew is logged.
const DefaultClockSkewWarn = 5 * time.Minute

// BatchProvenance summarises timestamp provenance for one collection batch.
type BatchProvenance struct {
	// NewestSource is the latest non-zero source timestamp seen in the batch.
	NewestSource time.Time
	// SkewSeconds is collector clock minus NewestSource, sign preserved. Only
	// meaningful when HasSource is true.
	SkewSeconds float64
	// HasSource reports whether any usable source timestamp was present.
	HasSource bool
	// Fallbacks counts entries that carried no usable source timestamp.
	Fallbacks int64
}

// InspectBatch computes the provenance summary for a batch.
//
// observedAt is the collector's own clock reading for this cycle. Entries with
// a zero timestamp are counted as fallbacks rather than silently skewing the
// result toward the epoch.
func InspectBatch(observedAt time.Time, sourceTimestamps []time.Time) BatchProvenance {
	var p BatchProvenance
	for _, ts := range sourceTimestamps {
		if ts.IsZero() {
			p.Fallbacks++
			continue
		}
		if p.NewestSource.IsZero() || ts.After(p.NewestSource) {
			p.NewestSource = ts
		}
	}
	if !p.NewestSource.IsZero() {
		p.HasSource = true
		p.SkewSeconds = ComputeSkew(observedAt, p.NewestSource)
	}
	return p
}

// ExceedsWarnThreshold reports whether the batch's skew magnitude is past
// threshold. A non-positive threshold falls back to DefaultClockSkewWarn.
func (p BatchProvenance) ExceedsWarnThreshold(threshold time.Duration) bool {
	if !p.HasSource {
		return false
	}
	if threshold <= 0 {
		threshold = DefaultClockSkewWarn
	}
	return SkewExceedsThreshold(p.SkewSeconds, threshold.Seconds())
}

// WarnIfSkewed logs once per batch when the skew magnitude is past threshold,
// so a misconfigured NTP or a drifting VM clock announces itself in the logs as
// well as in the metrics. No-op when no logger is wired or nothing was
// comparable.
func (p BatchProvenance) WarnIfSkewed(collector string, threshold time.Duration, logger SkewLogger) {
	if logger == nil || !p.ExceedsWarnThreshold(threshold) {
		return
	}
	if threshold <= 0 {
		threshold = DefaultClockSkewWarn
	}
	logger.Warn("collector clock skew exceeds threshold",
		"collector", collector,
		"skew_sec", p.SkewSeconds,
		"threshold_sec", threshold.Seconds(),
		"newest_source_timestamp", FormatTimestamp(p.NewestSource),
	)
}

// Metrics renders the provenance signals as OTLP metric data, ready to append
// to the same ScopeMetrics slice as the batch's domain metrics.
//
// The skew gauge is omitted when the batch had no source timestamp at all —
// reporting zero skew there would claim the clocks agree when in truth nothing
// was compared. The fallback counter is omitted when there was nothing to
// count, so a healthy collector emits no noise.
func (p BatchProvenance) Metrics(collector string, observedAt time.Time) []metricdata.Metrics {
	attrs := attribute.NewSet(attribute.String("collector", collector))
	out := make([]metricdata.Metrics, 0, 2)

	if p.HasSource {
		out = append(out, metricdata.Metrics{
			Name:        MetricClockSkewSeconds,
			Description: "Collector clock minus newest source timestamp (negative means the collector lags)",
			Unit:        "s",
			Data: metricdata.Gauge[float64]{
				DataPoints: []metricdata.DataPoint[float64]{{
					Attributes: attrs,
					Time:       observedAt,
					Value:      p.SkewSeconds,
				}},
			},
		})
	}

	if p.Fallbacks > 0 {
		out = append(out, metricdata.Metrics{
			Name:        MetricTimestampFallbackTotal,
			Description: "Metrics emitted with a collection instant because no source timestamp was available",
			Unit:        "{metric}",
			Data: metricdata.Sum[int64]{
				DataPoints: []metricdata.DataPoint[int64]{{
					Attributes: attrs,
					Time:       observedAt,
					Value:      p.Fallbacks,
				}},
				Temporality: metricdata.DeltaTemporality,
				IsMonotonic: true,
			},
		})
	}

	return out
}
