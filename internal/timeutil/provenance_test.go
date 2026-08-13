// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package timeutil

import (
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

var observedAt = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func TestInspectBatch_CollectorLagsSource(t *testing.T) {
	// Source is one hour ahead of the collector: the collector clock is slow,
	// which is the Phoenix incident's shape. Skew must be negative.
	source := observedAt.Add(time.Hour)
	p := InspectBatch(observedAt, []time.Time{source})

	if !p.HasSource {
		t.Fatal("expected HasSource")
	}
	if p.SkewSeconds != -3600 {
		t.Fatalf("expected skew -3600s (collector lags), got %v", p.SkewSeconds)
	}
	if p.Fallbacks != 0 {
		t.Fatalf("expected no fallbacks, got %d", p.Fallbacks)
	}
}

func TestInspectBatch_CollectorLeadsSource(t *testing.T) {
	source := observedAt.Add(-90 * time.Second)
	p := InspectBatch(observedAt, []time.Time{source})

	if p.SkewSeconds != 90 {
		t.Fatalf("expected skew +90s (collector leads), got %v", p.SkewSeconds)
	}
}

func TestInspectBatch_UsesNewestSource(t *testing.T) {
	p := InspectBatch(observedAt, []time.Time{
		observedAt.Add(-10 * time.Minute),
		observedAt.Add(-1 * time.Minute), // newest
		observedAt.Add(-5 * time.Minute),
	})

	if !p.NewestSource.Equal(observedAt.Add(-1 * time.Minute)) {
		t.Fatalf("expected newest source, got %v", p.NewestSource)
	}
	if p.SkewSeconds != 60 {
		t.Fatalf("expected skew 60s against newest sample, got %v", p.SkewSeconds)
	}
}

func TestInspectBatch_ZeroTimestampsCountAsFallback(t *testing.T) {
	p := InspectBatch(observedAt, []time.Time{{}, {}, observedAt.Add(-30 * time.Second)})

	if p.Fallbacks != 2 {
		t.Fatalf("expected 2 fallbacks, got %d", p.Fallbacks)
	}
	// A zero timestamp must not drag the skew toward the epoch.
	if p.SkewSeconds != 30 {
		t.Fatalf("expected skew 30s from the usable sample only, got %v", p.SkewSeconds)
	}
}

func TestInspectBatch_AllZeroIsPureFallback(t *testing.T) {
	p := InspectBatch(observedAt, []time.Time{{}, {}})

	if p.HasSource {
		t.Fatal("expected HasSource false when nothing was comparable")
	}
	if p.Fallbacks != 2 {
		t.Fatalf("expected 2 fallbacks, got %d", p.Fallbacks)
	}
	if p.SkewSeconds != 0 {
		t.Fatalf("expected zero skew when nothing was compared, got %v", p.SkewSeconds)
	}
}

func TestInspectBatch_EmptyBatch(t *testing.T) {
	p := InspectBatch(observedAt, nil)
	if p.HasSource || p.Fallbacks != 0 {
		t.Fatalf("expected an empty report, got %+v", p)
	}
}

func TestExceedsWarnThreshold(t *testing.T) {
	tests := []struct {
		name      string
		skew      time.Duration
		threshold time.Duration
		want      bool
	}{
		{"inside threshold", 4 * time.Minute, 5 * time.Minute, false},
		{"past threshold", 6 * time.Minute, 5 * time.Minute, true},
		{"negative past threshold", -6 * time.Minute, 5 * time.Minute, true},
		{"zero threshold falls back to default", 6 * time.Minute, 0, true},
		{"zero threshold default not tripped", 4 * time.Minute, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := InspectBatch(observedAt, []time.Time{observedAt.Add(-tc.skew)})
			if got := p.ExceedsWarnThreshold(tc.threshold); got != tc.want {
				t.Fatalf("ExceedsWarnThreshold = %v, want %v (skew %v)", got, tc.want, p.SkewSeconds)
			}
		})
	}
}

func TestExceedsWarnThreshold_NoSourceNeverWarns(t *testing.T) {
	p := InspectBatch(observedAt, []time.Time{{}})
	if p.ExceedsWarnThreshold(time.Nanosecond) {
		t.Fatal("a batch with no source timestamp must not warn about skew")
	}
}

func TestMetrics_EmitsSkewGauge(t *testing.T) {
	p := InspectBatch(observedAt, []time.Time{observedAt.Add(time.Hour)})
	ms := p.Metrics("vmware", observedAt)

	if len(ms) != 1 {
		t.Fatalf("expected only the skew gauge, got %d entries", len(ms))
	}
	if ms[0].Name != MetricClockSkewSeconds {
		t.Fatalf("unexpected metric name %q", ms[0].Name)
	}
	g, ok := ms[0].Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("expected a float64 gauge, got %T", ms[0].Data)
	}
	if g.DataPoints[0].Value != -3600 {
		t.Fatalf("expected -3600, got %v", g.DataPoints[0].Value)
	}
	if !g.DataPoints[0].Time.Equal(observedAt) {
		t.Fatalf("expected the gauge stamped at the collection instant, got %v", g.DataPoints[0].Time)
	}
}

func TestMetrics_EmitsFallbackCounter(t *testing.T) {
	p := InspectBatch(observedAt, []time.Time{{}, {}})
	ms := p.Metrics("netinfra", observedAt)

	if len(ms) != 1 {
		t.Fatalf("expected only the fallback counter, got %d entries", len(ms))
	}
	if ms[0].Name != MetricTimestampFallbackTotal {
		t.Fatalf("unexpected metric name %q", ms[0].Name)
	}
	s, ok := ms[0].Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("expected an int64 sum, got %T", ms[0].Data)
	}
	if s.DataPoints[0].Value != 2 {
		t.Fatalf("expected 2 fallbacks, got %v", s.DataPoints[0].Value)
	}
}

func TestMetrics_HealthyBatchEmitsNothingExtra(t *testing.T) {
	// Perfect agreement, no fallbacks: the skew gauge still reports (zero is a
	// real measurement) but no fallback counter is emitted.
	p := InspectBatch(observedAt, []time.Time{observedAt})
	ms := p.Metrics("storage", observedAt)

	if len(ms) != 1 || ms[0].Name != MetricClockSkewSeconds {
		t.Fatalf("expected just the skew gauge, got %+v", ms)
	}
}

func TestMetrics_EmptyBatchEmitsNothing(t *testing.T) {
	p := InspectBatch(observedAt, nil)
	if ms := p.Metrics("storage", observedAt); len(ms) != 0 {
		t.Fatalf("expected no provenance metrics, got %d", len(ms))
	}
}
