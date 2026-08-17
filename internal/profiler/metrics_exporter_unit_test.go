// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"log/slog"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestProfileMetricsDeclareNoDimensionlessUnit asserts that no metric emitted by any of
// the five profile converters declares the OTLP unit "1".
//
// A sum or gauge carrying unit "1" makes the collector's prometheusremotewrite exporter
// append a _ratio suffix to the series name, so profiler.cpu.samples would land in the
// TSDB as profiler_cpu_samples_ratio. Every profiler.* count metric below counts
// occurrences and is not a dimensionless ratio, so the unit must stay unset.
func TestProfileMetricsDeclareNoDimensionlessUnit(t *testing.T) {
	exporter := &MetricsExporter{
		config: DefaultMetricsExporterConfig(),
		log:    slog.Default(),
	}

	timestamp := time.Now().UTC()

	// No samples: every converter still emits its full set of metric families, so the
	// declared units are exercised without entering buildAggregationKey, which needs a
	// live ProcessMetadataResolver whose LRU goroutine would trip the package goleak check.
	profileFor := func(pt ProfileType) *Profile {
		return &Profile{
			Type:      pt,
			Timestamp: timestamp,
			Duration:  time.Second,
		}
	}

	converters := []struct {
		profileType ProfileType
		convert     func(*Profile, time.Time) []metricdata.Metrics
	}{
		{ProfileTypeCPU, exporter.cpuProfileToMetrics},
		{ProfileTypeOffCPU, exporter.offCPUProfileToMetrics},
		{ProfileTypeMemory, exporter.memoryProfileToMetrics},
		{ProfileTypeMutex, exporter.mutexProfileToMetrics},
		{ProfileTypeWall, exporter.wallProfileToMetrics},
	}

	for _, tc := range converters {
		metrics := tc.convert(profileFor(tc.profileType), timestamp)
		if len(metrics) == 0 {
			t.Fatalf("%s: expected at least one metric", tc.profileType)
		}
		for _, metric := range metrics {
			if metric.Unit == "1" {
				t.Fatalf("%s: metric %q declares dimensionless unit %q; the collector appends a _ratio suffix to it",
					tc.profileType, metric.Name, metric.Unit)
			}
		}
	}
}
