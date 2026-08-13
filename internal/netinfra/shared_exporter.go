// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netinfra

import (
	"context"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/netinfra/types"
	"github.com/mirastacklabs-ai/telegen/internal/timeutil"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func exportWithSharedMetricsExporter(ctx context.Context, exp sdkmetric.Exporter, metrics []*types.NetworkMetric, skewWarn time.Duration, logger timeutil.SkewLogger) error {
	if exp == nil || len(metrics) == 0 {
		return nil
	}

	type bucket struct {
		typ      types.MetricType
		gaugeDPs []metricdata.DataPoint[float64]
		sumDPs   []metricdata.DataPoint[float64]
	}
	buckets := map[string]*bucket{}
	order := make([]string, 0, len(metrics))

	// One export instant for the whole batch. This is the collector's own clock
	// reading, kept separate from each metric's Timestamp so collection lag
	// stays measurable instead of being erased.
	observedAt := time.Now().UTC()
	sourceTimestamps := make([]time.Time, 0, len(metrics))

	for _, m := range metrics {
		if m == nil || m.Name == "" {
			continue
		}
		if m.ObservedTimestamp.IsZero() {
			m.ObservedTimestamp = observedAt
		}
		sourceTimestamps = append(sourceTimestamps, m.Timestamp)
		b, ok := buckets[m.Name]
		if !ok {
			b = &bucket{typ: m.Type}
			buckets[m.Name] = b
			order = append(order, m.Name)
		}
		dp := metricdata.DataPoint[float64]{
			Attributes: labelsToAttrSet(m.Labels),
			Time:       m.Timestamp, // Use source timestamp (from gNMI, SNMP, etc.), not collection instant
			Value:      m.Value,
		}
		if m.Type == types.MetricTypeCounter {
			b.sumDPs = append(b.sumDPs, dp)
		} else {
			b.gaugeDPs = append(b.gaugeDPs, dp)
		}
	}

	ms := make([]metricdata.Metrics, 0, len(order))
	for _, name := range order {
		b := buckets[name]
		if len(b.gaugeDPs) > 0 {
			ms = append(ms, metricdata.Metrics{
				Name: name,
				Data: metricdata.Gauge[float64]{DataPoints: b.gaugeDPs},
			})
		}
		if len(b.sumDPs) > 0 {
			ms = append(ms, metricdata.Metrics{
				Name: name,
				Data: metricdata.Sum[float64]{
					DataPoints:  b.sumDPs,
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
				},
			})
		}
	}

	// Ride the same OTLP batch as the domain metrics so a bad clock announces
	// itself in the pipeline that actually reaches VictoriaMetrics.
	provenance := timeutil.InspectBatch(observedAt, sourceTimestamps)
	provenance.WarnIfSkewed("netinfra", skewWarn, logger)
	ms = append(ms, provenance.Metrics("netinfra", observedAt)...)

	rm := &metricdata.ResourceMetrics{
		Resource: resource.NewSchemaless(
			semconv.ServiceName("telegen-netinfra"),
			attribute.String("signal.source", "netinfra"),
		),
		ScopeMetrics: []metricdata.ScopeMetrics{
			{Metrics: ms},
		},
	}
	return exp.Export(ctx, rm)
}

func labelsToAttrSet(labels map[string]string) attribute.Set {
	if len(labels) == 0 {
		return attribute.NewSet()
	}
	kvs := make([]attribute.KeyValue, 0, len(labels))
	for k, v := range labels {
		kvs = append(kvs, attribute.String(k, v))
	}
	return attribute.NewSet(kvs...)
}
