// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"

	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
	"github.com/mirastacklabs-ai/telegen/internal/timeutil"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/otelcfg"
)

const scopeName = "telegen.storage"

func exportSharedMetrics(ctx context.Context, exp sdkmetric.Exporter, metrics []storagedef.Metric, skewWarn time.Duration, logger timeutil.SkewLogger) error {
	if exp == nil || len(metrics) == 0 {
		return nil
	}

	type bucket struct {
		help    string
		gauge   []metricdata.DataPoint[float64]
		counter []metricdata.DataPoint[float64]
	}
	order := make([]string, 0)
	buckets := map[string]*bucket{}

	// One export instant for the whole batch. Kept separate from each metric's
	// Timestamp so collection lag stays measurable instead of being erased.
	observedAt := time.Now().UTC()
	sourceTimestamps := make([]time.Time, 0, len(metrics))

	for i := range metrics {
		m := metrics[i]
		if metrics[i].ObservedTimestamp.IsZero() {
			metrics[i].ObservedTimestamp = observedAt
		}
		sourceTimestamps = append(sourceTimestamps, m.Timestamp)
		attrs := make([]attribute.KeyValue, 0, len(m.Labels))
		for k, v := range m.Labels {
			attrs = append(attrs, attribute.String(k, v))
		}
		dp := metricdata.DataPoint[float64]{
			Attributes: attribute.NewSet(attrs...),
			Time:       m.Timestamp,
			StartTime:  m.Timestamp,
			Value:      m.Value,
		}
		b, ok := buckets[m.Name]
		if !ok {
			b = &bucket{help: m.Help}
			buckets[m.Name] = b
			order = append(order, m.Name)
		}
		if m.Type == storagedef.MetricTypeCounter {
			b.counter = append(b.counter, dp)
		} else {
			b.gauge = append(b.gauge, dp)
		}
	}

	ms := make([]metricdata.Metrics, 0, len(order))
	for _, name := range order {
		b := buckets[name]
		if len(b.gauge) > 0 {
			ms = append(ms, metricdata.Metrics{
				Name: name, Description: b.help,
				Data: metricdata.Gauge[float64]{DataPoints: b.gauge},
			})
		}
		if len(b.counter) > 0 {
			ms = append(ms, metricdata.Metrics{
				Name: name, Description: b.help,
				Data: metricdata.Sum[float64]{
					DataPoints: b.counter, Temporality: metricdata.CumulativeTemporality, IsMonotonic: true,
				},
			})
		}
	}

	// Ride the same OTLP batch as the domain metrics so a bad clock announces
	// itself in the pipeline that actually reaches VictoriaMetrics.
	provenance := timeutil.InspectBatch(observedAt, sourceTimestamps)
	provenance.WarnIfSkewed("storage", skewWarn, logger)
	ms = append(ms, provenance.Metrics("storage", observedAt)...)

	resourceAttrs := []attribute.KeyValue{semconv.ServiceName("telegen-storage")}
	resourceAttrs = append(resourceAttrs, otelcfg.SiteResourceAttributes()...)

	rm := &metricdata.ResourceMetrics{
		Resource: resource.NewSchemaless(resourceAttrs...),
		ScopeMetrics: []metricdata.ScopeMetrics{{
			Scope:   instrumentation.Scope{Name: scopeName, Version: "1.0.0"},
			Metrics: ms,
		}},
	}
	return exp.Export(ctx, rm)
}
