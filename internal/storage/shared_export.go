// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"

	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

const scopeName = "telegen.storage"

func exportSharedMetrics(ctx context.Context, exp sdkmetric.Exporter, metrics []storagedef.Metric) error {
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

	for _, m := range metrics {
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

	rm := &metricdata.ResourceMetrics{
		Resource: resource.NewSchemaless(semconv.ServiceName("telegen-storage")),
		ScopeMetrics: []metricdata.ScopeMetrics{{
			Scope:   instrumentation.Scope{Name: scopeName, Version: "1.0.0"},
			Metrics: ms,
		}},
	}
	return exp.Export(ctx, rm)
}
