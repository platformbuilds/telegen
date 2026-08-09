// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/otelcfg"
)

// scopeName is the OTel instrumentation scope for VMware signals.
const scopeName = "telegen.vmware"

// exportMetrics groups the normalized metrics by name and exports them through
// the shared OTLP metrics exporter as a single ResourceMetrics batch.
//
// Reference pattern: internal/snmp/otlp_exporter.go:284-341 (ExportDirect).
// Unlike that implementation, this emits one metricdata.Metrics per unique
// metric name so metric identity is preserved end-to-end.
func exportMetrics(ctx context.Context, exp sdkmetric.Exporter, target string, extra map[string]string, metrics []vmwaredef.Metric) error {
	if len(metrics) == 0 {
		return nil
	}

	type bucket struct {
		help    string
		typ     vmwaredef.MetricType
		gauge   []metricdata.DataPoint[float64]
		counter []metricdata.DataPoint[float64]
	}

	order := make([]string, 0)
	buckets := make(map[string]*bucket)

	for _, m := range metrics {
		attrs := buildAttributes(m.Labels, extra)
		dp := metricdata.DataPoint[float64]{
			Attributes: attribute.NewSet(attrs...),
			Time:       m.Timestamp,
			Value:      m.Value,
		}
		// Gauges are point-in-time; set StartTime equal to Time.
		dp.StartTime = m.Timestamp

		b, ok := buckets[m.Name]
		if !ok {
			b = &bucket{help: m.Help, typ: m.Type}
			buckets[m.Name] = b
			order = append(order, m.Name)
		}

		if m.Type == vmwaredef.MetricTypeCounter {
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
				Name:        name,
				Description: b.help,
				Data:        metricdata.Gauge[float64]{DataPoints: b.gauge},
			})
		}
		if len(b.counter) > 0 {
			ms = append(ms, metricdata.Metrics{
				Name:        name,
				Description: b.help,
				Data: metricdata.Sum[float64]{
					DataPoints:  b.counter,
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
				},
			})
		}
	}

	resourceAttrs := []attribute.KeyValue{
		semconv.ServiceName("telegen-vmware"),
		attribute.String("vcenter", target),
	}
	resourceAttrs = append(resourceAttrs, otelcfg.SiteResourceAttributes()...)
	res := resource.NewSchemaless(resourceAttrs...)

	rm := &metricdata.ResourceMetrics{
		Resource: res,
		ScopeMetrics: []metricdata.ScopeMetrics{
			{
				Scope:   instrumentation.Scope{Name: scopeName, Version: "1.0.0"},
				Metrics: ms,
			},
		},
	}

	return exp.Export(ctx, rm)
}

// buildAttributes converts metric labels plus extra labels to OTel attributes.
// Mirrors internal/snmp/otlp_exporter.go:276-282.
func buildAttributes(labels, extra map[string]string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(labels)+len(extra))
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	for k, v := range extra {
		attrs = append(attrs, attribute.String(k, v))
	}
	return attrs
}
