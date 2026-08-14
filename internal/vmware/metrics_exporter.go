// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"

	"github.com/mirastacklabs-ai/telegen/internal/timeutil"
	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/otelcfg"
)

// scopeName is the OTel instrumentation scope for VMware signals.
const scopeName = "telegen.vmware"

const maxDataPointsPerBatch = 2000

// exportMetrics groups the normalized metrics by name and exports them through
// the shared OTLP metrics exporter as a single ResourceMetrics batch.
//
// Reference pattern: internal/snmp/otlp_exporter.go:284-341 (ExportDirect).
// Unlike that implementation, this emits one metricdata.Metrics per unique
// metric name so metric identity is preserved end-to-end.
func exportMetrics(ctx context.Context, exp sdkmetric.Exporter, target string, extra map[string]string, metrics []vmwaredef.Metric, skewWarn time.Duration, logger timeutil.SkewLogger) error {
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

	// One export instant for the whole batch. Kept separate from each metric's
	// Timestamp (which is the vCenter sample time where available) so collection
	// lag stays measurable instead of being erased.
	observedAt := time.Now().UTC()
	sourceTimestamps := make([]time.Time, 0, len(metrics))

	for _, m := range metrics {
		switch m.TimestampSource {
		case vmwaredef.TimestampFromSource:
			sourceTimestamps = append(sourceTimestamps, m.Timestamp)
		case vmwaredef.TimestampFromFallback:
			sourceTimestamps = append(sourceTimestamps, time.Time{})
		case vmwaredef.TimestampFromCycleInstant:
			// No source timestamp exists for inventory gauges.
		}
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
	// Ride the same OTLP batch as the domain metrics so a bad clock announces
	// itself in the pipeline that actually reaches VictoriaMetrics. On the
	// Phoenix host this gauge would have read roughly -21600.
	provenance := timeutil.InspectBatch(observedAt, sourceTimestamps)
	provenance.WarnIfSkewed("vmware", skewWarn, logger)
	ms = append(ms, provenance.Metrics("vmware", observedAt)...)

	res := resource.NewSchemaless(resourceAttrs...)
	scope := instrumentation.Scope{Name: scopeName, Version: "1.0.0"}

	chunks := make([][]metricdata.Metrics, 0, (len(ms)/4)+1)
	current := make([]metricdata.Metrics, 0, len(ms))
	currentPoints := 0
	for _, metric := range ms {
		points := dataPointCount(metric)
		if len(current) > 0 && currentPoints+points > maxDataPointsPerBatch {
			chunks = append(chunks, current)
			current = make([]metricdata.Metrics, 0, len(ms))
			currentPoints = 0
		}
		current = append(current, metric)
		currentPoints += points
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}

	var exportErr error
	for i, chunk := range chunks {
		rm := &metricdata.ResourceMetrics{
			Resource: res,
			ScopeMetrics: []metricdata.ScopeMetrics{
				{
					Scope:   scope,
					Metrics: chunk,
				},
			},
		}
		if err := exp.Export(ctx, rm); err != nil {
			if logger != nil {
				logger.Warn("vmware metrics chunk export failed",
					"chunk_index", i,
					"metrics", len(chunk),
					"data_points", metricsDataPointCount(chunk),
					"error", err)
			}
			exportErr = errors.Join(exportErr, err)
		}
	}

	return exportErr
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

func dataPointCount(m metricdata.Metrics) int {
	switch data := m.Data.(type) {
	case metricdata.Gauge[float64]:
		return len(data.DataPoints)
	case metricdata.Sum[float64]:
		return len(data.DataPoints)
	case metricdata.Sum[int64]:
		return len(data.DataPoints)
	default:
		return 0
	}
}

func metricsDataPointCount(metrics []metricdata.Metrics) int {
	total := 0
	for _, m := range metrics {
		total += dataPointCount(m)
	}
	return total
}
