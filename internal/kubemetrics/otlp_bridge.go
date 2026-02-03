// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"bytes"
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/platformbuilds/telegen/internal/sigdef"
)

// OTLPBridge converts Prometheus metrics to OTEL format and exports via OTLP
type OTLPBridge struct {
	exporter   sdkmetric.Exporter
	resource   *resource.Resource
	logger     *slog.Logger
	metaCfg    sigdef.MetadataFieldsConfig
	enableMeta bool
}

// NewOTLPBridge creates a new OTLP bridge
func NewOTLPBridge(
	exporter sdkmetric.Exporter,
	res *resource.Resource,
	logger *slog.Logger,
	metaCfg sigdef.MetadataFieldsConfig,
	enableMeta bool,
) *OTLPBridge {
	if res == nil {
		res, _ = resource.New(context.Background(),
			resource.WithSchemaURL(semconv.SchemaURL),
			resource.WithOS(),
			resource.WithHost(),
			resource.WithAttributes(
				semconv.ServiceName("telegen-kubemetrics"),
			),
		)
	}

	return &OTLPBridge{
		exporter:   exporter,
		resource:   res,
		logger:     logger,
		metaCfg:    metaCfg,
		enableMeta: enableMeta,
	}
}

// ExportPrometheusMetrics exports Prometheus metrics via OTLP
func (b *OTLPBridge) ExportPrometheusMetrics(ctx context.Context, families map[string]*dto.MetricFamily) error {
	rm := b.convertToResourceMetrics(families)
	if rm == nil || len(rm.ScopeMetrics) == 0 {
		return nil
	}

	return b.exporter.Export(ctx, rm)
}

// convertToResourceMetrics converts Prometheus MetricFamily to OTEL ResourceMetrics
func (b *OTLPBridge) convertToResourceMetrics(families map[string]*dto.MetricFamily) *metricdata.ResourceMetrics {
	if len(families) == 0 {
		return nil
	}

	metrics := make([]metricdata.Metrics, 0, len(families))
	now := time.Now()

	for name, family := range families {
		m := b.convertFamily(name, family, now)
		if m != nil {
			metrics = append(metrics, *m)
		}
	}

	if len(metrics) == 0 {
		return nil
	}

	return &metricdata.ResourceMetrics{
		Resource: b.resource,
		ScopeMetrics: []metricdata.ScopeMetrics{
			{
				Scope: instrumentation.Scope{
					Name:    "github.com/platformbuilds/telegen/kubemetrics",
					Version: "1.0.0",
				},
				Metrics: metrics,
			},
		},
	}
}

// convertFamily converts a single Prometheus MetricFamily to OTEL Metrics
func (b *OTLPBridge) convertFamily(name string, family *dto.MetricFamily, now time.Time) *metricdata.Metrics {
	if family == nil || len(family.Metric) == 0 {
		return nil
	}

	// Get signal metadata for this metric
	var signalAttrs []attribute.KeyValue
	if b.enableMeta {
		meta := SignalMetadataDefinitions[getMetricPrefix(name)]
		if meta != nil {
			signalAttrs = meta.ToAttributesWithConfig(b.metaCfg)
		}
	}

	switch family.GetType() {
	case dto.MetricType_GAUGE:
		return b.convertGauge(name, family, now, signalAttrs)
	case dto.MetricType_COUNTER:
		return b.convertCounter(name, family, now, signalAttrs)
	case dto.MetricType_HISTOGRAM:
		return b.convertHistogram(name, family, now, signalAttrs)
	case dto.MetricType_SUMMARY:
		// Convert summary to gauge for now
		return b.convertSummary(name, family, now, signalAttrs)
	default:
		return nil
	}
}

// convertGauge converts a Prometheus gauge to OTEL gauge
func (b *OTLPBridge) convertGauge(name string, family *dto.MetricFamily, now time.Time, signalAttrs []attribute.KeyValue) *metricdata.Metrics {
	dataPoints := make([]metricdata.DataPoint[float64], 0, len(family.Metric))

	for _, m := range family.Metric {
		if m.Gauge == nil {
			continue
		}

		attrs := b.convertLabels(m.Label)
		attrs = append(attrs, signalAttrs...)

		dataPoints = append(dataPoints, metricdata.DataPoint[float64]{
			Time:       now,
			Value:      m.Gauge.GetValue(),
			Attributes: attribute.NewSet(attrs...),
		})
	}

	if len(dataPoints) == 0 {
		return nil
	}

	return &metricdata.Metrics{
		Name:        name,
		Description: family.GetHelp(),
		Unit:        guessUnit(name),
		Data: metricdata.Gauge[float64]{
			DataPoints: dataPoints,
		},
	}
}

// convertCounter converts a Prometheus counter to OTEL sum
func (b *OTLPBridge) convertCounter(name string, family *dto.MetricFamily, now time.Time, signalAttrs []attribute.KeyValue) *metricdata.Metrics {
	dataPoints := make([]metricdata.DataPoint[float64], 0, len(family.Metric))

	for _, m := range family.Metric {
		if m.Counter == nil {
			continue
		}

		attrs := b.convertLabels(m.Label)
		attrs = append(attrs, signalAttrs...)

		dataPoints = append(dataPoints, metricdata.DataPoint[float64]{
			Time:       now,
			Value:      m.Counter.GetValue(),
			Attributes: attribute.NewSet(attrs...),
		})
	}

	if len(dataPoints) == 0 {
		return nil
	}

	return &metricdata.Metrics{
		Name:        name,
		Description: family.GetHelp(),
		Unit:        guessUnit(name),
		Data: metricdata.Sum[float64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints:  dataPoints,
		},
	}
}

// convertHistogram converts a Prometheus histogram to OTEL histogram
func (b *OTLPBridge) convertHistogram(name string, family *dto.MetricFamily, now time.Time, signalAttrs []attribute.KeyValue) *metricdata.Metrics {
	dataPoints := make([]metricdata.HistogramDataPoint[float64], 0, len(family.Metric))

	for _, m := range family.Metric {
		if m.Histogram == nil {
			continue
		}

		h := m.Histogram
		attrs := b.convertLabels(m.Label)
		attrs = append(attrs, signalAttrs...)

		bounds := make([]float64, 0, len(h.Bucket))
		counts := make([]uint64, 0, len(h.Bucket))

		for _, bucket := range h.Bucket {
			bounds = append(bounds, bucket.GetUpperBound())
			counts = append(counts, bucket.GetCumulativeCount())
		}

		dataPoints = append(dataPoints, metricdata.HistogramDataPoint[float64]{
			Time:         now,
			Count:        h.GetSampleCount(),
			Sum:          h.GetSampleSum(),
			Bounds:       bounds,
			BucketCounts: counts,
			Attributes:   attribute.NewSet(attrs...),
		})
	}

	if len(dataPoints) == 0 {
		return nil
	}

	return &metricdata.Metrics{
		Name:        name,
		Description: family.GetHelp(),
		Unit:        guessUnit(name),
		Data: metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints:  dataPoints,
		},
	}
}

// convertSummary converts a Prometheus summary to OTEL gauge (quantiles)
func (b *OTLPBridge) convertSummary(name string, family *dto.MetricFamily, now time.Time, signalAttrs []attribute.KeyValue) *metricdata.Metrics {
	dataPoints := make([]metricdata.DataPoint[float64], 0)

	for _, m := range family.Metric {
		if m.Summary == nil {
			continue
		}

		s := m.Summary
		baseAttrs := b.convertLabels(m.Label)
		baseAttrs = append(baseAttrs, signalAttrs...)

		// Export quantiles as separate data points
		for _, q := range s.Quantile {
			attrs := append(baseAttrs, attribute.Float64("quantile", q.GetQuantile()))
			dataPoints = append(dataPoints, metricdata.DataPoint[float64]{
				Time:       now,
				Value:      q.GetValue(),
				Attributes: attribute.NewSet(attrs...),
			})
		}
	}

	if len(dataPoints) == 0 {
		return nil
	}

	return &metricdata.Metrics{
		Name:        name,
		Description: family.GetHelp(),
		Unit:        guessUnit(name),
		Data: metricdata.Gauge[float64]{
			DataPoints: dataPoints,
		},
	}
}

// convertLabels converts Prometheus labels to OTEL attributes
func (b *OTLPBridge) convertLabels(labels []*dto.LabelPair) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(labels))
	for _, l := range labels {
		attrs = append(attrs, attribute.String(l.GetName(), l.GetValue()))
	}
	return attrs
}

// getMetricPrefix extracts the metric prefix for metadata lookup
func getMetricPrefix(name string) string {
	// Try common prefixes
	prefixes := []string{
		"kube_pod", "kube_deployment", "kube_node", "kube_statefulset",
		"kube_daemonset", "kube_replicaset", "kube_job", "kube_cronjob",
		"kube_service", "kube_namespace", "kube_persistentvolumeclaim",
		"kube_persistentvolume", "kube_configmap", "kube_secret",
		"kube_hpa", "kube_ingress", "kube_endpoints",
		"container_cpu", "container_memory", "container_network", "container_fs",
	}

	for _, p := range prefixes {
		if len(name) >= len(p) && name[:len(p)] == p {
			return p
		}
	}

	return ""
}

// guessUnit guesses the unit from the metric name
func guessUnit(name string) string {
	// Order matters: more specific suffixes must come first
	type suffixUnit struct {
		suffix string
		unit   string
	}
	suffixes := []suffixUnit{
		{"_bytes_total", "By"},
		{"_seconds_total", "s"},
		{"_bytes", "By"},
		{"_seconds", "s"},
		{"_total", "1"},
		{"_ratio", "1"},
		{"_percent", "%"},
	}

	for _, su := range suffixes {
		if len(name) > len(su.suffix) && name[len(name)-len(su.suffix):] == su.suffix {
			return su.unit
		}
	}

	return "1"
}

// ParsePrometheusText parses Prometheus text format to MetricFamily map
func ParsePrometheusText(data []byte) (map[string]*dto.MetricFamily, error) {
	parser := expfmt.NewTextParser(model.LegacyValidation)
	return parser.TextToMetricFamilies(bytes.NewReader(data))
}
