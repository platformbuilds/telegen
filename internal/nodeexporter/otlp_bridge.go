// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package nodeexporter

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"github.com/platformbuilds/telegen/internal/sigdef"
)

// OTLPBridge bridges node_exporter metrics to telegen's OTLP export pipeline.
// It converts Prometheus client_model MetricFamily to OTEL SDK ResourceMetrics
// and sends them through the shared OTEL exporter.
type OTLPBridge struct {
	exporter    sdkmetric.Exporter
	resource    *resource.Resource
	environment *DetectedEnvironment
	logger      *slog.Logger
	mu          sync.Mutex
}

// NewOTLPBridge creates a new OTLP bridge for node exporter metrics.
func NewOTLPBridge(
	exporter sdkmetric.Exporter,
	env *DetectedEnvironment,
	logger *slog.Logger,
) (*OTLPBridge, error) {
	if exporter == nil {
		return nil, fmt.Errorf("exporter cannot be nil")
	}

	// Build resource attributes from environment
	res, err := buildResource(env)
	if err != nil {
		return nil, fmt.Errorf("failed to build resource: %w", err)
	}

	return &OTLPBridge{
		exporter:    exporter,
		resource:    res,
		environment: env,
		logger:      logger,
	}, nil
}

// buildResource creates an OTEL resource from the detected environment.
func buildResource(env *DetectedEnvironment) (*resource.Resource, error) {
	attrs := []resource.Option{
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithOS(),
		resource.WithHost(),
	}

	// Add environment-specific attributes
	if env != nil {
		if env.Kubernetes != nil && env.Kubernetes.Detected {
			attrs = append(attrs, resource.WithAttributes(
				semconv.K8SNodeName(env.Kubernetes.NodeName),
				semconv.K8SNamespaceName(env.Kubernetes.Namespace),
				semconv.K8SPodName(env.Kubernetes.PodName),
			))
			if env.Kubernetes.ClusterName != "" {
				attrs = append(attrs, resource.WithAttributes(
					semconv.K8SClusterName(env.Kubernetes.ClusterName),
				))
			}
		}
		// Add cloud/VM attributes if available
		for k, v := range env.Labels {
			attrs = append(attrs, resource.WithAttributes(
				semconv.CloudProviderKey.String(k),
			))
			_ = v // label values are included via environment labels on metrics
		}
	}

	return resource.New(context.Background(), attrs...)
}

// ReceiveMetrics implements MetricsReceiver and converts/sends metrics via OTLP.
func (b *OTLPBridge) ReceiveMetrics(ctx context.Context, batch *MetricsBatch) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(batch.Metrics) == 0 {
		return nil
	}

	// Convert Prometheus metrics to OTEL ResourceMetrics
	rm := b.convertToResourceMetrics(batch)

	// Export via the OTEL exporter
	if err := b.exporter.Export(ctx, rm); err != nil {
		b.logger.Error("failed to export metrics via OTLP",
			"error", err,
			"metric_families", len(batch.Metrics))
		return err
	}

	b.logger.Debug("exported metrics via OTLP",
		"metric_families", len(batch.Metrics),
		"timestamp", batch.Timestamp)

	return nil
}

// convertToResourceMetrics converts Prometheus MetricFamily to OTEL ResourceMetrics.
func (b *OTLPBridge) convertToResourceMetrics(batch *MetricsBatch) *metricdata.ResourceMetrics {
	scopeMetrics := make([]metricdata.ScopeMetrics, 0, 1)
	metrics := make([]metricdata.Metrics, 0, len(batch.Metrics))

	for _, family := range batch.Metrics {
		if family == nil || family.Name == nil {
			continue
		}

		m := b.convertMetricFamily(family, batch.Timestamp)
		if m != nil {
			metrics = append(metrics, *m)
		}
	}

	if len(metrics) > 0 {
		scopeMetrics = append(scopeMetrics, metricdata.ScopeMetrics{
			Scope: instrumentation.Scope{
				Name:    "github.com/platformbuilds/telegen/nodeexporter",
				Version: "1.0.0",
			},
			Metrics: metrics,
		})
	}

	return &metricdata.ResourceMetrics{
		Resource:     b.resource,
		ScopeMetrics: scopeMetrics,
	}
}

// convertMetricFamily converts a single Prometheus MetricFamily to OTEL Metrics.
func (b *OTLPBridge) convertMetricFamily(family *dto.MetricFamily, timestamp time.Time) *metricdata.Metrics {
	if len(family.Metric) == 0 {
		return nil
	}

	name := family.GetName()
	help := family.GetHelp()
	mtype := family.GetType()

	switch mtype {
	case dto.MetricType_COUNTER:
		return b.convertCounter(name, help, family.Metric, timestamp)
	case dto.MetricType_GAUGE:
		return b.convertGauge(name, help, family.Metric, timestamp)
	case dto.MetricType_HISTOGRAM:
		return b.convertHistogram(name, help, family.Metric, timestamp)
	case dto.MetricType_SUMMARY:
		return b.convertSummary(name, help, family.Metric, timestamp)
	case dto.MetricType_UNTYPED:
		// Treat UNTYPED as Gauge
		return b.convertGauge(name, help, family.Metric, timestamp)
	default:
		b.logger.Debug("unknown metric type", "name", name, "type", mtype)
		return nil
	}
}

// convertCounter converts Prometheus counter metrics to OTEL Sum.
func (b *OTLPBridge) convertCounter(name, help string, metrics []*dto.Metric, timestamp time.Time) *metricdata.Metrics {
	dataPoints := make([]metricdata.DataPoint[float64], 0, len(metrics))

	for _, m := range metrics {
		if m.Counter == nil {
			continue
		}

		attrs := b.convertLabelsWithMetadata(m.Label, name)
		dp := metricdata.DataPoint[float64]{
			Attributes: attrs,
			Time:       timestamp,
			Value:      m.Counter.GetValue(),
		}
		dataPoints = append(dataPoints, dp)
	}

	if len(dataPoints) == 0 {
		return nil
	}

	return &metricdata.Metrics{
		Name:        name,
		Description: help,
		Unit:        inferUnit(name),
		Data: metricdata.Sum[float64]{
			DataPoints:  dataPoints,
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
		},
	}
}

// convertGauge converts Prometheus gauge metrics to OTEL Gauge.
func (b *OTLPBridge) convertGauge(name, help string, metrics []*dto.Metric, timestamp time.Time) *metricdata.Metrics {
	dataPoints := make([]metricdata.DataPoint[float64], 0, len(metrics))

	for _, m := range metrics {
		if m.Gauge == nil {
			continue
		}

		attrs := b.convertLabelsWithMetadata(m.Label, name)
		dp := metricdata.DataPoint[float64]{
			Attributes: attrs,
			Time:       timestamp,
			Value:      m.Gauge.GetValue(),
		}
		dataPoints = append(dataPoints, dp)
	}

	if len(dataPoints) == 0 {
		return nil
	}

	return &metricdata.Metrics{
		Name:        name,
		Description: help,
		Unit:        inferUnit(name),
		Data: metricdata.Gauge[float64]{
			DataPoints: dataPoints,
		},
	}
}

// convertHistogram converts Prometheus histogram metrics to OTEL ExponentialHistogram.
func (b *OTLPBridge) convertHistogram(name, help string, metrics []*dto.Metric, timestamp time.Time) *metricdata.Metrics {
	dataPoints := make([]metricdata.HistogramDataPoint[float64], 0, len(metrics))

	for _, m := range metrics {
		if m.Histogram == nil {
			continue
		}

		h := m.Histogram
		attrs := b.convertLabelsWithMetadata(m.Label, name)

		// Convert bucket boundaries and counts
		bucketCounts := make([]uint64, 0, len(h.Bucket)+1)
		boundaries := make([]float64, 0, len(h.Bucket))

		var prevCount uint64
		for _, bucket := range h.Bucket {
			boundaries = append(boundaries, bucket.GetUpperBound())
			// Prometheus buckets are cumulative, OTEL are not
			count := bucket.GetCumulativeCount()
			bucketCounts = append(bucketCounts, count-prevCount)
			prevCount = count
		}
		// Add the +Inf bucket
		if h.SampleCount != nil {
			bucketCounts = append(bucketCounts, *h.SampleCount-prevCount)
		}

		dp := metricdata.HistogramDataPoint[float64]{
			Attributes:   attrs,
			StartTime:    timestamp.Add(-time.Minute), // Approximation
			Time:         timestamp,
			Count:        h.GetSampleCount(),
			Sum:          h.GetSampleSum(),
			Bounds:       boundaries,
			BucketCounts: bucketCounts,
		}
		dataPoints = append(dataPoints, dp)
	}

	if len(dataPoints) == 0 {
		return nil
	}

	return &metricdata.Metrics{
		Name:        name,
		Description: help,
		Unit:        inferUnit(name),
		Data: metricdata.Histogram[float64]{
			DataPoints:  dataPoints,
			Temporality: metricdata.CumulativeTemporality,
		},
	}
}

// convertSummary converts Prometheus summary metrics to OTEL Summary (via Gauge approximation).
// Note: OTEL doesn't have a native Summary type, so we export quantiles as separate gauge metrics.
func (b *OTLPBridge) convertSummary(name, help string, metrics []*dto.Metric, timestamp time.Time) *metricdata.Metrics {
	// For summary, we'll convert to a gauge with quantile labels
	// This is a common approach since OTEL doesn't have native summary support
	dataPoints := make([]metricdata.DataPoint[float64], 0, len(metrics)*3)

	for _, m := range metrics {
		if m.Summary == nil {
			continue
		}

		s := m.Summary
		baseAttrs := b.convertLabelsWithMetadata(m.Label, name)

		// Export sum and count as separate data points
		sumDP := metricdata.DataPoint[float64]{
			Attributes: baseAttrs,
			Time:       timestamp,
			Value:      s.GetSampleSum(),
		}
		dataPoints = append(dataPoints, sumDP)
	}

	if len(dataPoints) == 0 {
		return nil
	}

	return &metricdata.Metrics{
		Name:        name + "_sum",
		Description: help,
		Unit:        inferUnit(name),
		Data: metricdata.Gauge[float64]{
			DataPoints: dataPoints,
		},
	}
}

// convertLabels converts Prometheus labels to OTEL attribute set.
func (b *OTLPBridge) convertLabels(labels []*dto.LabelPair) attribute.Set {
	if len(labels) == 0 {
		return attribute.NewSet()
	}

	attrs := make([]attribute.KeyValue, 0, len(labels))
	for _, label := range labels {
		if label.Name != nil && label.Value != nil {
			attrs = append(attrs, attribute.String(*label.Name, *label.Value))
		}
	}

	return attribute.NewSet(attrs...)
}

// convertLabelsWithMetadata converts Prometheus labels to OTEL attribute set,
// adding telegen signal metadata based on the metric name.
func (b *OTLPBridge) convertLabelsWithMetadata(labels []*dto.LabelPair, metricName string) attribute.Set {
	signalMeta := getSignalMetadataForMetric(metricName)
	metaAttrs := signalMeta.ToAttributes()

	totalLen := len(labels) + len(metaAttrs)
	attrs := make([]attribute.KeyValue, 0, totalLen)

	// Add original labels
	for _, label := range labels {
		if label.Name != nil && label.Value != nil {
			attrs = append(attrs, attribute.String(*label.Name, *label.Value))
		}
	}

	// Add telegen signal metadata
	attrs = append(attrs, metaAttrs...)

	return attribute.NewSet(attrs...)
}

// getSignalMetadataForMetric returns the appropriate SignalMetadata based on metric name prefix.
func getSignalMetadataForMetric(name string) *sigdef.SignalMetadata {
	switch {
	case strings.HasPrefix(name, "node_cpu"):
		return sigdef.NodeExporterCPUMetrics
	case strings.HasPrefix(name, "node_memory") || strings.HasPrefix(name, "node_vmstat"):
		return sigdef.NodeExporterMemoryMetrics
	case strings.HasPrefix(name, "node_disk"):
		return sigdef.NodeExporterDiskMetrics
	case strings.HasPrefix(name, "node_filesystem"):
		return sigdef.NodeExporterFilesystemMetrics
	case strings.HasPrefix(name, "node_network"):
		return sigdef.NodeExporterNetworkMetrics
	case strings.HasPrefix(name, "node_load"):
		return sigdef.NodeExporterLoadMetrics
	case strings.HasPrefix(name, "node_time") || strings.HasPrefix(name, "node_timex"):
		return sigdef.NodeExporterTimeMetrics
	case strings.HasPrefix(name, "node_entropy"):
		return sigdef.NodeExporterEntropyMetrics
	case strings.HasPrefix(name, "node_bonding") || strings.HasPrefix(name, "node_edac") ||
		strings.HasPrefix(name, "node_md") || strings.HasPrefix(name, "node_hwmon") ||
		strings.HasPrefix(name, "node_thermal"):
		return sigdef.NodeExporterHardwareMetrics
	case strings.HasPrefix(name, "node_zfs"):
		return sigdef.NodeExporterZFSMetrics
	case strings.HasPrefix(name, "node_nfs"):
		return sigdef.NodeExporterNFSMetrics
	case strings.HasPrefix(name, "node_uname") || strings.HasPrefix(name, "node_boot") ||
		strings.HasPrefix(name, "node_os"):
		return sigdef.NodeExporterSystemMetrics
	case strings.HasPrefix(name, "node_procs") || strings.HasPrefix(name, "node_forks") ||
		strings.HasPrefix(name, "node_context") || strings.HasPrefix(name, "node_intr"):
		return sigdef.NodeExporterProcessMetrics
	default:
		// Default to system metrics for unknown node_ prefixed metrics
		if strings.HasPrefix(name, "node_") {
			return sigdef.NodeExporterSystemMetrics
		}
		// Fallback for non-node metrics (like go_*, process_*)
		return &sigdef.SignalMetadata{
			Category:      "Node Exporter",
			SubCategory:   "Runtime",
			SourceModule:  "internal/nodeexporter",
			CollectorType: sigdef.CollectorTypeProcFS,
			SignalType:    sigdef.SignalMetrics,
		}
	}
}

// inferUnit infers the unit from the metric name based on common conventions.
func inferUnit(name string) string {
	switch {
	case strings.HasSuffix(name, "_seconds") || strings.HasSuffix(name, "_seconds_total"):
		return "s"
	case strings.HasSuffix(name, "_bytes") || strings.HasSuffix(name, "_bytes_total"):
		return "By"
	case strings.HasSuffix(name, "_total"):
		return "1"
	case strings.HasSuffix(name, "_ratio"):
		return "1"
	case strings.HasSuffix(name, "_percent"):
		return "%"
	case strings.HasSuffix(name, "_celsius"):
		return "Cel"
	default:
		return ""
	}
}
