package converters

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// PrometheusConverter converts Prometheus metrics to OTLP format.
type PrometheusConverter struct {
	// NormalizeMetricNames converts metric names to OTLP conventions.
	NormalizeMetricNames bool
	// AddTypeMetadata adds Prometheus type as metadata.
	AddTypeMetadata bool
}

// PrometheusMetricFamily represents a Prometheus metric family.
type PrometheusMetricFamily struct {
	Name    string
	Help    string
	Type    PrometheusMetricType
	Metrics []PrometheusMetric
}

// PrometheusMetric represents a single Prometheus metric sample.
type PrometheusMetric struct {
	Labels    map[string]string
	Value     float64
	Timestamp time.Time
	// For histograms.
	Buckets []HistogramBucket
	Count   uint64
	Sum     float64
	// For summaries.
	Quantiles []Quantile
}

// HistogramBucket represents a Prometheus histogram bucket.
type HistogramBucket struct {
	UpperBound      float64
	CumulativeCount uint64
}

// Quantile represents a Prometheus summary quantile.
type Quantile struct {
	Quantile float64
	Value    float64
}

// PrometheusMetricType represents Prometheus metric types.
type PrometheusMetricType int

const (
	PrometheusTypeUnknown PrometheusMetricType = iota
	PrometheusTypeCounter
	PrometheusTypeGauge
	PrometheusTypeHistogram
	PrometheusTypeSummary
	PrometheusTypeUntyped
)

// String returns the string representation of the metric type.
func (t PrometheusMetricType) String() string {
	switch t {
	case PrometheusTypeCounter:
		return "counter"
	case PrometheusTypeGauge:
		return "gauge"
	case PrometheusTypeHistogram:
		return "histogram"
	case PrometheusTypeSummary:
		return "summary"
	case PrometheusTypeUntyped:
		return "untyped"
	default:
		return "unknown"
	}
}

// NewPrometheusConverter creates a new PrometheusConverter with default settings.
func NewPrometheusConverter() *PrometheusConverter {
	return &PrometheusConverter{
		NormalizeMetricNames: true,
		AddTypeMetadata:      true,
	}
}

// Name returns the converter name.
func (c *PrometheusConverter) Name() string {
	return "prometheus_to_otlp"
}

// ConvertMetrics converts Prometheus metrics to OTLP format.
func (c *PrometheusConverter) ConvertMetrics(ctx context.Context, source interface{}) (pmetric.Metrics, error) {
	families, ok := source.([]*PrometheusMetricFamily)
	if !ok {
		return pmetric.Metrics{}, fmt.Errorf("expected []*PrometheusMetricFamily, got %T", source)
	}

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen.converter.prometheus")
	sm.Scope().SetVersion("1.0.0")

	for _, family := range families {
		if err := c.convertFamily(family, sm); err != nil {
			return pmetric.Metrics{}, fmt.Errorf("converting family %s: %w", family.Name, err)
		}
	}

	return metrics, nil
}

// convertFamily converts a single Prometheus metric family.
func (c *PrometheusConverter) convertFamily(family *PrometheusMetricFamily, sm pmetric.ScopeMetrics) error {
	if len(family.Metrics) == 0 {
		return nil
	}

	metricName := family.Name
	if c.NormalizeMetricNames {
		metricName = normalizePrometheusName(metricName)
	}

	switch family.Type {
	case PrometheusTypeCounter:
		return c.convertCounter(family, metricName, sm)
	case PrometheusTypeGauge:
		return c.convertGauge(family, metricName, sm)
	case PrometheusTypeHistogram:
		return c.convertHistogram(family, metricName, sm)
	case PrometheusTypeSummary:
		return c.convertSummary(family, metricName, sm)
	case PrometheusTypeUntyped, PrometheusTypeUnknown:
		// Default to gauge for untyped metrics.
		return c.convertGauge(family, metricName, sm)
	default:
		return fmt.Errorf("unknown metric type: %d", family.Type)
	}
}

// convertCounter converts a Prometheus counter to OTLP Sum.
func (c *PrometheusConverter) convertCounter(family *PrometheusMetricFamily, name string, sm pmetric.ScopeMetrics) error {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	m.SetDescription(family.Help)

	sum := m.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

	for _, pm := range family.Metrics {
		dp := sum.DataPoints().AppendEmpty()
		dp.SetDoubleValue(pm.Value)
		dp.SetTimestamp(pcommon.NewTimestampFromTime(pm.Timestamp))
		setLabelsAsAttributes(dp.Attributes(), pm.Labels)
	}

	return nil
}

// convertGauge converts a Prometheus gauge to OTLP Gauge.
func (c *PrometheusConverter) convertGauge(family *PrometheusMetricFamily, name string, sm pmetric.ScopeMetrics) error {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	m.SetDescription(family.Help)

	gauge := m.SetEmptyGauge()

	for _, pm := range family.Metrics {
		dp := gauge.DataPoints().AppendEmpty()
		dp.SetDoubleValue(pm.Value)
		dp.SetTimestamp(pcommon.NewTimestampFromTime(pm.Timestamp))
		setLabelsAsAttributes(dp.Attributes(), pm.Labels)
	}

	return nil
}

// convertHistogram converts a Prometheus histogram to OTLP ExponentialHistogram.
func (c *PrometheusConverter) convertHistogram(family *PrometheusMetricFamily, name string, sm pmetric.ScopeMetrics) error {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	m.SetDescription(family.Help)

	hist := m.SetEmptyHistogram()
	hist.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

	for _, pm := range family.Metrics {
		dp := hist.DataPoints().AppendEmpty()
		dp.SetTimestamp(pcommon.NewTimestampFromTime(pm.Timestamp))
		dp.SetCount(pm.Count)
		dp.SetSum(pm.Sum)
		setLabelsAsAttributes(dp.Attributes(), pm.Labels)

		// Convert buckets.
		if len(pm.Buckets) > 0 {
			// Sort buckets by upper bound.
			sortedBuckets := make([]HistogramBucket, len(pm.Buckets))
			copy(sortedBuckets, pm.Buckets)
			sort.Slice(sortedBuckets, func(i, j int) bool {
				return sortedBuckets[i].UpperBound < sortedBuckets[j].UpperBound
			})

			bounds := make([]float64, 0, len(sortedBuckets))
			counts := make([]uint64, 0, len(sortedBuckets))
			var prevCount uint64

			for _, bucket := range sortedBuckets {
				if !math.IsInf(bucket.UpperBound, 1) {
					bounds = append(bounds, bucket.UpperBound)
				}
				// Convert cumulative to bucket counts.
				bucketCount := bucket.CumulativeCount - prevCount
				counts = append(counts, bucketCount)
				prevCount = bucket.CumulativeCount
			}

			dp.ExplicitBounds().FromRaw(bounds)
			dp.BucketCounts().FromRaw(counts)
		}
	}

	return nil
}

// convertSummary converts a Prometheus summary to OTLP Summary.
func (c *PrometheusConverter) convertSummary(family *PrometheusMetricFamily, name string, sm pmetric.ScopeMetrics) error {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	m.SetDescription(family.Help)

	summary := m.SetEmptySummary()

	for _, pm := range family.Metrics {
		dp := summary.DataPoints().AppendEmpty()
		dp.SetTimestamp(pcommon.NewTimestampFromTime(pm.Timestamp))
		dp.SetCount(pm.Count)
		dp.SetSum(pm.Sum)
		setLabelsAsAttributes(dp.Attributes(), pm.Labels)

		// Convert quantiles.
		for _, q := range pm.Quantiles {
			qv := dp.QuantileValues().AppendEmpty()
			qv.SetQuantile(q.Quantile)
			qv.SetValue(q.Value)
		}
	}

	return nil
}

// normalizePrometheusName converts Prometheus naming conventions to OTLP.
// e.g., http_request_duration_seconds_total → http.request.duration
func normalizePrometheusName(name string) string {
	// Remove common suffixes.
	suffixes := []string{"_total", "_count", "_sum", "_bucket", "_seconds", "_bytes", "_info"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			name = strings.TrimSuffix(name, suffix)
			break
		}
	}
	// Replace underscores with dots.
	name = strings.ReplaceAll(name, "_", ".")
	return name
}

// setLabelsAsAttributes sets Prometheus labels as OTLP attributes.
func setLabelsAsAttributes(attrs pcommon.Map, labels map[string]string) {
	for k, v := range labels {
		// Skip internal Prometheus labels.
		if strings.HasPrefix(k, "__") {
			continue
		}
		attrs.PutStr(k, v)
	}
}

// ParsePrometheusText parses Prometheus text exposition format.
func ParsePrometheusText(text string) ([]*PrometheusMetricFamily, error) {
	var families []*PrometheusMetricFamily
	currentFamily := &PrometheusMetricFamily{}
	
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse HELP line.
		if strings.HasPrefix(line, "# HELP ") {
			parts := strings.SplitN(line[7:], " ", 2)
			if len(parts) >= 1 {
				if currentFamily.Name != "" && currentFamily.Name != parts[0] {
					if len(currentFamily.Metrics) > 0 {
						families = append(families, currentFamily)
					}
					currentFamily = &PrometheusMetricFamily{}
				}
				currentFamily.Name = parts[0]
				if len(parts) == 2 {
					currentFamily.Help = parts[1]
				}
			}
			continue
		}

		// Parse TYPE line.
		if strings.HasPrefix(line, "# TYPE ") {
			parts := strings.SplitN(line[7:], " ", 2)
			if len(parts) == 2 {
				if currentFamily.Name == "" {
					currentFamily.Name = parts[0]
				}
				currentFamily.Type = parseMetricType(parts[1])
			}
			continue
		}

		// Skip other comments.
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse metric line.
		metric, err := parseMetricLine(line)
		if err != nil {
			continue // Skip malformed lines.
		}

		// Extract base name from metric name.
		baseName := extractBaseName(metric.name)
		if currentFamily.Name == "" {
			currentFamily.Name = baseName
		}

		pm := PrometheusMetric{
			Labels:    metric.labels,
			Value:     metric.value,
			Timestamp: metric.timestamp,
		}
		currentFamily.Metrics = append(currentFamily.Metrics, pm)
	}

	if len(currentFamily.Metrics) > 0 {
		families = append(families, currentFamily)
	}

	return families, nil
}

type parsedMetricLine struct {
	name      string
	labels    map[string]string
	value     float64
	timestamp time.Time
}

func parseMetricLine(line string) (*parsedMetricLine, error) {
	result := &parsedMetricLine{
		labels:    make(map[string]string),
		timestamp: time.Now(),
	}

	// Find labels section.
	labelStart := strings.Index(line, "{")
	labelEnd := strings.Index(line, "}")

	var valueStr string
	if labelStart != -1 && labelEnd != -1 {
		result.name = line[:labelStart]
		labelsStr := line[labelStart+1 : labelEnd]
		valueStr = strings.TrimSpace(line[labelEnd+1:])

		// Parse labels.
		labelPairs := splitLabels(labelsStr)
		for _, pair := range labelPairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.Trim(strings.TrimSpace(kv[1]), "\"")
				result.labels[key] = value
			}
		}
	} else {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid metric line: %s", line)
		}
		result.name = parts[0]
		valueStr = parts[1]
	}

	// Parse value.
	parts := strings.Fields(valueStr)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no value found: %s", line)
	}

	value, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return nil, fmt.Errorf("invalid value: %s", parts[0])
	}
	result.value = value

	// Parse optional timestamp.
	if len(parts) > 1 {
		ts, err := strconv.ParseInt(parts[1], 10, 64)
		if err == nil {
			result.timestamp = time.UnixMilli(ts)
		}
	}

	return result, nil
}

func splitLabels(s string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false
	escaped := false

	for _, r := range s {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			current.WriteRune(r)
			continue
		}
		if r == '"' {
			inQuotes = !inQuotes
			current.WriteRune(r)
			continue
		}
		if r == ',' && !inQuotes {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}

func parseMetricType(s string) PrometheusMetricType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "counter":
		return PrometheusTypeCounter
	case "gauge":
		return PrometheusTypeGauge
	case "histogram":
		return PrometheusTypeHistogram
	case "summary":
		return PrometheusTypeSummary
	case "untyped":
		return PrometheusTypeUntyped
	default:
		return PrometheusTypeUnknown
	}
}

var histogramSuffixRe = regexp.MustCompile(`_(bucket|count|sum)$`)
var summarySuffixRe = regexp.MustCompile(`_(count|sum)$`)

func extractBaseName(name string) string {
	name = histogramSuffixRe.ReplaceAllString(name, "")
	name = summarySuffixRe.ReplaceAllString(name, "")
	return name
}
