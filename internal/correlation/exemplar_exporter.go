// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// ExemplarExporter exports exemplars to OTLP metrics.
type ExemplarExporter struct {
	store        *ExemplarStore
	log          *slog.Logger
	mu           sync.RWMutex
	metricScopes map[string]*MetricScope
}

// MetricScope holds scope information for metrics.
type MetricScope struct {
	Name    string
	Version string
	Schema  string
}

// NewExemplarExporter creates a new exemplar exporter.
func NewExemplarExporter(store *ExemplarStore, log *slog.Logger) *ExemplarExporter {
	if store == nil {
		store = NewExemplarStore(nil)
	}
	if log == nil {
		log = slog.Default()
	}

	return &ExemplarExporter{
		store:        store,
		log:          log.With("component", "exemplar_exporter"),
		metricScopes: make(map[string]*MetricScope),
	}
}

// RegisterMetricScope registers a scope for a metric.
func (e *ExemplarExporter) RegisterMetricScope(metricName string, scope *MetricScope) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.metricScopes[metricName] = scope
}

// Record records a measurement for a metric with trace context from context.
func (e *ExemplarExporter) Record(ctx context.Context, metricName string, value float64, attrs map[string]interface{}) {
	e.store.Record(ctx, metricName, value, attrs)
}

// RecordWithTraceContext records a measurement with explicit trace context.
func (e *ExemplarExporter) RecordWithTraceContext(metricName string, value float64, tc *TraceContext, attrs map[string]interface{}) {
	if tc == nil || !tc.TraceID.IsValid() {
		return
	}

	ctx := ContextWithTraceContext(context.Background(), tc)
	e.store.Record(ctx, metricName, value, attrs)
}

// CollectExemplarsForMetric collects exemplars for a specific metric.
func (e *ExemplarExporter) CollectExemplarsForMetric(metricName string) []metricdata.Exemplar[float64] {
	exemplars := e.store.Collect(metricName)
	return e.convertToOTLP(exemplars)
}

// CollectAllExemplars collects all exemplars grouped by metric.
func (e *ExemplarExporter) CollectAllExemplars() map[string][]metricdata.Exemplar[float64] {
	allExemplars := e.store.CollectAll()
	result := make(map[string][]metricdata.Exemplar[float64], len(allExemplars))

	for _, me := range allExemplars {
		result[me.MetricName] = e.convertToOTLP(me.Exemplars)
	}

	return result
}

// convertToOTLP converts internal exemplars to OTLP format.
func (e *ExemplarExporter) convertToOTLP(exemplars []*Exemplar) []metricdata.Exemplar[float64] {
	result := make([]metricdata.Exemplar[float64], 0, len(exemplars))

	for _, ex := range exemplars {
		if ex == nil || !ex.IsValid() {
			continue
		}

		otlpExemplar := metricdata.Exemplar[float64]{
			Value:   ex.Value,
			Time:    ex.Timestamp,
			TraceID: ex.TraceID[:],
			SpanID:  ex.SpanID[:],
		}

		// Convert filtered attributes
		if len(ex.FilteredAttributes) > 0 {
			attrs := make([]attribute.KeyValue, 0, len(ex.FilteredAttributes))
			for k, v := range ex.FilteredAttributes {
				attrs = append(attrs, convertToAttribute(k, v))
			}
			otlpExemplar.FilteredAttributes = attrs
		}

		result = append(result, otlpExemplar)
	}

	return result
}

// convertToAttribute converts an interface value to an OTEL attribute.
func convertToAttribute(key string, value interface{}) attribute.KeyValue {
	switch v := value.(type) {
	case string:
		return attribute.String(key, v)
	case int:
		return attribute.Int(key, v)
	case int64:
		return attribute.Int64(key, v)
	case float64:
		return attribute.Float64(key, v)
	case bool:
		return attribute.Bool(key, v)
	case []string:
		return attribute.StringSlice(key, v)
	case []int:
		return attribute.IntSlice(key, v)
	case []int64:
		return attribute.Int64Slice(key, v)
	case []float64:
		return attribute.Float64Slice(key, v)
	case []bool:
		return attribute.BoolSlice(key, v)
	default:
		return attribute.String(key, "")
	}
}

// ExemplarAggregator aggregates exemplars across multiple collection periods.
type ExemplarAggregator struct {
	exporter       *ExemplarExporter
	aggregated     map[string][]metricdata.Exemplar[float64]
	mu             sync.Mutex
	maxPerMetric   int
	retentionTime  time.Duration
	lastCollection time.Time
}

// NewExemplarAggregator creates a new exemplar aggregator.
func NewExemplarAggregator(exporter *ExemplarExporter, maxPerMetric int, retention time.Duration) *ExemplarAggregator {
	if maxPerMetric <= 0 {
		maxPerMetric = 10
	}
	if retention <= 0 {
		retention = time.Minute
	}

	return &ExemplarAggregator{
		exporter:       exporter,
		aggregated:     make(map[string][]metricdata.Exemplar[float64]),
		maxPerMetric:   maxPerMetric,
		retentionTime:  retention,
		lastCollection: time.Now(),
	}
}

// Aggregate collects and aggregates exemplars.
func (a *ExemplarAggregator) Aggregate() map[string][]metricdata.Exemplar[float64] {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	// Clear stale exemplars
	if now.Sub(a.lastCollection) > a.retentionTime {
		a.aggregated = make(map[string][]metricdata.Exemplar[float64])
	}
	a.lastCollection = now

	// Collect new exemplars
	newExemplars := a.exporter.CollectAllExemplars()

	// Merge with existing
	for metric, exemplars := range newExemplars {
		existing := a.aggregated[metric]
		combined := append(existing, exemplars...)

		// Keep only most recent
		if len(combined) > a.maxPerMetric {
			combined = combined[len(combined)-a.maxPerMetric:]
		}

		a.aggregated[metric] = combined
	}

	// Return copy
	result := make(map[string][]metricdata.Exemplar[float64], len(a.aggregated))
	for k, v := range a.aggregated {
		result[k] = v
	}

	return result
}

// ExemplarEnricher enriches OTLP metrics with exemplars.
type ExemplarEnricher struct {
	aggregator *ExemplarAggregator
}

// NewExemplarEnricher creates a new enricher.
func NewExemplarEnricher(aggregator *ExemplarAggregator) *ExemplarEnricher {
	return &ExemplarEnricher{
		aggregator: aggregator,
	}
}

// EnrichSum enriches a Sum metric with exemplars.
func (e *ExemplarEnricher) EnrichSum(sum *metricdata.Sum[float64], metricName string) {
	if e.aggregator == nil {
		return
	}

	exemplars := e.aggregator.Aggregate()
	if metricExemplars, ok := exemplars[metricName]; ok {
		for i := range sum.DataPoints {
			sum.DataPoints[i].Exemplars = metricExemplars
		}
	}
}

// EnrichHistogram enriches a Histogram metric with exemplars.
func (e *ExemplarEnricher) EnrichHistogram(hist *metricdata.Histogram[float64], metricName string) {
	if e.aggregator == nil {
		return
	}

	exemplars := e.aggregator.Aggregate()
	if metricExemplars, ok := exemplars[metricName]; ok {
		for i := range hist.DataPoints {
			hist.DataPoints[i].Exemplars = metricExemplars
		}
	}
}

// EnrichGauge enriches a Gauge metric with exemplars.
func (e *ExemplarEnricher) EnrichGauge(gauge *metricdata.Gauge[float64], metricName string) {
	if e.aggregator == nil {
		return
	}

	exemplars := e.aggregator.Aggregate()
	if metricExemplars, ok := exemplars[metricName]; ok {
		for i := range gauge.DataPoints {
			gauge.DataPoints[i].Exemplars = metricExemplars
		}
	}
}

// Global exemplar components
var (
	globalExemplarStore    *ExemplarStore
	globalExemplarExporter *ExemplarExporter
	globalExemplarInit     sync.Once
)

// GetGlobalExemplarStore returns the global exemplar store.
func GetGlobalExemplarStore() *ExemplarStore {
	globalExemplarInit.Do(func() {
		globalExemplarStore = NewExemplarStore(func() ExemplarReservoir {
			return NewSimpleExemplarReservoir(5)
		})
		globalExemplarExporter = NewExemplarExporter(globalExemplarStore, nil)
	})
	return globalExemplarStore
}

// GetGlobalExemplarExporter returns the global exemplar exporter.
func GetGlobalExemplarExporter() *ExemplarExporter {
	GetGlobalExemplarStore() // Ensure initialization
	return globalExemplarExporter
}

// RecordExemplar is a convenience function to record an exemplar globally.
func RecordExemplar(ctx context.Context, metricName string, value float64, attrs map[string]interface{}) {
	GetGlobalExemplarExporter().Record(ctx, metricName, value, attrs)
}
