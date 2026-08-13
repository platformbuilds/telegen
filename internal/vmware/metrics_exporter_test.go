// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/mirastacklabs-ai/telegen/internal/timeutil"
	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

// captureExporter is a fake sdkmetric.Exporter that records the last batch.
type captureExporter struct {
	last *metricdata.ResourceMetrics
}

func (e *captureExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (e *captureExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.AggregationDefault{}
}

func (e *captureExporter) Export(_ context.Context, rm *metricdata.ResourceMetrics) error {
	e.last = rm
	return nil
}

func (e *captureExporter) ForceFlush(context.Context) error { return nil }
func (e *captureExporter) Shutdown(context.Context) error   { return nil }

// TestExportMetricsGroupsByName verifies each unique metric name becomes its own
// metricdata.Metrics entry (the key correctness improvement over snmp's bucketing).
func TestExportMetricsGroupsByName(t *testing.T) {
	now := time.Now()
	exp := &captureExporter{}
	metrics := []vmwaredef.Metric{
		{Name: "vmware_host_info", Type: vmwaredef.MetricTypeGauge, Value: 1, Labels: map[string]string{"host": "esx-1", "vcenter": "vc"}, Timestamp: now},
		{Name: "vmware_host_info", Type: vmwaredef.MetricTypeGauge, Value: 1, Labels: map[string]string{"host": "esx-2", "vcenter": "vc"}, Timestamp: now},
		{Name: "vmware_host_cpu_usagemhz_average", Type: vmwaredef.MetricTypeGauge, Value: 512, Labels: map[string]string{"host": "esx-1", "vcenter": "vc"}, Timestamp: now},
	}

	if err := exportMetrics(context.Background(), exp, "vc", map[string]string{"env": "test"}, metrics, 0, nil); err != nil {
		t.Fatalf("exportMetrics: %v", err)
	}
	if exp.last == nil {
		t.Fatal("exporter received no batch")
	}
	if len(exp.last.ScopeMetrics) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(exp.last.ScopeMetrics))
	}

	sm := exp.last.ScopeMetrics[0]
	if sm.Scope.Name != scopeName {
		t.Errorf("scope name = %q, want %q", sm.Scope.Name, scopeName)
	}

	byName := map[string]metricdata.Metrics{}
	for _, m := range sm.Metrics {
		byName[m.Name] = m
	}

	// The batch carries the domain metrics plus the timestamp-provenance
	// signals, which deliberately ride the same OTLP export so a bad clock
	// reaches VictoriaMetrics with the data it describes.
	domain := 0
	for name := range byName {
		if name != timeutil.MetricClockSkewSeconds && name != timeutil.MetricTimestampFallbackTotal {
			domain++
		}
	}
	if domain != 2 {
		t.Fatalf("expected 2 distinct domain metric names, got %d (all: %v)", domain, sm.Metrics)
	}

	hostInfo, ok := byName["vmware_host_info"]
	if !ok {
		t.Fatal("vmware_host_info missing")
	}
	g, ok := hostInfo.Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("vmware_host_info is not a Gauge, got %T", hostInfo.Data)
	}
	if len(g.DataPoints) != 2 {
		t.Errorf("expected 2 datapoints for vmware_host_info, got %d", len(g.DataPoints))
	}
	// extra_labels must be applied to datapoints.
	if _, present := g.DataPoints[0].Attributes.Value("env"); !present {
		t.Error("extra label 'env' not applied to datapoint attributes")
	}

	// Every sample carried a source timestamp, so skew is reported and there is
	// nothing to count as a fallback.
	if _, ok := byName[timeutil.MetricClockSkewSeconds]; !ok {
		t.Error("expected the clock-skew gauge to ride along with the batch")
	}
	if _, ok := byName[timeutil.MetricTimestampFallbackTotal]; ok {
		t.Error("no sample lacked a timestamp, so no fallback counter should be emitted")
	}
}

// TestExportMetricsReportsClockSkew pins the sign and magnitude of the skew
// gauge at the export seam. A source timestamp an hour ahead of the collector
// means the collector clock is slow, which is the shape of the incident this
// signal exists to catch.
func TestExportMetricsReportsClockSkew(t *testing.T) {
	exp := &captureExporter{}
	sourceAhead := time.Now().UTC().Add(time.Hour)
	metrics := []vmwaredef.Metric{
		{Name: "vmware_host_info", Type: vmwaredef.MetricTypeGauge, Value: 1, Labels: map[string]string{"host": "esx-1"}, Timestamp: sourceAhead},
	}

	if err := exportMetrics(context.Background(), exp, "vc", nil, metrics, 0, nil); err != nil {
		t.Fatalf("exportMetrics: %v", err)
	}

	var skew *metricdata.Gauge[float64]
	for _, m := range exp.last.ScopeMetrics[0].Metrics {
		if m.Name != timeutil.MetricClockSkewSeconds {
			continue
		}
		g, ok := m.Data.(metricdata.Gauge[float64])
		if !ok {
			t.Fatalf("skew metric is not a float64 gauge, got %T", m.Data)
		}
		skew = &g
	}
	if skew == nil {
		t.Fatal("clock-skew gauge missing from the batch")
	}
	// Roughly -3600; allow slack for the clock read inside the exporter.
	if v := skew.DataPoints[0].Value; v > -3590 || v < -3610 {
		t.Errorf("expected skew near -3600s (collector lags source), got %v", v)
	}
	if c, present := skew.DataPoints[0].Attributes.Value("collector"); !present || c.AsString() != "vmware" {
		t.Errorf("expected collector=vmware attribute, got %v (present=%v)", c.AsString(), present)
	}
}

// TestExportMetricsCountsTimestampFallbacks proves a metric that reaches export
// without a source timestamp is counted rather than silently accepted.
func TestExportMetricsCountsTimestampFallbacks(t *testing.T) {
	exp := &captureExporter{}
	metrics := []vmwaredef.Metric{
		{Name: "vmware_host_info", Type: vmwaredef.MetricTypeGauge, Value: 1, Labels: map[string]string{"host": "esx-1"}},
		{Name: "vmware_host_info", Type: vmwaredef.MetricTypeGauge, Value: 1, Labels: map[string]string{"host": "esx-2"}},
	}

	if err := exportMetrics(context.Background(), exp, "vc", nil, metrics, 0, nil); err != nil {
		t.Fatalf("exportMetrics: %v", err)
	}

	var found bool
	for _, m := range exp.last.ScopeMetrics[0].Metrics {
		if m.Name != timeutil.MetricTimestampFallbackTotal {
			continue
		}
		found = true
		s, ok := m.Data.(metricdata.Sum[int64])
		if !ok {
			t.Fatalf("fallback metric is not an int64 sum, got %T", m.Data)
		}
		if s.DataPoints[0].Value != 2 {
			t.Errorf("expected 2 fallbacks, got %d", s.DataPoints[0].Value)
		}
	}
	if !found {
		t.Error("expected a timestamp-fallback counter when no sample carried a source time")
	}
}

// TestExportMetricsSetsObservedTimestamp proves collection lag stays measurable:
// the source instant is preserved on the data point while ObservedTimestamp
// records when the collector actually saw it.
func TestExportMetricsSetsObservedTimestamp(t *testing.T) {
	exp := &captureExporter{}
	source := time.Now().UTC().Add(-30 * time.Minute)
	metrics := []vmwaredef.Metric{
		{Name: "vmware_host_info", Type: vmwaredef.MetricTypeGauge, Value: 1, Labels: map[string]string{"host": "esx-1"}, Timestamp: source},
	}

	if err := exportMetrics(context.Background(), exp, "vc", nil, metrics, 0, nil); err != nil {
		t.Fatalf("exportMetrics: %v", err)
	}

	if metrics[0].ObservedTimestamp.IsZero() {
		t.Fatal("ObservedTimestamp was never populated, so collection lag is unmeasurable")
	}
	if !metrics[0].Timestamp.Equal(source) {
		t.Errorf("source timestamp must survive export, got %v want %v", metrics[0].Timestamp, source)
	}
	if !metrics[0].ObservedTimestamp.After(metrics[0].Timestamp) {
		t.Errorf("ObservedTimestamp %v should be after the source instant %v",
			metrics[0].ObservedTimestamp, metrics[0].Timestamp)
	}
}
