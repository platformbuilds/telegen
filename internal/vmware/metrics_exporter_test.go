// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"errors"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/mirastacklabs-ai/telegen/internal/timeutil"
	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

type captureExporter struct {
	batches []*metricdata.ResourceMetrics
	// failOn is a 1-based export call index set to fail.
	failOn map[int]error
	calls  int
}

func (e *captureExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (e *captureExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.AggregationDefault{}
}

func (e *captureExporter) Export(_ context.Context, rm *metricdata.ResourceMetrics) error {
	e.calls++
	e.batches = append(e.batches, rm)
	if err, ok := e.failOn[e.calls]; ok {
		return err
	}
	return nil
}

func (e *captureExporter) ForceFlush(context.Context) error { return nil }
func (e *captureExporter) Shutdown(context.Context) error   { return nil }

func TestExportMetricsGroupsByName(t *testing.T) {
	now := time.Now().UTC()
	exp := &captureExporter{}
	metrics := []vmwaredef.Metric{
		{Name: "vmware_host_info", Type: vmwaredef.MetricTypeGauge, Value: 1, Labels: map[string]string{"host": "esx-1", "vcenter": "vc"}, Timestamp: now, TimestampSource: vmwaredef.TimestampFromSource},
		{Name: "vmware_host_info", Type: vmwaredef.MetricTypeGauge, Value: 1, Labels: map[string]string{"host": "esx-2", "vcenter": "vc"}, Timestamp: now, TimestampSource: vmwaredef.TimestampFromSource},
		{Name: "vmware_host_cpu_usagemhz_average", Type: vmwaredef.MetricTypeGauge, Value: 512, Labels: map[string]string{"host": "esx-1", "vcenter": "vc"}, Timestamp: now, TimestampSource: vmwaredef.TimestampFromSource},
	}

	if err := exportMetrics(context.Background(), exp, "vc", map[string]string{"env": "test"}, metrics, 0, nil); err != nil {
		t.Fatalf("exportMetrics: %v", err)
	}
	if len(exp.batches) != 1 {
		t.Fatalf("expected one export batch, got %d", len(exp.batches))
	}
	last := exp.batches[len(exp.batches)-1]
	if last == nil {
		t.Fatal("exporter received no batch")
	}
	if len(last.ScopeMetrics) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(last.ScopeMetrics))
	}

	sm := last.ScopeMetrics[0]
	if sm.Scope.Name != scopeName {
		t.Errorf("scope name = %q, want %q", sm.Scope.Name, scopeName)
	}

	byName := map[string]metricdata.Metrics{}
	for _, m := range sm.Metrics {
		byName[m.Name] = m
	}

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

	if _, ok := byName[timeutil.MetricClockSkewSeconds]; !ok {
		t.Error("expected the clock-skew gauge to ride along with the batch")
	}
	if _, ok := byName[timeutil.MetricTimestampFallbackTotal]; ok {
		t.Error("no sample lacked a timestamp, so no fallback counter should be emitted")
	}
}

func TestExportMetricsReportsClockSkewFromSourceOnly(t *testing.T) {
	exp := &captureExporter{}
	sourceAhead := time.Now().UTC().Add(time.Hour)
	metrics := []vmwaredef.Metric{
		{
			Name:            "vmware_host_cpu_usagemhz_average",
			Type:            vmwaredef.MetricTypeGauge,
			Value:           1,
			Labels:          map[string]string{"host": "esx-1"},
			Timestamp:       sourceAhead,
			TimestampSource: vmwaredef.TimestampFromSource,
		},
	}
	for i := 0; i < 50; i++ {
		metrics = append(metrics, vmwaredef.Metric{
			Name:            "vmware_host_info",
			Type:            vmwaredef.MetricTypeGauge,
			Value:           1,
			Labels:          map[string]string{"host": "esx"},
			Timestamp:       time.Now().UTC(),
			TimestampSource: vmwaredef.TimestampFromCycleInstant,
		})
	}

	if err := exportMetrics(context.Background(), exp, "vc", nil, metrics, 0, nil); err != nil {
		t.Fatalf("exportMetrics: %v", err)
	}

	var skew *metricdata.Gauge[float64]
	last := exp.batches[len(exp.batches)-1]
	for _, m := range last.ScopeMetrics[0].Metrics {
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

func TestExportMetricsCountsTimestampFallbacks(t *testing.T) {
	exp := &captureExporter{}
	metrics := []vmwaredef.Metric{
		{
			Name:            "vmware_host_info",
			Type:            vmwaredef.MetricTypeGauge,
			Value:           1,
			Labels:          map[string]string{"host": "esx-1"},
			TimestampSource: vmwaredef.TimestampFromFallback,
		},
		{
			Name:            "vmware_host_info",
			Type:            vmwaredef.MetricTypeGauge,
			Value:           1,
			Labels:          map[string]string{"host": "esx-2"},
			TimestampSource: vmwaredef.TimestampFromFallback,
		},
	}

	if err := exportMetrics(context.Background(), exp, "vc", nil, metrics, 0, nil); err != nil {
		t.Fatalf("exportMetrics: %v", err)
	}

	var found bool
	last := exp.batches[len(exp.batches)-1]
	for _, m := range last.ScopeMetrics[0].Metrics {
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

func TestExportMetricsChunking(t *testing.T) {
	exp := &captureExporter{}
	metrics := make([]vmwaredef.Metric, 0, maxDataPointsPerBatch+501)
	now := time.Now().UTC()
	for i := 0; i < maxDataPointsPerBatch+500; i++ {
		metrics = append(metrics, vmwaredef.Metric{
			Name:            "vmware_vm_cpu_usagemhz_average",
			Type:            vmwaredef.MetricTypeGauge,
			Value:           float64(i),
			Labels:          map[string]string{"vm": "vm"},
			Timestamp:       now,
			TimestampSource: vmwaredef.TimestampFromSource,
		})
	}

	if err := exportMetrics(context.Background(), exp, "vc", nil, metrics, 0, nil); err != nil {
		t.Fatalf("exportMetrics: %v", err)
	}
	if len(exp.batches) < 2 {
		t.Fatalf("expected chunked export into multiple batches, got %d", len(exp.batches))
	}

	total := 0
	provenanceCount := 0
	for i, batch := range exp.batches {
		if len(batch.ScopeMetrics) != 1 {
			t.Fatalf("batch %d has %d scope metrics, want 1", i, len(batch.ScopeMetrics))
		}
		for _, m := range batch.ScopeMetrics[0].Metrics {
			total += dataPointCount(m)
			if m.Name == timeutil.MetricClockSkewSeconds || m.Name == timeutil.MetricTimestampFallbackTotal {
				provenanceCount++
			}
		}
	}
	if total < len(metrics) {
		t.Fatalf("expected at least %d data points across chunks, got %d", len(metrics), total)
	}
	if provenanceCount != 1 {
		t.Fatalf("expected one provenance metric set across chunks, got %d", provenanceCount)
	}
}

func TestExportMetricsContinuesWhenChunkFails(t *testing.T) {
	exp := &captureExporter{
		failOn: map[int]error{
			1: errors.New("first chunk failed"),
		},
	}
	metrics := make([]vmwaredef.Metric, 0, maxDataPointsPerBatch+50)
	now := time.Now().UTC()
	for i := 0; i < maxDataPointsPerBatch+20; i++ {
		metrics = append(metrics, vmwaredef.Metric{
			Name:            "vmware_host_cpu_usagemhz_average",
			Type:            vmwaredef.MetricTypeGauge,
			Value:           float64(i),
			Labels:          map[string]string{"host": "esx"},
			Timestamp:       now,
			TimestampSource: vmwaredef.TimestampFromSource,
		})
	}
	err := exportMetrics(context.Background(), exp, "vc", nil, metrics, 0, nil)
	if err == nil {
		t.Fatal("expected export error when one chunk fails")
	}
	if len(exp.batches) < 2 {
		t.Fatalf("expected subsequent chunks to still be exported, got %d batches", len(exp.batches))
	}
}
