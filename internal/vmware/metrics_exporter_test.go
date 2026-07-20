// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

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

	if err := exportMetrics(context.Background(), exp, "vc", map[string]string{"env": "test"}, metrics); err != nil {
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
	if len(sm.Metrics) != 2 {
		t.Fatalf("expected 2 distinct metric names, got %d", len(sm.Metrics))
	}

	byName := map[string]metricdata.Metrics{}
	for _, m := range sm.Metrics {
		byName[m.Name] = m
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
}
