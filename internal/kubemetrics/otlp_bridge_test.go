// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"log/slog"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

func TestSanitizeOpenMetricsTypes(t *testing.T) {
	input := []byte(`# HELP kube_pod_info Information about pod.
# TYPE kube_pod_info info
kube_pod_info{namespace="default",pod="demo"} 1
# HELP kube_node_status_condition The condition status.
# TYPE kube_node_status_condition stateset
kube_node_status_condition{node="n1",condition="Ready",status="true"} 1
# HELP kube_pod_status_phase The pod phase.
# TYPE kube_pod_status_phase gauge
kube_pod_status_phase{namespace="default",pod="demo",phase="Running"} 1
`)

	output := string(sanitizeOpenMetricsTypes(input))
	if !strings.Contains(output, "# TYPE kube_pod_info gauge") {
		t.Fatalf("expected info type to be rewritten to gauge, output:\n%s", output)
	}
	if !strings.Contains(output, "# TYPE kube_node_status_condition gauge") {
		t.Fatalf("expected stateset type to be rewritten to gauge, output:\n%s", output)
	}
	if !strings.Contains(output, "# TYPE kube_pod_status_phase gauge") {
		t.Fatalf("expected existing gauge type to remain unchanged, output:\n%s", output)
	}
}

func TestOTLPBridgeConvertTextPreservesNamesAndLabels(t *testing.T) {
	exposition := []byte(`# HELP kube_pod_info Information about pod.
# TYPE kube_pod_info info
kube_pod_info{namespace="default",pod="demo-pod",uid="u-1"} 1
# HELP kube_pod_status_phase Pod phase.
# TYPE kube_pod_status_phase gauge
kube_pod_status_phase{namespace="default",pod="demo-pod",phase="Running"} 1
# HELP kube_deployment_status_replicas Number of replicas.
# TYPE kube_deployment_status_replicas counter
kube_deployment_status_replicas{namespace="default",deployment="demo-deploy"} 3
# HELP kube_node_status_condition Condition status.
# TYPE kube_node_status_condition stateset
kube_node_status_condition{node="n1",condition="Ready",status="true"} 1
`)

	bridge := NewOTLPBridge(nil, nil, slog.Default(), sigdef.DefaultMetadataFieldsConfig(), false)
	metrics, err := bridge.ConvertText(exposition)
	if err != nil {
		t.Fatalf("ConvertText failed: %v", err)
	}

	if len(metrics) != 4 {
		t.Fatalf("expected 4 metric families, got %d", len(metrics))
	}

	byName := map[string]metricdata.Metrics{}
	for _, m := range metrics {
		byName[m.Name] = m
	}

	expectedNames := []string{
		"kube_pod_info",
		"kube_pod_status_phase",
		"kube_deployment_status_replicas",
		"kube_node_status_condition",
	}
	for _, name := range expectedNames {
		if _, ok := byName[name]; !ok {
			t.Fatalf("missing expected metric name %q", name)
		}
	}

	assertGaugeWithAttribute(t, byName["kube_pod_info"], "namespace", "default")
	assertGaugeWithAttribute(t, byName["kube_pod_info"], "pod", "demo-pod")
	assertGaugeWithAttribute(t, byName["kube_node_status_condition"], "condition", "Ready")
	assertGaugeWithAttribute(t, byName["kube_node_status_condition"], "status", "true")
}

func TestSanitizePrometheusTextDedupesHelpType(t *testing.T) {
	input := []byte(`# HELP kube_pod_info Information about pod.
# TYPE kube_pod_info info
kube_pod_info{namespace="default",pod="a"} 1
# HELP kube_pod_info Information about pod.
# TYPE kube_pod_info info
kube_pod_info{namespace="default",pod="b"} 1
`)

	output := string(sanitizePrometheusText(input))
	if strings.Count(output, "# HELP kube_pod_info") != 1 {
		t.Fatalf("expected one HELP line after dedupe, got output:\n%s", output)
	}
	if strings.Count(output, "# TYPE kube_pod_info") != 1 {
		t.Fatalf("expected one TYPE line after dedupe, got output:\n%s", output)
	}
	if !strings.Contains(output, "# TYPE kube_pod_info gauge") {
		t.Fatalf("expected TYPE rewrite info->gauge to be preserved, got output:\n%s", output)
	}
}

func TestOTLPBridgeConvertTextHandlesDuplicateMetadataLines(t *testing.T) {
	exposition := []byte(`# HELP kube_pod_info Information about pod.
# TYPE kube_pod_info info
kube_pod_info{namespace="default",pod="demo-a"} 1
# HELP kube_pod_info Information about pod.
# TYPE kube_pod_info info
kube_pod_info{namespace="default",pod="demo-b"} 1
`)

	bridge := NewOTLPBridge(nil, nil, slog.Default(), sigdef.DefaultMetadataFieldsConfig(), false)
	metrics, err := bridge.ConvertText(exposition)
	if err != nil {
		t.Fatalf("ConvertText failed: %v", err)
	}

	if len(metrics) != 1 {
		t.Fatalf("expected exactly one metric family, got %d", len(metrics))
	}

	metric := metrics[0]
	if metric.Name != "kube_pod_info" {
		t.Fatalf("expected kube_pod_info metric, got %q", metric.Name)
	}

	gauge, ok := metric.Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("expected gauge data type, got %T", metric.Data)
	}
	if len(gauge.DataPoints) != 2 {
		t.Fatalf("expected two data points for duplicate metadata input, got %d", len(gauge.DataPoints))
	}
}

func assertGaugeWithAttribute(t *testing.T, metric metricdata.Metrics, key, expected string) {
	t.Helper()

	gauge, ok := metric.Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("expected metric %q to be gauge, got %T", metric.Name, metric.Data)
	}
	if len(gauge.DataPoints) == 0 {
		t.Fatalf("expected metric %q to contain datapoints", metric.Name)
	}

	value, ok := gauge.DataPoints[0].Attributes.Value(attribute.Key(key))
	if !ok {
		t.Fatalf("expected attribute %q on metric %q", key, metric.Name)
	}
	if value.AsString() != expected {
		t.Fatalf("unexpected value for %q on metric %q: got %q want %q", key, metric.Name, value.AsString(), expected)
	}
}

func TestOTLPBridgeConvertTextKubeNodeInfoHasEmptyUnit(t *testing.T) {
	exposition := []byte(`# HELP kube_node_info Information about a cluster node.
# TYPE kube_node_info gauge
kube_node_info{node="n1"} 1
`)

	bridge := NewOTLPBridge(nil, nil, slog.Default(), sigdef.DefaultMetadataFieldsConfig(), false)
	metrics, err := bridge.ConvertText(exposition)
	if err != nil {
		t.Fatalf("ConvertText failed: %v", err)
	}
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric family, got %d", len(metrics))
	}
	if metrics[0].Name != "kube_node_info" {
		t.Fatalf("expected metric name kube_node_info, got %q", metrics[0].Name)
	}
	if metrics[0].Unit != "" {
		t.Fatalf("expected empty unit for kube_node_info, got %q", metrics[0].Unit)
	}
}

func TestOTLPBridgeConvertTextLeavesAllUnitsEmpty(t *testing.T) {
	exposition := []byte(`# HELP container_memory_usage_bytes container bytes.
# TYPE container_memory_usage_bytes gauge
container_memory_usage_bytes{pod="p1"} 1
# HELP container_cpu_usage_seconds_total container cpu.
# TYPE container_cpu_usage_seconds_total counter
container_cpu_usage_seconds_total{pod="p1"} 2
# HELP node_cpu_ratio node ratio.
# TYPE node_cpu_ratio gauge
node_cpu_ratio{node="n1"} 0.5
# HELP app_error_percent error percent.
# TYPE app_error_percent gauge
app_error_percent{service="svc"} 10
`)

	bridge := NewOTLPBridge(nil, nil, slog.Default(), sigdef.DefaultMetadataFieldsConfig(), false)
	metrics, err := bridge.ConvertText(exposition)
	if err != nil {
		t.Fatalf("ConvertText failed: %v", err)
	}
	if len(metrics) != 4 {
		t.Fatalf("expected 4 metric families, got %d", len(metrics))
	}
	for _, metric := range metrics {
		if metric.Unit != "" {
			t.Fatalf("expected empty unit for %q, got %q", metric.Name, metric.Unit)
		}
	}
}
