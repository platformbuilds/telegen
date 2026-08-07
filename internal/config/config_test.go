package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
)

func TestLoad_PointerTogglesDoNotBreakEnvParse(t *testing.T) {
	t.Parallel()

	yamlConfig := `
vmware:
  enabled: true
  collectors:
    datacenter: true
    host: false

pipelines:
  jfr:
    enabled: true
    recursive: true
`

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if !cfg.VMware.Collectors.Enabled("datacenter") {
		t.Fatalf("datacenter collector should be enabled")
	}
	if cfg.VMware.Collectors.Enabled("host") {
		t.Fatalf("host collector should be disabled")
	}
	if !cfg.VMware.Collectors.Enabled("cluster") {
		t.Fatalf("cluster collector should default to enabled when unset")
	}
	if cfg.Pipelines.JFR.Recursive == nil {
		t.Fatalf("pipelines.jfr.recursive pointer should be non-nil")
	}
	if !*cfg.Pipelines.JFR.Recursive {
		t.Fatalf("pipelines.jfr.recursive should be true")
	}
}

func TestLoad_DefaultInternalMetricsEnabledOnSelfTelemetryPort(t *testing.T) {
	t.Parallel()

	yamlConfig := `
agent:
  service_name: test
`
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.EBPF.InternalMetrics.Exporter != imetrics.InternalMetricsExporterPrometheus {
		t.Fatalf("expected prometheus internal metrics exporter, got %q", cfg.EBPF.InternalMetrics.Exporter)
	}
	if cfg.EBPF.InternalMetrics.Prometheus.Port != 19090 {
		t.Fatalf("expected internal metrics port 19090, got %d", cfg.EBPF.InternalMetrics.Prometheus.Port)
	}
}

func TestLoad_InternalMetricsPortFollowsSelfTelemetryListen(t *testing.T) {
	t.Parallel()

	yamlConfig := `
selfTelemetry:
  listen: ":29090"
ebpf:
  internal_metrics:
    exporter: prometheus
`
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.EBPF.InternalMetrics.Prometheus.Port != 29090 {
		t.Fatalf("expected internal metrics port 29090, got %d", cfg.EBPF.InternalMetrics.Prometheus.Port)
	}
}
