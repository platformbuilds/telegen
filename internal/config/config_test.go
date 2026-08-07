package config

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLoad_DefaultInternalMetricsSharesSelfTelemetryEndpoint(t *testing.T) {
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
	if cfg.EBPF.InternalMetrics.Prometheus.Port != 0 {
		t.Fatalf("expected internal metrics port 0 for shared endpoint, got %d", cfg.EBPF.InternalMetrics.Prometheus.Port)
	}
	if cfg.EBPF.InternalMetrics.Prometheus.Path != "/metrics" {
		t.Fatalf("expected internal metrics path /metrics, got %q", cfg.EBPF.InternalMetrics.Prometheus.Path)
	}
}

func TestLoad_InternalMetricsExplicitPortIsPreserved(t *testing.T) {
	t.Parallel()

	yamlConfig := `
selfTelemetry:
  listen: ":29090"
ebpf:
  internal_metrics:
    exporter: prometheus
    prometheus:
      port: 29091
`
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.EBPF.InternalMetrics.Prometheus.Port != 29091 {
		t.Fatalf("expected internal metrics port 29091, got %d", cfg.EBPF.InternalMetrics.Prometheus.Port)
	}
}

func TestLoad_InternalMetricsPortCollisionRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		yamlConfig     string
		expectedReason string
	}{
		{
			name: "collides with self telemetry listen",
			yamlConfig: `
selfTelemetry:
  listen: ":19090"
ebpf:
  internal_metrics:
    exporter: prometheus
    prometheus:
      port: 19090
`,
			expectedReason: "conflicts with selfTelemetry.listen",
		},
		{
			name: "collides with health listen",
			yamlConfig: `
selfTelemetry:
  health_listen: ":8080"
ebpf:
  internal_metrics:
    exporter: prometheus
    prometheus:
      port: 8080
`,
			expectedReason: "conflicts with selfTelemetry.health_listen",
		},
		{
			name: "collides with pprof port",
			yamlConfig: `
selfTelemetry:
  pprof_enabled: true
  pprof_port: 6060
ebpf:
  internal_metrics:
    exporter: prometheus
    prometheus:
      port: 6060
`,
			expectedReason: "conflicts with selfTelemetry.pprof_port",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfgPath := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(cfgPath, []byte(tc.yamlConfig), 0o600); err != nil {
				t.Fatalf("write temp config: %v", err)
			}

			_, err := Load(cfgPath)
			if err == nil {
				t.Fatalf("expected load error for %s", tc.expectedReason)
			}
			if !strings.Contains(err.Error(), tc.expectedReason) {
				t.Fatalf("expected error to contain %q, got %v", tc.expectedReason, err)
			}
		})
	}
}

func TestLoad_DefaultInstanceLockPath(t *testing.T) {
	t.Parallel()

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("agent:\n  service_name: test\n"), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Agent.InstanceLockPath != "/var/run/telegen.pid" {
		t.Fatalf("expected default instance lock path /var/run/telegen.pid, got %q", cfg.Agent.InstanceLockPath)
	}
}

func TestLoad_InstanceLockPathOverride(t *testing.T) {
	t.Parallel()

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	yamlConfig := `
agent:
  service_name: test
  instance_lock_path: /var/lib/telegen/telegen.pid
`
	if err := os.WriteFile(cfgPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Agent.InstanceLockPath != "/var/lib/telegen/telegen.pid" {
		t.Fatalf("expected explicit instance lock path to be preserved, got %q", cfg.Agent.InstanceLockPath)
	}
}
