package config

import (
	"os"
	"path/filepath"
	"testing"
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
