package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, yamlConfig string) (*Config, error) {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return Load(cfgPath)
}

func TestLoad_SignalMetadataDefaultsOn(t *testing.T) {
	t.Parallel()

	cfg, err := loadYAML(t, "agent:\n  service_name: test\n")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if !cfg.Exports.IncludeSignalMetadata {
		t.Fatal("exports.include_signal_metadata should default to true")
	}
	if !cfg.Exports.MetadataFields.EnableCategory {
		t.Fatal("metadata_fields.enable_category should default to true")
	}
	if cfg.Exports.MetadataFields.EnableDescription {
		t.Fatal("metadata_fields.enable_description should default to false")
	}
}

func TestLoad_SignalMetadataPartialOverrideKeepsOtherDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := loadYAML(t, `
agent:
  service_name: test
exports:
  include_signal_metadata: true
  metadata_fields:
    enable_description: true
    enable_bpf_component: false
`)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if !cfg.Exports.MetadataFields.EnableDescription {
		t.Fatal("enable_description override was dropped")
	}
	if cfg.Exports.MetadataFields.EnableBPFComponent {
		t.Fatal("enable_bpf_component override was dropped")
	}
	if !cfg.Exports.MetadataFields.EnableCategory {
		t.Fatal("unset enable_category should keep its default of true")
	}
}

func TestLoad_SignalMetadataCanBeDisabled(t *testing.T) {
	t.Parallel()

	cfg, err := loadYAML(t, `
agent:
  service_name: test
exports:
  include_signal_metadata: false
`)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Exports.IncludeSignalMetadata {
		t.Fatal("exports.include_signal_metadata: false was ignored")
	}
}

func TestLoad_OTLPCompressionNormalisation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		yaml     string
		wantGRPC string
		wantHTTP string
	}{
		{
			name:     "unset defaults to gzip",
			yaml:     "agent:\n  service_name: test\n",
			wantGRPC: CompressionGzip,
			wantHTTP: CompressionGzip,
		},
		{
			name: "legacy gzip false yields none",
			yaml: `
agent:
  service_name: test
exports:
  otlp:
    grpc:
      gzip: false
    http:
      gzip: false
`,
			wantGRPC: CompressionNone,
			wantHTTP: CompressionNone,
		},
		{
			name: "explicit compression wins over legacy gzip",
			yaml: `
agent:
  service_name: test
exports:
  otlp:
    grpc:
      gzip: true
      compression: "none"
    http:
      gzip: false
      compression: "gzip"
`,
			wantGRPC: CompressionNone,
			wantHTTP: CompressionGzip,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := loadYAML(t, tt.yaml)
			if err != nil {
				t.Fatalf("load config: %v", err)
			}
			if got := cfg.Exports.OTLP.GRPC.Compression; got != tt.wantGRPC {
				t.Fatalf("grpc compression = %q, want %q", got, tt.wantGRPC)
			}
			if got := cfg.Exports.OTLP.HTTP.Compression; got != tt.wantHTTP {
				t.Fatalf("http compression = %q, want %q", got, tt.wantHTTP)
			}
		})
	}
}

func TestLoad_UnsupportedOTLPCompressionRejected(t *testing.T) {
	t.Parallel()

	_, err := loadYAML(t, `
agent:
  service_name: test
exports:
  otlp:
    grpc:
      compression: "snappy"
`)
	if err == nil {
		t.Fatal("expected an unsupported OTLP codec to be rejected")
	}
	if !strings.Contains(err.Error(), "exports.otlp.grpc.compression") {
		t.Fatalf("unexpected error: %v", err)
	}
}
