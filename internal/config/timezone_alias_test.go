package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadTestConfig(t *testing.T, yamlConfig string) *Config {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

func TestCanonicalizeIANATimezone(t *testing.T) {
	if got := canonicalizeIANATimezone("Asia/Calcutta"); got != "Asia/Kolkata" {
		t.Fatalf("legacy alias was not canonicalized: got %q, want %q", got, "Asia/Kolkata")
	}
	if got := canonicalizeIANATimezone("Asia/Kolkata"); got != "Asia/Kolkata" {
		t.Fatalf("canonical id should pass through: got %q", got)
	}
	if got := canonicalizeIANATimezone("UTC"); got != "UTC" {
		t.Fatalf("UTC should pass through: got %q", got)
	}
}

func TestValidateCanonicalizesSiteTimezone(t *testing.T) {
	cfg := loadTestConfig(t, "agent:\n  service_name: test\n")
	cfg.Site.Timezone = "Asia/Calcutta"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if cfg.Site.Timezone != "Asia/Kolkata" {
		t.Fatalf("expected canonical site timezone, got %q", cfg.Site.Timezone)
	}
}

func TestValidateRejectsInvalidSiteTimezoneUnchanged(t *testing.T) {
	cfg := loadTestConfig(t, "agent:\n  service_name: test\n")
	cfg.Site.Timezone = "Not/AZone"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected invalid site timezone to fail validation")
	}
	if !strings.Contains(err.Error(), `site.timezone "Not/AZone" is invalid IANA timezone`) {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if cfg.Site.Timezone != "Not/AZone" {
		t.Fatalf("invalid timezone value should be preserved, got %q", cfg.Site.Timezone)
	}
}
