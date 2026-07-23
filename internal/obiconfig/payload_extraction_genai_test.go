package config

import "testing"

func TestGenAIConfigEnabled(t *testing.T) {
	var cfg GenAIConfig
	if cfg.Enabled() {
		t.Fatalf("empty GenAI config should be disabled")
	}

	cfg.OpenAI.Enabled = true
	if !cfg.Enabled() {
		t.Fatalf("GenAI config should be enabled when any provider is enabled")
	}
}

func TestEnrichmentConfigValidateRequiresObfuscationPaths(t *testing.T) {
	cfg := EnrichmentConfig{
		Rules: []HTTPParsingRule{
			{
				Action: HTTPParsingActionObfuscate,
				Type:   HTTPParsingRuleTypeBody,
				Scope:  HTTPParsingScopeAll,
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for obfuscation rule without JSON paths")
	}
}
