// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"os"
	"testing"
)

func TestIsInCluster(t *testing.T) {
	// Save original env
	origHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	origPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	defer func() {
		_ = os.Setenv("KUBERNETES_SERVICE_HOST", origHost)
		_ = os.Setenv("KUBERNETES_SERVICE_PORT", origPort)
	}()

	// Test 1: Not in cluster (no env vars, no service account)
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")
	_ = os.Unsetenv("KUBERNETES_SERVICE_PORT")
	if IsInCluster() {
		// This might pass if running in actual K8s
		t.Log("IsInCluster() returned true - either running in K8s or service account exists")
	}

	// Test 2: In cluster via env var
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if !IsInCluster() {
		t.Error("IsInCluster() should return true when KUBERNETES_SERVICE_HOST is set")
	}
}

func TestDefaultAgentConfig(t *testing.T) {
	cfg := DefaultAgentConfig()

	// Check defaults
	if cfg.Enabled {
		t.Error("Enabled should be false by default (uses AutoDetect)")
	}
	if !cfg.AutoDetect {
		t.Error("AutoDetect should be true by default")
	}
	if cfg.ListenAddress != ":9443" {
		t.Errorf("ListenAddress = %s, want :9443", cfg.ListenAddress)
	}
	if cfg.MetricsPath != "/metrics" {
		t.Errorf("MetricsPath = %s, want /metrics", cfg.MetricsPath)
	}
	if !cfg.SeparateEndpoints {
		t.Error("SeparateEndpoints should be true by default")
	}
	// KubeState and Cadvisor should be enabled when used via kubemetrics
	if !cfg.KubeState.Enabled {
		t.Error("KubeState.Enabled should be true by default in kubemetrics context")
	}
	if !cfg.Cadvisor.Enabled {
		t.Error("Cadvisor.Enabled should be true by default in kubemetrics context")
	}
	if cfg.Streaming.Enabled {
		t.Error("Streaming.Enabled should be false by default")
	}
	if cfg.LogsStreaming.Enabled {
		t.Error("LogsStreaming.Enabled should be false by default")
	}
	if !cfg.SignalMetadata.Enabled {
		t.Error("SignalMetadata.Enabled should be true by default")
	}
}

func TestNewFromAgentConfig_NilConfig(t *testing.T) {
	_, err := NewFromAgentConfig(nil, nil)
	if err == nil {
		t.Error("NewFromAgentConfig should return error for nil config")
	}
}

func TestNewFromAgentConfig_NotInCluster(t *testing.T) {
	// Save original env
	origHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	defer func() { _ = os.Setenv("KUBERNETES_SERVICE_HOST", origHost) }()
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")

	cfg := &AgentConfig{
		Enabled:    false,
		AutoDetect: true, // Auto-detect but not in cluster
	}

	// Should return nil provider (not an error) when not in cluster
	provider, err := NewFromAgentConfig(cfg, nil)
	if err != nil {
		// If err is about not being in cluster, that's expected
		t.Logf("Got expected error for non-cluster environment: %v", err)
	}
	if provider != nil {
		t.Error("Provider should be nil when not in cluster with auto-detect")
		_ = provider.Stop(nil)
	}
}
