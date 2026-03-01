// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"k8s.io/client-go/rest"

	"github.com/mirastacklabs-ai/telegen/internal/cadvisor"
	"github.com/mirastacklabs-ai/telegen/internal/kubestate"
	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// AgentConfig represents the kube_metrics section from telegen config.
// This mirrors config.KubeMetricsConfig but avoids import cycles.
type AgentConfig struct {
	// Enabled controls whether Kubernetes metrics collection is active
	Enabled bool

	// AutoDetect enables automatic Kubernetes environment detection
	AutoDetect bool

	// ListenAddress is the address to listen on for metrics
	ListenAddress string

	// MetricsPath is the path for the metrics endpoint
	MetricsPath string

	// SeparateEndpoints exposes kubestate and cadvisor on separate paths
	SeparateEndpoints bool

	// KubeState configuration
	KubeState kubestate.Config

	// Cadvisor configuration
	Cadvisor cadvisor.Config

	// Streaming configuration
	Streaming StreamingAgentConfig

	// LogsStreaming configuration
	LogsStreaming LogsStreamingAgentConfig

	// SignalMetadata configuration
	SignalMetadata SignalMetadataAgentConfig
}

// StreamingAgentConfig mirrors config.StreamingConfig
type StreamingAgentConfig struct {
	Enabled      bool
	Interval     time.Duration
	BatchSize    int
	FlushTimeout time.Duration
	UseOTLP      bool
}

// LogsStreamingAgentConfig mirrors config.LogsStreamingConfig
type LogsStreamingAgentConfig struct {
	Enabled       bool
	BufferSize    int
	FlushInterval time.Duration
	EventTypes    []string
	Namespaces    []string
}

// SignalMetadataAgentConfig mirrors config.SignalMetadataConfig
type SignalMetadataAgentConfig struct {
	Enabled bool
	Fields  sigdef.MetadataFieldsConfig
}

// IsInCluster returns true if we're running inside a Kubernetes cluster.
// This checks for the presence of in-cluster configuration (service account token, etc.)
func IsInCluster() bool {
	// Check for standard Kubernetes service account paths
	// These are mounted automatically when running in a pod
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	if _, err := os.Stat(tokenPath); err == nil {
		if _, err := os.Stat(caPath); err == nil {
			// Also verify we can create an in-cluster config
			if _, err := rest.InClusterConfig(); err == nil {
				return true
			}
		}
	}

	// Alternative: check for KUBERNETES_SERVICE_HOST environment variable
	// This is always set when running in a Kubernetes pod
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	return false
}

// NewFromAgentConfig creates a Provider from agent configuration.
// This is the main factory function used by the telegen agent.
// It handles auto-detection and config conversion.
func NewFromAgentConfig(agentCfg *AgentConfig, logger *slog.Logger) (*Provider, error) {
	if agentCfg == nil {
		return nil, fmt.Errorf("agentCfg is nil")
	}

	// Check if we should enable based on auto-detection
	inCluster := IsInCluster()
	shouldEnable := agentCfg.Enabled || (agentCfg.AutoDetect && inCluster)

	if !shouldEnable {
		return nil, nil // Return nil provider when not enabled (not an error)
	}

	if !inCluster && agentCfg.KubeState.Kubeconfig == "" {
		// Not in cluster and no kubeconfig specified - can't proceed
		return nil, fmt.Errorf("not running in Kubernetes cluster and no kubeconfig specified")
	}

	logger.Info("kubernetes metrics collection enabled",
		"auto_detect", agentCfg.AutoDetect,
		"in_cluster", inCluster,
		"listen_address", agentCfg.ListenAddress,
	)

	// Convert agent config to kubemetrics config
	cfg := &Config{
		KubeState:     agentCfg.KubeState,
		Cadvisor:      agentCfg.Cadvisor,
		ListenAddress: agentCfg.ListenAddress,
		MetricsPath:   agentCfg.MetricsPath,
		TelemetryPath: "/telemetry",
		HealthzPath:   "/healthz",
		Streaming: StreamingConfig{
			Enabled:      agentCfg.Streaming.Enabled,
			Interval:     agentCfg.Streaming.Interval,
			BatchSize:    agentCfg.Streaming.BatchSize,
			FlushTimeout: agentCfg.Streaming.FlushTimeout,
		},
		LogsStreaming: LogsStreamingConfig{
			Enabled:       agentCfg.LogsStreaming.Enabled,
			BufferSize:    agentCfg.LogsStreaming.BufferSize,
			FlushInterval: agentCfg.LogsStreaming.FlushInterval,
			EventTypes:    agentCfg.LogsStreaming.EventTypes,
			Namespaces:    agentCfg.LogsStreaming.Namespaces,
		},
		SignalMetadata: SignalMetadataConfig{
			Enabled: agentCfg.SignalMetadata.Enabled,
			Fields:  agentCfg.SignalMetadata.Fields,
		},
	}

	// Apply defaults for empty values
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = ":9443"
	}
	if cfg.MetricsPath == "" {
		cfg.MetricsPath = "/metrics"
	}
	if cfg.Streaming.Interval == 0 {
		cfg.Streaming.Interval = 15 * time.Second
	}
	if cfg.Streaming.BatchSize == 0 {
		cfg.Streaming.BatchSize = 1000
	}
	if cfg.Streaming.FlushTimeout == 0 {
		cfg.Streaming.FlushTimeout = 5 * time.Second
	}
	if cfg.LogsStreaming.BufferSize == 0 {
		cfg.LogsStreaming.BufferSize = 1000
	}
	if cfg.LogsStreaming.FlushInterval == 0 {
		cfg.LogsStreaming.FlushInterval = 5 * time.Second
	}
	if len(cfg.LogsStreaming.EventTypes) == 0 {
		cfg.LogsStreaming.EventTypes = []string{"Normal", "Warning"}
	}

	// Create the provider
	return New(cfg, logger)
}

// DefaultAgentConfig returns the default agent configuration for kubemetrics
func DefaultAgentConfig() *AgentConfig {
	// Get defaults from underlying packages
	ksConfig := kubestate.DefaultConfig()
	caConfig := cadvisor.DefaultConfig()

	// Enable them by default when used via kubemetrics
	// The individual packages have Enabled=false for standalone use
	ksConfig.Enabled = true
	caConfig.Enabled = true

	return &AgentConfig{
		Enabled:           false, // Overall kubemetrics is disabled, uses auto_detect
		AutoDetect:        true,
		ListenAddress:     ":9443",
		MetricsPath:       "/metrics",
		SeparateEndpoints: true,
		KubeState:         *ksConfig,
		Cadvisor:          *caConfig,
		Streaming: StreamingAgentConfig{
			Enabled:      false,
			Interval:     15 * time.Second,
			BatchSize:    1000,
			FlushTimeout: 5 * time.Second,
			UseOTLP:      true,
		},
		LogsStreaming: LogsStreamingAgentConfig{
			Enabled:       false,
			BufferSize:    1000,
			FlushInterval: 5 * time.Second,
			EventTypes:    []string{"Normal", "Warning"},
			Namespaces:    []string{},
		},
		SignalMetadata: SignalMetadataAgentConfig{
			Enabled: true,
			Fields:  sigdef.DefaultMetadataFieldsConfig(),
		},
	}
}
