// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"time"

	"github.com/platformbuilds/telegen/internal/cadvisor"
	"github.com/platformbuilds/telegen/internal/kubestate"
	"github.com/platformbuilds/telegen/internal/sigdef"
)

// KubeMetricsConfig holds configuration for Kubernetes metrics collection
// This includes kube-state-metrics equivalent and cAdvisor equivalent metrics
// Part of Telegen's "One Agent, Many Signals" architecture.
type KubeMetricsConfig struct {
	// Enabled controls whether Kubernetes metrics collection is active
	// Auto-enabled when running in a Kubernetes cluster (if auto_detect is true)
	Enabled bool `yaml:"enabled"`

	// AutoDetect enables automatic Kubernetes environment detection
	// When true, kube_metrics is automatically enabled if running in-cluster
	AutoDetect bool `yaml:"auto_detect"`

	// KubeState configures kube-state-metrics equivalent collection
	// Provides metrics about Kubernetes object state (pods, deployments, etc.)
	KubeState kubestate.Config `yaml:"kube_state"`

	// Cadvisor configures cAdvisor equivalent collection
	// Provides container resource utilization metrics (CPU, memory, disk, network)
	Cadvisor cadvisor.Config `yaml:"cadvisor"`

	// ListenAddress is the address to listen on for metrics
	// Default: ":9443" (separate from main Prometheus endpoint)
	ListenAddress string `yaml:"listen_address"`

	// MetricsPath is the path for the combined metrics endpoint
	// Default: "/metrics"
	MetricsPath string `yaml:"metrics_path"`

	// SeparateEndpoints exposes kubestate and cadvisor on separate paths
	// When true: /metrics/kubestate and /metrics/cadvisor
	// When false: combined on /metrics
	SeparateEndpoints bool `yaml:"separate_endpoints"`

	// Streaming configures OTLP push export for metrics
	Streaming StreamingConfig `yaml:"streaming"`

	// LogsStreaming configures K8s events as OTLP logs
	LogsStreaming LogsStreamingConfig `yaml:"logs_streaming"`

	// SignalMetadata configures telegen.* attributes
	SignalMetadata SignalMetadataConfig `yaml:"signal_metadata"`
}

// StreamingConfig configures OTLP push export for kube metrics
type StreamingConfig struct {
	// Enabled enables streaming push to OTLP endpoint
	Enabled bool `yaml:"enabled"`

	// Interval is the push interval
	Interval time.Duration `yaml:"interval"`

	// BatchSize is the maximum batch size
	BatchSize int `yaml:"batch_size"`

	// FlushTimeout is the flush timeout
	FlushTimeout time.Duration `yaml:"flush_timeout"`

	// UseOTLP uses telegen's configured OTLP exporter
	UseOTLP bool `yaml:"use_otlp"`
}

// LogsStreamingConfig configures K8s events as OTLP logs
type LogsStreamingConfig struct {
	// Enabled enables K8s event streaming as OTLP logs
	Enabled bool `yaml:"enabled"`

	// BufferSize is the event buffer size
	BufferSize int `yaml:"buffer_size"`

	// FlushInterval is the flush interval
	FlushInterval time.Duration `yaml:"flush_interval"`

	// EventTypes are the event types to include
	EventTypes []string `yaml:"event_types"`

	// Namespaces to watch (empty = all)
	Namespaces []string `yaml:"namespaces"`
}

// SignalMetadataConfig controls telegen.* attributes
type SignalMetadataConfig struct {
	// Enabled enables signal metadata
	Enabled bool `yaml:"enabled"`

	// Fields controls which metadata fields are exported
	// Uses sigdef.MetadataFieldsConfig for consistency across telegen
	Fields sigdef.MetadataFieldsConfig `yaml:"fields"`
}

// DefaultKubeMetricsConfig returns the default Kubernetes metrics configuration
func DefaultKubeMetricsConfig() KubeMetricsConfig {
	return KubeMetricsConfig{
		Enabled:           false, // Disabled by default, auto-enabled if in K8s
		AutoDetect:        true,  // Auto-detect K8s environment
		KubeState:         *kubestate.DefaultConfig(),
		Cadvisor:          *cadvisor.DefaultConfig(),
		ListenAddress:     ":9443",
		MetricsPath:       "/metrics",
		SeparateEndpoints: true,
		Streaming: StreamingConfig{
			Enabled:      false,
			Interval:     15 * time.Second,
			BatchSize:    1000,
			FlushTimeout: 5 * time.Second,
			UseOTLP:      true,
		},
		LogsStreaming: LogsStreamingConfig{
			Enabled:       false,
			BufferSize:    1000,
			FlushInterval: 5 * time.Second,
			EventTypes:    []string{"Normal", "Warning"},
			Namespaces:    []string{},
		},
		SignalMetadata: SignalMetadataConfig{
			Enabled: true,
			Fields:  sigdef.DefaultMetadataFieldsConfig(),
		},
	}
}

// Validate validates the Kubernetes metrics configuration
func (c *KubeMetricsConfig) Validate() error {
	if !c.Enabled && !c.AutoDetect {
		return nil
	}

	if c.KubeState.Enabled {
		if err := c.KubeState.Validate(); err != nil {
			return err
		}
	}

	if c.Cadvisor.Enabled {
		if err := c.Cadvisor.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// ShouldAutoEnable checks if kube_metrics should be auto-enabled
// based on Kubernetes environment detection
func (c *KubeMetricsConfig) ShouldAutoEnable(inCluster bool) bool {
	if c.Enabled {
		return true
	}
	return c.AutoDetect && inCluster
}

// ToKubeStateConfig returns the kubestate config
func (c *KubeMetricsConfig) ToKubeStateConfig() *kubestate.Config {
	return &c.KubeState
}

// ToCadvisorConfig returns the cadvisor config
func (c *KubeMetricsConfig) ToCadvisorConfig() *cadvisor.Config {
	return &c.Cadvisor
}
