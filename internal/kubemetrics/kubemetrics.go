// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package kubemetrics provides unified Kubernetes metrics collection combining
// kube-state-metrics equivalent (kubestate) and cAdvisor equivalent (cadvisor).
// Supports both HTTP/Prometheus pull and OTLP push export modes.
package kubemetrics

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"k8s.io/client-go/kubernetes"

	"github.com/platformbuilds/telegen/internal/cadvisor"
	"github.com/platformbuilds/telegen/internal/kubestate"
	"github.com/platformbuilds/telegen/internal/sigdef"
)

// Config holds configuration for the unified Kubernetes metrics provider
type Config struct {
	// KubeState configuration for kube-state-metrics equivalent
	KubeState kubestate.Config `yaml:"kubeState"`

	// Cadvisor configuration for container resource metrics
	Cadvisor cadvisor.Config `yaml:"cadvisor"`

	// ListenAddress is the address to listen on for metrics
	ListenAddress string `yaml:"listenAddress"`

	// MetricsPath is the path for the metrics endpoint
	MetricsPath string `yaml:"metricsPath"`

	// TelemetryPath is the path for self-telemetry
	TelemetryPath string `yaml:"telemetryPath"`

	// HealthzPath is the path for health checks
	HealthzPath string `yaml:"healthzPath"`

	// Streaming configuration for OTLP push export
	Streaming StreamingConfig `yaml:"streaming"`

	// LogsStreaming configuration for Kubernetes events as OTLP logs
	LogsStreaming LogsStreamingConfig `yaml:"logsStreaming"`

	// SignalMetadata configuration for telegen.* attributes
	SignalMetadata SignalMetadataConfig `yaml:"signalMetadata"`
}

// SignalMetadataConfig controls signal metadata export
type SignalMetadataConfig struct {
	// Enabled enables signal metadata export
	Enabled bool `yaml:"enabled"`

	// Fields controls which metadata fields are exported
	Fields sigdef.MetadataFieldsConfig `yaml:"fields"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		KubeState:     *kubestate.DefaultConfig(),
		Cadvisor:      *cadvisor.DefaultConfig(),
		ListenAddress: ":8080",
		MetricsPath:   "/metrics",
		TelemetryPath: "/telemetry",
		HealthzPath:   "/healthz",
		Streaming:     DefaultStreamingConfig(),
		LogsStreaming: DefaultLogsStreamingConfig(),
		SignalMetadata: SignalMetadataConfig{
			Enabled: true,
			Fields:  sigdef.DefaultMetadataFieldsConfig(),
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if err := c.KubeState.Validate(); err != nil {
		return fmt.Errorf("kubestate config: %w", err)
	}
	if err := c.Cadvisor.Validate(); err != nil {
		return fmt.Errorf("cadvisor config: %w", err)
	}
	return nil
}

// Provider provides unified Kubernetes metrics
type Provider struct {
	config    *Config
	kubestate *kubestate.KubeState
	cadvisor  *cadvisor.Collector
	logger    *slog.Logger

	// Streaming exporters
	metricsStreaming *StreamingExporter
	logsStreaming    *LogsStreamingExporter
	metadataProvider *MetadataProvider

	server   *http.Server
	serverMu sync.Mutex
}

// New creates a new Kubernetes metrics provider
func New(config *Config, logger *slog.Logger) (*Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	p := &Provider{
		config:           config,
		logger:           logger,
		metadataProvider: NewMetadataProvider(config.SignalMetadata.Fields, config.SignalMetadata.Enabled),
	}

	// Initialize kubestate collector
	if config.KubeState.Enabled {
		ks, err := kubestate.New(&config.KubeState, logger.With("component", "kubestate"))
		if err != nil {
			return nil, fmt.Errorf("failed to create kubestate: %w", err)
		}
		p.kubestate = ks
	}

	// Initialize cadvisor collector
	if config.Cadvisor.Enabled {
		ca, err := cadvisor.NewCollector(&config.Cadvisor, logger.With("component", "cadvisor"))
		if err != nil {
			return nil, fmt.Errorf("failed to create cadvisor: %w", err)
		}
		p.cadvisor = ca
	}

	return p, nil
}

// SetupStreaming configures streaming export to OTLP
func (p *Provider) SetupStreaming(
	metricsExporter sdkmetric.Exporter,
	logsExporter LogsExporter,
	kubeClient kubernetes.Interface,
) error {
	// Setup metrics streaming
	if p.config.Streaming.Enabled && metricsExporter != nil {
		streamingCfg := &p.config.Streaming
		streamingCfg.IncludeSignalMetadata = p.config.SignalMetadata.Enabled
		streamingCfg.MetadataConfig = p.config.SignalMetadata.Fields

		streamer, err := NewStreamingExporter(
			streamingCfg,
			p,
			metricsExporter,
			p.logger.With("component", "streaming"),
		)
		if err != nil {
			return fmt.Errorf("failed to create metrics streamer: %w", err)
		}
		p.metricsStreaming = streamer
	}

	// Setup logs streaming (Kubernetes events)
	if p.config.LogsStreaming.Enabled && logsExporter != nil && kubeClient != nil {
		logsCfg := &p.config.LogsStreaming
		logsCfg.IncludeSignalMetadata = p.config.SignalMetadata.Enabled
		logsCfg.MetadataConfig = p.config.SignalMetadata.Fields

		logsStreamer, err := NewLogsStreamingExporter(
			logsCfg,
			kubeClient,
			logsExporter,
			p.logger.With("component", "logs_streaming"),
		)
		if err != nil {
			return fmt.Errorf("failed to create logs streamer: %w", err)
		}
		p.logsStreaming = logsStreamer
	}

	return nil
}

// Start starts the metrics provider
func (p *Provider) Start(ctx context.Context) error {
	// Start kubestate
	if p.kubestate != nil {
		if err := p.kubestate.Start(ctx); err != nil {
			return fmt.Errorf("failed to start kubestate: %w", err)
		}
	}

	// Start cadvisor
	if p.cadvisor != nil {
		if err := p.cadvisor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start cadvisor: %w", err)
		}
	}

	// Start streaming exporters
	if p.metricsStreaming != nil {
		if err := p.metricsStreaming.Start(ctx); err != nil {
			return fmt.Errorf("failed to start metrics streaming: %w", err)
		}
	}

	if p.logsStreaming != nil {
		if err := p.logsStreaming.Start(ctx); err != nil {
			return fmt.Errorf("failed to start logs streaming: %w", err)
		}
	}

	// Start HTTP server
	mux := http.NewServeMux()

	// Main metrics endpoint - combines both kubestate and cadvisor
	mux.HandleFunc(p.config.MetricsPath, p.metricsHandler)

	// Separate endpoints for each component
	if p.kubestate != nil {
		mux.HandleFunc("/metrics/kubestate", func(w http.ResponseWriter, r *http.Request) {
			p.kubestate.ServeHTTP(w, r)
		})
	}
	if p.cadvisor != nil {
		mux.HandleFunc("/metrics/cadvisor", func(w http.ResponseWriter, r *http.Request) {
			p.cadvisor.ServeHTTP(w, r)
		})
	}

	// Health check
	mux.HandleFunc(p.config.HealthzPath, p.healthHandler)

	// Telemetry about the provider itself
	mux.HandleFunc(p.config.TelemetryPath, p.telemetryHandler)

	p.serverMu.Lock()
	p.server = &http.Server{
		Addr:    p.config.ListenAddress,
		Handler: mux,
	}
	p.serverMu.Unlock()

	p.logger.Info("starting kubernetes metrics provider",
		"address", p.config.ListenAddress,
		"metricsPath", p.config.MetricsPath,
		"streaming.enabled", p.config.Streaming.Enabled,
		"logs_streaming.enabled", p.config.LogsStreaming.Enabled)

	go func() {
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.logger.Error("server error", "error", err)
		}
	}()

	return nil
}

// Stop stops the metrics provider
func (p *Provider) Stop(ctx context.Context) error {
	p.serverMu.Lock()
	server := p.server
	p.serverMu.Unlock()

	if server != nil {
		if err := server.Shutdown(ctx); err != nil {
			p.logger.Error("failed to shutdown server", "error", err)
		}
	}

	// Stop streaming exporters
	if p.metricsStreaming != nil {
		p.metricsStreaming.Stop()
	}
	if p.logsStreaming != nil {
		p.logsStreaming.Stop()
	}

	if p.kubestate != nil {
		p.kubestate.Stop()
	}
	if p.cadvisor != nil {
		p.cadvisor.Stop()
	}

	return nil
}

// metricsHandler serves combined metrics from kubestate and cadvisor
func (p *Provider) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Write kubestate metrics
	if p.kubestate != nil {
		_ = p.kubestate.WriteMetrics(w)
	}

	// Write cadvisor metrics
	if p.cadvisor != nil {
		stats, err := p.cadvisor.CollectAll()
		if err != nil {
			p.logger.Error("failed to collect cadvisor metrics", "error", err)
		} else {
			p.cadvisor.WriteMetrics(w, stats)
		}
	}
}

// healthHandler serves health check endpoint
func (p *Provider) healthHandler(w http.ResponseWriter, r *http.Request) {
	healthy := true
	status := make(map[string]string)

	if p.kubestate != nil {
		if p.kubestate.IsHealthy() {
			status["kubestate"] = "ok"
		} else {
			status["kubestate"] = "unhealthy"
			healthy = false
		}
	}

	if p.cadvisor != nil {
		if p.cadvisor.IsHealthy() {
			status["cadvisor"] = "ok"
		} else {
			status["cadvisor"] = "unhealthy"
			healthy = false
		}
	}

	if healthy {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "unhealthy")
	}
}

// telemetryHandler serves self-telemetry metrics
func (p *Provider) telemetryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	if p.kubestate != nil {
		stats := p.kubestate.Stats()
		_, _ = fmt.Fprintf(w, "# HELP kubemetrics_kubestate_stores_total Number of metrics stores\n")
		_, _ = fmt.Fprintf(w, "# TYPE kubemetrics_kubestate_stores_total gauge\n")
		_, _ = fmt.Fprintf(w, "kubemetrics_kubestate_stores_total %v\n", stats["stores"])
		_, _ = fmt.Fprintf(w, "# HELP kubemetrics_kubestate_informers_total Number of active informers\n")
		_, _ = fmt.Fprintf(w, "# TYPE kubemetrics_kubestate_informers_total gauge\n")
		_, _ = fmt.Fprintf(w, "kubemetrics_kubestate_informers_total %v\n", stats["informers"])
	}

	if p.cadvisor != nil {
		stats := p.cadvisor.Stats()
		_, _ = fmt.Fprintf(w, "# HELP kubemetrics_cadvisor_containers_total Number of containers being monitored\n")
		_, _ = fmt.Fprintf(w, "# TYPE kubemetrics_cadvisor_containers_total gauge\n")
		_, _ = fmt.Fprintf(w, "kubemetrics_cadvisor_containers_total %v\n", stats["containers"])
	}

	// Streaming stats
	if p.metricsStreaming != nil {
		stats := p.metricsStreaming.Stats()
		_, _ = fmt.Fprintf(w, "# HELP kubemetrics_streaming_exports_total Total streaming exports\n")
		_, _ = fmt.Fprintf(w, "# TYPE kubemetrics_streaming_exports_total counter\n")
		_, _ = fmt.Fprintf(w, "kubemetrics_streaming_exports_total %v\n", stats["export_count"])
	}

	if p.logsStreaming != nil {
		stats := p.logsStreaming.Stats()
		_, _ = fmt.Fprintf(w, "# HELP kubemetrics_logs_events_received_total K8s events received\n")
		_, _ = fmt.Fprintf(w, "# TYPE kubemetrics_logs_events_received_total counter\n")
		_, _ = fmt.Fprintf(w, "kubemetrics_logs_events_received_total %v\n", stats["events_received"])
		_, _ = fmt.Fprintf(w, "# HELP kubemetrics_logs_events_exported_total K8s events exported\n")
		_, _ = fmt.Fprintf(w, "# TYPE kubemetrics_logs_events_exported_total counter\n")
		_, _ = fmt.Fprintf(w, "kubemetrics_logs_events_exported_total %v\n", stats["events_exported"])
	}
}

// Stats returns combined statistics
func (p *Provider) Stats() map[string]interface{} {
	stats := make(map[string]interface{})

	if p.kubestate != nil {
		stats["kubestate"] = p.kubestate.Stats()
	}
	if p.cadvisor != nil {
		stats["cadvisor"] = p.cadvisor.Stats()
	}
	if p.metricsStreaming != nil {
		stats["metrics_streaming"] = p.metricsStreaming.Stats()
	}
	if p.logsStreaming != nil {
		stats["logs_streaming"] = p.logsStreaming.Stats()
	}

	return stats
}

// GetMetadataProvider returns the signal metadata provider
func (p *Provider) GetMetadataProvider() *MetadataProvider {
	return p.metadataProvider
}

// GetKubernetesClient returns the Kubernetes client if available
func (p *Provider) GetKubernetesClient() kubernetes.Interface {
	if p.kubestate != nil {
		return p.kubestate.GetClient()
	}
	return nil
}

// getEnvOrDefault returns an environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
