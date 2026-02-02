// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nodeexporter provides Prometheus node_exporter compatible system metrics
// collection for telegen. This package enables telegen to be a drop-in replacement
// for node_exporter while maintaining its architecture.
package nodeexporter

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/platformbuilds/telegen/internal/nodeexporter/collector"
)

// Exporter represents a node_exporter compatible metrics exporter.
type Exporter struct {
	config      *Config
	collectors  map[string]collector.Collector
	registry    *prometheus.Registry
	logger      *slog.Logger
	server      *http.Server
	environment *DetectedEnvironment
	streaming   *StreamingExporter
}

// New creates a new Exporter with the given configuration.
func New(cfg Config) (*Exporter, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = "node"
	}
	if cfg.Paths.ProcPath == "" {
		cfg.Paths.ProcPath = "/proc"
	}
	if cfg.Paths.SysPath == "" {
		cfg.Paths.SysPath = "/sys"
	}
	if cfg.Paths.RootPath == "" {
		cfg.Paths.RootPath = "/"
	}
	if cfg.Endpoint.Port == 0 {
		cfg.Endpoint.Port = 9100
	}
	if cfg.Endpoint.Path == "" {
		cfg.Endpoint.Path = "/metrics"
	}
	if cfg.Scrape.Timeout == 0 {
		cfg.Scrape.Timeout = 20 * time.Second
	}

	logger := slog.Default()

	// Detect environment
	env := DetectEnvironment(cfg.Environment)

	e := &Exporter{
		config:      &cfg,
		collectors:  make(map[string]collector.Collector),
		registry:    prometheus.NewRegistry(),
		logger:      logger,
		environment: env,
	}

	logger.Info("detected environment",
		"type", env.Type,
		"virtualized", env.IsVirtualized,
		"virtualization_type", env.VirtualizationType)

	if env.Kubernetes != nil && env.Kubernetes.Detected {
		logger.Info("kubernetes environment detected",
			"node", env.Kubernetes.NodeName,
			"namespace", env.Kubernetes.Namespace,
			"pod", env.Kubernetes.PodName)
	}

	if err := e.initCollectors(); err != nil {
		return nil, fmt.Errorf("failed to initialize collectors: %w", err)
	}

	return e, nil
}

// initCollectors initializes all enabled collectors.
func (e *Exporter) initCollectors() error {
	pathConfig := collector.PathConfig{
		ProcPath:   e.config.Paths.ProcPath,
		SysPath:    e.config.Paths.SysPath,
		RootfsPath: e.config.Paths.RootPath,
		UdevPath:   e.config.Paths.UdevDataPath,
	}

	baseCfg := collector.CollectorConfig{
		Paths:            pathConfig,
		Logger:           e.logger,
		CollectorTimeout: e.config.Scrape.Timeout,
		Extra:            make(map[string]interface{}),
	}

	// Add collector-specific configurations
	if e.config.Collectors.CPU.EnableGuest || e.config.Collectors.CPU.EnableInfo {
		cpuConfig := collector.CPUCollectorConfig{
			EnableGuest:  e.config.Collectors.CPU.EnableGuest,
			EnableInfo:   e.config.Collectors.CPU.EnableInfo,
			FlagsInclude: e.config.Collectors.CPU.FlagsInclude,
			BugsInclude:  e.config.Collectors.CPU.BugsInclude,
		}
		baseCfg.CPUConfig = &cpuConfig
	}

	// Initialize collectors
	collectors, err := collector.DefaultRegistry.CreateEnabled(
		baseCfg,
		e.isCollectorEnabled,
		e.logger,
	)
	if err != nil {
		return err
	}

	e.collectors = collectors

	// Create the NodeCollector
	nodeCollector := collector.NewNodeCollector(
		e.config.Namespace,
		e.collectors,
		e.logger,
		e.config.Scrape.Timeout,
		true, // continueOnError
	)

	if err := e.registry.Register(nodeCollector); err != nil {
		return fmt.Errorf("failed to register node collector: %w", err)
	}

	return nil
}

// isCollectorEnabled checks if a collector is enabled based on configuration.
func (e *Exporter) isCollectorEnabled(name string, defaultEnabled bool) bool {
	return e.config.IsCollectorEnabled(name, defaultEnabled)
}

// Handler returns an HTTP handler for the metrics endpoint.
func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(
		e.registry,
		promhttp.HandlerOpts{
			ErrorLog:            slog.NewLogLogger(e.logger.Handler(), slog.LevelError),
			ErrorHandling:       promhttp.ContinueOnError,
			MaxRequestsInFlight: 0, // unlimited
			Timeout:             e.config.Scrape.Timeout,
			EnableOpenMetrics:   true,
		},
	)
}

// Collect runs all collectors and returns metrics.
func (e *Exporter) Collect() ([]*prometheus.Metric, error) {
	ch := make(chan prometheus.Metric)
	var metrics []*prometheus.Metric

	go func() {
		for metric := range ch {
			m := metric
			metrics = append(metrics, &m)
		}
	}()

	for name, c := range e.collectors {
		if err := c.Update(ch); err != nil {
			if !collector.IsNoDataError(err) {
				e.logger.Error("collector failed", "collector", name, "err", err)
			}
		}
	}
	close(ch)

	return metrics, nil
}

// Registry returns the Prometheus registry used by this exporter.
func (e *Exporter) Registry() *prometheus.Registry {
	return e.registry
}

// Environment returns the detected deployment environment.
func (e *Exporter) Environment() *DetectedEnvironment {
	return e.environment
}

// EnabledCollectors returns a list of enabled collector names.
func (e *Exporter) EnabledCollectors() []string {
	names := make([]string, 0, len(e.collectors))
	for name := range e.collectors {
		names = append(names, name)
	}
	return names
}

// StartStreaming starts the streaming exporter if configured.
// This enables periodic collection and push of metrics to the configured receiver.
func (e *Exporter) StartStreaming(ctx context.Context, receiver MetricsReceiver) error {
	if !e.config.Export.Enabled {
		return nil
	}

	e.streaming = NewStreamingExporter(
		&e.config.Export,
		e.registry,
		e.environment,
		e.logger,
	)
	e.streaming.SetReceiver(receiver)

	return e.streaming.Start(ctx)
}

// StopStreaming stops the streaming exporter.
func (e *Exporter) StopStreaming() {
	if e.streaming != nil {
		e.streaming.Stop()
	}
}

// Close releases any resources held by the exporter.
func (e *Exporter) Close() error {
	e.StopStreaming()
	return nil
}

// Serve starts an HTTP server for the metrics endpoint.
func (e *Exporter) Serve() error {
	mux := http.NewServeMux()

	// Metrics endpoint
	mux.Handle(e.config.Endpoint.Path, e.Handler())

	// Liveness endpoint - always returns OK if the process is running
	mux.HandleFunc("/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	// Readiness endpoint - returns OK if collectors are initialized
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if len(e.collectors) == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Not Ready: no collectors initialized\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Ready\n"))
	})

	// Health endpoint - detailed health status
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"healthy","collectors":%d,"namespace":"%s"}`, len(e.collectors), e.config.Namespace)
		_, _ = w.Write([]byte("\n"))
	})

	// Root endpoint - landing page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Telegen Node Exporter</title></head>
<body>
<h1>Telegen Node Exporter</h1>
<p><a href="%s">Metrics</a></p>
<p><a href="/health">Health</a></p>
<p><a href="/ready">Ready</a></p>
<p><a href="/live">Live</a></p>
</body>
</html>
`, e.config.Endpoint.Path)
	})

	addr := fmt.Sprintf(":%d", e.config.Endpoint.Port)
	e.logger.Info("starting node_exporter compatible endpoint",
		"addr", addr,
		"path", e.config.Endpoint.Path,
		"collectors", e.EnabledCollectors())

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	return server.ListenAndServe()
}

// Run starts the exporter and blocks until the context is cancelled.
// This is the preferred method for integration with telegen.
func (e *Exporter) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	// Metrics endpoint
	mux.Handle(e.config.Endpoint.Path, e.Handler())

	// Liveness endpoint
	mux.HandleFunc("/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	// Readiness endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if len(e.collectors) == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Not Ready: no collectors initialized\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Ready\n"))
	})

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"healthy","collectors":%d,"namespace":"%s"}`, len(e.collectors), e.config.Namespace)
		_, _ = w.Write([]byte("\n"))
	})

	// Root endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Telegen Node Exporter</title></head>
<body>
<h1>Telegen Node Exporter</h1>
<p><a href="%s">Metrics</a></p>
<p><a href="/health">Health</a></p>
<p><a href="/ready">Ready</a></p>
<p><a href="/live">Live</a></p>
</body>
</html>
`, e.config.Endpoint.Path)
	})

	addr := fmt.Sprintf(":%d", e.config.Endpoint.Port)
	e.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	e.logger.Info("starting node_exporter compatible endpoint",
		"addr", addr,
		"path", e.config.Endpoint.Path,
		"collectors", e.EnabledCollectors())

	// Watch for context cancellation
	go func() {
		<-ctx.Done()
		_ = e.Shutdown(context.Background())
	}()

	return e.server.ListenAndServe()
}

// Shutdown gracefully shuts down the exporter.
func (e *Exporter) Shutdown(ctx context.Context) error {
	e.StopStreaming()
	if e.server != nil {
		return e.server.Shutdown(ctx)
	}
	return nil
}

// ConfigureOTLPStreaming sets up OTLP streaming with the provided exporter.
// This allows the node exporter to push metrics through telegen's OTLP pipeline.
func (e *Exporter) ConfigureOTLPStreaming(ctx context.Context, exporter sdkmetric.Exporter) error {
	if exporter == nil {
		return nil
	}

	bridge, err := NewOTLPBridge(exporter, e.environment, e.logger)
	if err != nil {
		return fmt.Errorf("failed to create OTLP bridge: %w", err)
	}

	return e.StartStreaming(ctx, bridge)
}
