package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/platformbuilds/telegen/internal/config"
	"github.com/platformbuilds/telegen/internal/kube"
	"github.com/platformbuilds/telegen/internal/kubemetrics"
	"github.com/platformbuilds/telegen/internal/nodeexporter"
	"github.com/platformbuilds/telegen/internal/pipeline"
	"github.com/platformbuilds/telegen/internal/profiler"
	"github.com/platformbuilds/telegen/internal/selftelemetry"
	"github.com/platformbuilds/telegen/internal/version"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Global JSON logger - all telegen logs are structured JSON
var logger *slog.Logger

func init() {
	// Initialize JSON logger as the default for all telegen output
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)
}

func main() {
	cfgPath := flag.String("config", "/etc/telegen/config.yaml", "path to config yaml")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf(`{"level":"INFO","msg":"version","version":"%s","os":"%s","arch":"%s"}`+"\n",
			version.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Log startup info
	logger.Info("telegen starting",
		"version", version.Version(),
		"mode", "one agent, many signals",
		"ebpf_enabled", cfg.EBPF.Enabled,
		"profiling_enabled", cfg.Profiling.Enabled,
		"jfr_enabled", cfg.Pipelines.JFR.Enabled,
		"logs_enabled", cfg.Pipelines.Logs.Enabled,
	)

	mux := http.NewServeMux()
	st := selftelemetry.InstallHandlers(mux, cfg.SelfTelemetry.Listen)
	srv := &http.Server{Addr: cfg.SelfTelemetry.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info("HTTP server started", "address", cfg.SelfTelemetry.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())

	// Track which signals are successfully started for graceful degradation
	var signalsStarted int

	// Start the pipeline FIRST to get the shared OTLP exporters
	// The pipeline creates OTLP trace, log, and metrics exporters from exports.otlp config
	pl := pipeline.New(cfg, st)
	if err := pl.Start(ctx); err != nil {
		logger.Warn("pipeline failed to start, continuing with other signals",
			"error", err,
			"status", "degraded")
	} else {
		signalsStarted++
	}

	// Get the shared metrics exporter from the pipeline for kube_metrics and node_exporter
	sharedMetricsExporter := pl.GetMetricsExporter()

	// Start node_exporter if enabled
	var nodeExp *nodeexporter.Exporter
	if cfg.NodeExporter.Enabled {
		var err error
		nodeExp, err = nodeexporter.New(cfg.NodeExporter)
		if err != nil {
			logger.Warn("node_exporter failed to initialize, continuing without node metrics",
				"error", err,
				"status", "degraded")
			nodeExp = nil // Ensure it's nil so we don't try to use it later
		} else {
			signalsStarted++
			go func() {
				logger.Info("node_exporter started",
					"port", cfg.NodeExporter.Endpoint.Port,
					"path", cfg.NodeExporter.Endpoint.Path)
				if err := nodeExp.Run(ctx); err != nil && err != http.ErrServerClosed {
					logger.Error("node_exporter runtime error",
						"error", err,
						"status", "degraded")
				}
			}()
		}
	}

	// Start kube_metrics if enabled or auto-detected
	// This provides kube-state-metrics + cAdvisor equivalent metrics natively
	kubeMetricsProvider := startKubeMetrics(ctx, cfg, sharedMetricsExporter)
	if kubeMetricsProvider != nil {
		signalsStarted++
	}

	// Get kube.Store from pipeline's eBPF context (reuse what's already working)
	// The pipeline already initialized kube.Store for eBPF instrumentation
	var kubeStore *kube.Store
	if cfg.EBPF.Enabled {
		var err error
		kubeStore, err = pl.GetKubeStore(ctx)
		if err != nil {
			logger.Warn("failed to get kube.Store from pipeline for profiler",
				"error", err)
		} else if kubeStore != nil {
			logger.Info("profiler will use pipeline's kube.Store for namespace resolution")
		}
	}

	// Start eBPF profiler if enabled
	var profilerRunner *profiler.Runner
	if cfg.Profiling.Enabled {
		var err error
		// Inject service name from agent config
		profCfg := cfg.Profiling
		profCfg.ServiceName = cfg.Agent.ServiceName

		profilerRunner, err = profiler.NewRunner(profCfg, logger, kubeStore)
		if err != nil {
			logger.Warn("profiler failed to initialize, continuing without profiling",
				"error", err,
				"status", "degraded")
		} else {
			if err := profilerRunner.Start(ctx); err != nil {
				logger.Warn("profiler failed to start, continuing without profiling",
					"error", err,
					"status", "degraded")
				profilerRunner = nil
			} else {
				signalsStarted++
				logger.Info("eBPF profiling started",
					"cpu_enabled", cfg.Profiling.CPU.Enabled,
					"offcpu_enabled", cfg.Profiling.OffCPU.Enabled,
					"memory_enabled", cfg.Profiling.Memory.Enabled,
					"mutex_enabled", cfg.Profiling.Mutex.Enabled,
					"wall_enabled", cfg.Profiling.Wall.Enabled,
					"log_export_enabled", cfg.Profiling.LogExport.Enabled,
					"metrics_export_enabled", cfg.Profiling.MetricsExport.Enabled,
					"metrics_export_endpoint", cfg.Profiling.MetricsExport.Endpoint,
				)
			}
		}
	}

	// Check if we have at least one working signal
	if signalsStarted == 0 {
		logger.Error("no signals could be started, cannot operate without at least one data source")
		os.Exit(1)
	}
	logger.Info("telegen ready", "signals_started", signalsStarted)

	// Wire up node_exporter OTLP streaming if enabled
	if nodeExp != nil && cfg.NodeExporter.Export.Enabled && cfg.NodeExporter.Export.UseOTLP {
		if sharedMetricsExporter != nil {
			if err := nodeExp.ConfigureOTLPStreaming(ctx, sharedMetricsExporter); err != nil {
				logger.Warn("node_exporter failed to configure OTLP streaming", "error", err)
			} else {
				logger.Info("node_exporter OTLP streaming enabled",
					"interval", cfg.NodeExporter.Export.Interval)
			}
		} else {
			logger.Warn("node_exporter OTLP streaming configured but no OTLP metrics exporter available")
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	logger.Info("telegen shutting down")
	cancel()
	pl.Close()
	if profilerRunner != nil {
		_ = profilerRunner.Stop(context.Background())
	}
	if nodeExp != nil {
		_ = nodeExp.Shutdown(context.Background())
	}
	if kubeMetricsProvider != nil {
		_ = kubeMetricsProvider.Stop(context.Background())
	}
	_ = srv.Shutdown(context.Background())
	logger.Info("telegen shutdown complete")
}

// startKubeMetrics initializes and starts the kubemetrics provider if enabled or auto-detected.
// Returns nil if kubemetrics is disabled or if running outside a Kubernetes cluster without explicit config.
func startKubeMetrics(ctx context.Context, cfg *config.Config, metricsExporter sdkmetric.Exporter) *kubemetrics.Provider {
	// Create a structured logger for kubemetrics (uses global logger with component tag)
	kubeLogger := logger.With("component", "kubemetrics")

	// Check if we should auto-enable based on Kubernetes detection
	inCluster := kubemetrics.IsInCluster()

	// Determine if we should start kubemetrics
	shouldStart := cfg.KubeMetrics.ShouldAutoEnable(inCluster)
	if !shouldStart {
		if cfg.KubeMetrics.AutoDetect {
			logger.Info("kube_metrics auto-detect enabled but not in Kubernetes cluster")
		}
		return nil
	}

	// Build agent config from the main config
	agentCfg := &kubemetrics.AgentConfig{
		Enabled:           cfg.KubeMetrics.Enabled,
		AutoDetect:        cfg.KubeMetrics.AutoDetect,
		ListenAddress:     cfg.KubeMetrics.ListenAddress,
		MetricsPath:       cfg.KubeMetrics.MetricsPath,
		SeparateEndpoints: cfg.KubeMetrics.SeparateEndpoints,
		KubeState:         cfg.KubeMetrics.KubeState,
		Cadvisor:          cfg.KubeMetrics.Cadvisor,
		Streaming: kubemetrics.StreamingAgentConfig{
			Enabled:      cfg.KubeMetrics.Streaming.Enabled,
			Interval:     cfg.KubeMetrics.Streaming.Interval,
			BatchSize:    cfg.KubeMetrics.Streaming.BatchSize,
			FlushTimeout: cfg.KubeMetrics.Streaming.FlushTimeout,
			UseOTLP:      cfg.KubeMetrics.Streaming.UseOTLP,
		},
		LogsStreaming: kubemetrics.LogsStreamingAgentConfig{
			Enabled:       cfg.KubeMetrics.LogsStreaming.Enabled,
			BufferSize:    cfg.KubeMetrics.LogsStreaming.BufferSize,
			FlushInterval: cfg.KubeMetrics.LogsStreaming.FlushInterval,
			EventTypes:    cfg.KubeMetrics.LogsStreaming.EventTypes,
			Namespaces:    cfg.KubeMetrics.LogsStreaming.Namespaces,
		},
		SignalMetadata: kubemetrics.SignalMetadataAgentConfig{
			Enabled: cfg.KubeMetrics.SignalMetadata.Enabled,
			Fields:  cfg.KubeMetrics.SignalMetadata.Fields,
		},
	}

	// Create the provider
	provider, err := kubemetrics.NewFromAgentConfig(agentCfg, kubeLogger)
	if err != nil {
		logger.Warn("kube_metrics failed to create provider", "error", err)
		return nil
	}
	if provider == nil {
		// Not an error, just not enabled
		return nil
	}

	// Start the provider (HTTP server + collectors)
	if err := provider.Start(ctx); err != nil {
		logger.Warn("kube_metrics failed to start", "error", err)
		return nil
	}

	logger.Info("kube_metrics enabled",
		"listen_address", cfg.KubeMetrics.ListenAddress,
		"metrics_path", cfg.KubeMetrics.MetricsPath,
		"kubestate_enabled", cfg.KubeMetrics.KubeState.Enabled,
		"cadvisor_enabled", cfg.KubeMetrics.Cadvisor.Enabled,
	)

	// Configure OTLP streaming if enabled
	if cfg.KubeMetrics.Streaming.Enabled && cfg.KubeMetrics.Streaming.UseOTLP {
		configureKubeMetricsStreaming(ctx, provider, cfg, metricsExporter)
	}

	return provider
}

// configureKubeMetricsStreaming sets up OTLP streaming for kubemetrics
func configureKubeMetricsStreaming(ctx context.Context, provider *kubemetrics.Provider, cfg *config.Config, metricsExporter sdkmetric.Exporter) {
	// Use the shared OTLP metrics exporter from the pipeline
	if metricsExporter == nil {
		logger.Warn("kube_metrics OTLP streaming configured but no OTLP metrics exporter available")
		return
	}

	// Get the Kubernetes client for logs streaming (events watching)
	kubeClient := provider.GetKubernetesClient()

	// Setup streaming - logs exporter is nil for now (can be added when OTLP logs are configured)
	if err := provider.SetupStreaming(metricsExporter, nil, kubeClient); err != nil {
		logger.Error("kube_metrics failed to configure OTLP streaming", "error", err)
		return
	}

	logger.Info("kube_metrics OTLP streaming enabled", "interval", cfg.KubeMetrics.Streaming.Interval)
}
