package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/platformbuilds/telegen/internal/config"
	"github.com/platformbuilds/telegen/internal/kubemetrics"
	"github.com/platformbuilds/telegen/internal/nodeexporter"
	"github.com/platformbuilds/telegen/internal/pipeline"
	"github.com/platformbuilds/telegen/internal/selftelemetry"
	"github.com/platformbuilds/telegen/internal/version"
	"github.com/platformbuilds/telegen/pkg/export/otel/otelcfg"
)

func main() {
	cfgPath := flag.String("config", "/etc/telegen/config.yaml", "path to config yaml")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		log.Printf("telegen %s (%s/%s)", version.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Log startup info
	log.Printf("telegen %s starting (one agent, many signals)", version.Version())
	if cfg.EBPF.Enabled {
		log.Printf("  eBPF instrumentation: enabled (context propagation, auto-instrumentation)")
	}
	if cfg.Pipelines.JFR.Enabled {
		log.Printf("  JFR profiling: enabled")
	}
	if cfg.Pipelines.Logs.Enabled {
		log.Printf("  Log collection: enabled")
	}

	mux := http.NewServeMux()
	st := selftelemetry.InstallHandlers(mux, cfg.SelfTelemetry.Listen)
	srv := &http.Server{Addr: cfg.SelfTelemetry.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("HTTP server listening on %s", cfg.SelfTelemetry.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())

	// Start node_exporter if enabled
	var nodeExp *nodeexporter.Exporter
	if cfg.NodeExporter.Enabled {
		var err error
		nodeExp, err = nodeexporter.New(cfg.NodeExporter)
		if err != nil {
			log.Fatalf("node_exporter: %v", err)
		}
		go func() {
			log.Printf("  node_exporter: enabled on :%d%s", cfg.NodeExporter.Endpoint.Port, cfg.NodeExporter.Endpoint.Path)
			if err := nodeExp.Run(ctx); err != nil && err != http.ErrServerClosed {
				log.Printf("node_exporter: %v", err)
			}
		}()
	}

	// Start kube_metrics if enabled or auto-detected
	// This provides kube-state-metrics + cAdvisor equivalent metrics natively
	kubeMetricsProvider := startKubeMetrics(ctx, cfg)

	pl := pipeline.New(cfg, st)
	if err := pl.Start(ctx); err != nil {
		log.Fatalf("start: %v", err)
	}

	// Wire up node_exporter OTLP streaming if enabled
	if nodeExp != nil && cfg.NodeExporter.Export.Enabled && cfg.NodeExporter.Export.UseOTLP {
		// Create a MetricsExporterInstancer for node exporter metrics
		// Uses the EBPF OTELMetrics config if available, or can be extended for standalone config
		if cfg.EBPF.OTELMetrics.EndpointEnabled() {
			meInstancer := &otelcfg.MetricsExporterInstancer{Cfg: &cfg.EBPF.OTELMetrics}
			exporter, err := meInstancer.Instantiate(ctx)
			if err != nil {
				log.Printf("node_exporter: failed to create OTLP exporter: %v", err)
			} else {
				if err := nodeExp.ConfigureOTLPStreaming(ctx, exporter); err != nil {
					log.Printf("node_exporter: failed to configure OTLP streaming: %v", err)
				} else {
					log.Printf("  node_exporter: OTLP streaming enabled (interval: %s)", cfg.NodeExporter.Export.Interval)
				}
			}
		} else {
			log.Printf("  node_exporter: OTLP streaming configured but no OTEL endpoint available")
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Println("telegen: shutting down…")
	cancel()
	pl.Close()
	if nodeExp != nil {
		_ = nodeExp.Shutdown(context.Background())
	}
	if kubeMetricsProvider != nil {
		_ = kubeMetricsProvider.Stop(context.Background())
	}
	_ = srv.Shutdown(context.Background())
}

// startKubeMetrics initializes and starts the kubemetrics provider if enabled or auto-detected.
// Returns nil if kubemetrics is disabled or if running outside a Kubernetes cluster without explicit config.
func startKubeMetrics(ctx context.Context, cfg *config.Config) *kubemetrics.Provider {
	// Create a structured logger for kubemetrics
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "kubemetrics")

	// Check if we should auto-enable based on Kubernetes detection
	inCluster := kubemetrics.IsInCluster()

	// Determine if we should start kubemetrics
	shouldStart := cfg.KubeMetrics.ShouldAutoEnable(inCluster)
	if !shouldStart {
		if cfg.KubeMetrics.AutoDetect {
			log.Printf("  kube_metrics: auto-detect enabled but not running in Kubernetes cluster")
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
	provider, err := kubemetrics.NewFromAgentConfig(agentCfg, logger)
	if err != nil {
		log.Printf("kube_metrics: failed to create provider: %v", err)
		return nil
	}
	if provider == nil {
		// Not an error, just not enabled
		return nil
	}

	// Start the provider (HTTP server + collectors)
	if err := provider.Start(ctx); err != nil {
		log.Printf("kube_metrics: failed to start: %v", err)
		return nil
	}

	log.Printf("  kube_metrics: enabled on %s%s (kubestate=%v, cadvisor=%v)",
		cfg.KubeMetrics.ListenAddress,
		cfg.KubeMetrics.MetricsPath,
		cfg.KubeMetrics.KubeState.Enabled,
		cfg.KubeMetrics.Cadvisor.Enabled,
	)

	// Configure OTLP streaming if enabled
	if cfg.KubeMetrics.Streaming.Enabled && cfg.KubeMetrics.Streaming.UseOTLP {
		configureKubeMetricsStreaming(ctx, provider, cfg, logger)
	}

	return provider
}

// configureKubeMetricsStreaming sets up OTLP streaming for kubemetrics
func configureKubeMetricsStreaming(ctx context.Context, provider *kubemetrics.Provider, cfg *config.Config, logger *slog.Logger) {
	// Use the same OTLP endpoint as eBPF metrics
	if !cfg.EBPF.OTELMetrics.EndpointEnabled() {
		log.Printf("  kube_metrics: OTLP streaming configured but no OTEL endpoint available")
		return
	}

	// Create metrics exporter
	meInstancer := &otelcfg.MetricsExporterInstancer{Cfg: &cfg.EBPF.OTELMetrics}
	metricsExporter, err := meInstancer.Instantiate(ctx)
	if err != nil {
		log.Printf("kube_metrics: failed to create OTLP metrics exporter: %v", err)
		return
	}

	// Get the Kubernetes client for logs streaming (events watching)
	kubeClient := provider.GetKubernetesClient()

	// Setup streaming - logs exporter is nil for now (can be added when OTLP logs are configured)
	if err := provider.SetupStreaming(metricsExporter, nil, kubeClient); err != nil {
		log.Printf("kube_metrics: failed to configure OTLP streaming: %v", err)
		return
	}

	log.Printf("  kube_metrics: OTLP streaming enabled (interval: %s)", cfg.KubeMetrics.Streaming.Interval)
}
