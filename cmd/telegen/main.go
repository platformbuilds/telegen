package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/platformbuilds/telegen/internal/config"
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
	_ = srv.Shutdown(context.Background())
}
