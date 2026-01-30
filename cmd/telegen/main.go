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
	"github.com/platformbuilds/telegen/internal/pipeline"
	"github.com/platformbuilds/telegen/internal/selftelemetry"
	"github.com/platformbuilds/telegen/internal/version"
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
	pl := pipeline.New(cfg, st)
	if err := pl.Start(ctx); err != nil {
		log.Fatalf("start: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Println("telegen: shutting down…")
	cancel()
	pl.Close()
	_ = srv.Shutdown(context.Background())
}
