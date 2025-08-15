package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/platformbuilds/telegen/internal/config"
	"github.com/platformbuilds/telegen/internal/pipeline"
	"github.com/platformbuilds/telegen/internal/selftelemetry"
	"github.com/platformbuilds/telegen/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/telegen/config.yaml", "path to config yaml")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	mux := http.NewServeMux()
	st := selftelemetry.InstallHandlers(mux, cfg.SelfTelemetry.Listen)
	srv := &http.Server{Addr: cfg.SelfTelemetry.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("telegen %s starting HTTP on %s", version.Version(), cfg.SelfTelemetry.Listen)
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
