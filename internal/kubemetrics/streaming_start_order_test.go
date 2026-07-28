// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/mirastacklabs-ai/telegen/internal/kubestate"
)

// TestSetupStreamingAfterStartStillExports reproduces the production bug where
// startKubeMetrics called Provider.Start BEFORE SetupStreaming, so the metrics
// streamer was created too late and its export loop never launched
// (kubemetrics_streaming_exports_total stayed 0, no kube_* in VictoriaMetrics).
//
// With the start-order-independent Provider (SetupStreaming auto-starts a
// late-created streamer), an export must occur even in this buggy call order.
func TestSetupStreamingAfterStartStillExports(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddress = "127.0.0.1:0" // ephemeral port, avoid conflicts
	cfg.Streaming.Enabled = true
	cfg.Streaming.UseOTLP = true
	cfg.Streaming.Interval = 20 * time.Millisecond
	cfg.Streaming.IncludeSignalMetadata = false
	cfg.KubeState.Resources = []string{}

	logger := slog.Default()

	// Inject a kubestate backed by a fake clientset so collectResourceMetrics
	// enters the kubestate branch. The self-telemetry metric guarantees at
	// least one metric per collection, so Export is called regardless of
	// whether any kube_* series exist.
	ks, err := kubestate.NewWithClientset(&cfg.KubeState, fake.NewSimpleClientset(), logger)
	if err != nil {
		t.Fatalf("kubestate.NewWithClientset: %v", err)
	}

	p := &Provider{config: cfg, logger: logger}
	p.kubestate = ks

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// BUGGY ORDER ON PURPOSE: Start first, then SetupStreaming.
	if err := p.Start(ctx); err != nil {
		t.Fatalf("provider.Start: %v", err)
	}
	defer func() { _ = p.Stop(context.Background()) }()

	exp := &MockMetricsExporter{}
	if err := p.SetupStreaming(exp, nil, nil); err != nil {
		t.Fatalf("provider.SetupStreaming: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if exp.Count() > 0 {
			return // success: streamer ran and exported
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected >=1 export after SetupStreaming-following-Start, got 0 (regression: streamer loop not started)")
}

// TestSetupStreamingBeforeStartExports covers the fixed main.go order:
// SetupStreaming first, then Start.
func TestSetupStreamingBeforeStartExports(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.Streaming.Enabled = true
	cfg.Streaming.UseOTLP = true
	cfg.Streaming.Interval = 20 * time.Millisecond
	cfg.Streaming.IncludeSignalMetadata = false
	cfg.KubeState.Resources = []string{}

	logger := slog.Default()
	ks, err := kubestate.NewWithClientset(&cfg.KubeState, fake.NewSimpleClientset(), logger)
	if err != nil {
		t.Fatalf("kubestate.NewWithClientset: %v", err)
	}

	p := &Provider{config: cfg, logger: logger}
	p.kubestate = ks

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exp := &MockMetricsExporter{}
	if err := p.SetupStreaming(exp, nil, nil); err != nil {
		t.Fatalf("provider.SetupStreaming: %v", err)
	}
	if err := p.Start(ctx); err != nil {
		t.Fatalf("provider.Start: %v", err)
	}
	defer func() { _ = p.Stop(context.Background()) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if exp.Count() > 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected >=1 export in correct order, got 0")
}
