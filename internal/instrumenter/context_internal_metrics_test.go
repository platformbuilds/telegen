package instrumenter

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mirastacklabs-ai/telegen/internal/obi"
	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
)

// Regression guard for the agent crash "panic: duplicate metrics collector registration
// attempted". startEBPFSource used to build the ContextInfo twice against one *obi.Config,
// so the shared registry received the internal-metrics collectors twice.
func TestBuildCommonContextInfoWithExporter_TwiceWithSharedRegistryDoesNotPanic(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	cfg := obi.DefaultConfig
	// Override the host ID so the builder does not probe live cloud metadata endpoints.
	cfg.Attributes.HostID.Override = "test-host"
	cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
	cfg.InternalMetrics.Prometheus.Port = 0
	cfg.InternalMetrics.Registry = reg

	firstCtxInfo, err := BuildCommonContextInfoWithExporter(context.Background(), &cfg, nil, nil)
	if err != nil {
		t.Fatalf("first build failed: %v", err)
	}
	if firstCtxInfo == nil {
		t.Fatal("first build returned nil context info")
	}

	secondCtxInfo, err := BuildCommonContextInfoWithExporter(context.Background(), &cfg, nil, nil)
	if err != nil {
		t.Fatalf("second build failed: %v", err)
	}
	if secondCtxInfo == nil {
		t.Fatal("second build returned nil context info")
	}
}
