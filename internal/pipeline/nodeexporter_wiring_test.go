package pipeline

import (
	"context"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/config"
)

func TestStartRuntimeSources_UsesNodeExporterWhenEnabled(t *testing.T) {
	t.Parallel()

	p, err := NewUnifiedPipeline(DefaultUnifiedPipelineConfig())
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer p.cancel()
	defer close(p.stopCh)

	runtimeCfg := &config.Config{}
	runtimeCfg.NodeExporter.Enabled = true
	runtimeCfg.NodeExporter.Export.Enabled = true
	p.config.RuntimeConfig = runtimeCfg

	if err := p.startRuntimeSources(context.Background()); err != nil {
		t.Fatalf("startRuntimeSources failed: %v", err)
	}
	if p.nodeExp == nil {
		t.Fatal("expected node exporter to be initialized")
	}
}

func TestStartRuntimeSources_FallsBackWhenNodeExporterDisabled(t *testing.T) {
	t.Parallel()

	p, err := NewUnifiedPipeline(DefaultUnifiedPipelineConfig())
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer p.cancel()
	defer close(p.stopCh)

	runtimeCfg := &config.Config{}
	runtimeCfg.NodeExporter.Enabled = false
	runtimeCfg.Exports.RemoteWrite.Endpoints = []config.RWEndpoint{
		{URL: "http://example.invalid/api/v1/write"},
	}
	p.config.RuntimeConfig = runtimeCfg

	if err := p.startRuntimeSources(context.Background()); err != nil {
		t.Fatalf("startRuntimeSources failed: %v", err)
	}
	if p.nodeExp != nil {
		t.Fatal("expected node exporter to remain nil when disabled")
	}
}
