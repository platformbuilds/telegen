package enrichment

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestEnrichmentPipelineCreation(t *testing.T) {
	config := DefaultEnricherConfig()
	pipeline, err := NewEnrichmentPipeline(config, nil)
	if err != nil {
		t.Fatalf("NewEnrichmentPipeline failed: %v", err)
	}

	names := pipeline.EnricherNames()
	if len(names) != 3 {
		t.Errorf("expected 3 enrichers, got %d", len(names))
	}

	// Check expected enrichers are registered.
	expectedEnrichers := map[string]bool{"cloud": false, "kubernetes": false, "host": false}
	for _, name := range names {
		expectedEnrichers[name] = true
	}
	for name, found := range expectedEnrichers {
		if !found {
			t.Errorf("enricher %s not found", name)
		}
	}
}

func TestEnrichmentPipelineDisabledEnrichers(t *testing.T) {
	config := DefaultEnricherConfig()
	config.Cloud.Enabled = false
	config.Kubernetes.Enabled = false
	// Host still enabled.

	pipeline, err := NewEnrichmentPipeline(config, nil)
	if err != nil {
		t.Fatalf("NewEnrichmentPipeline failed: %v", err)
	}

	names := pipeline.EnricherNames()
	if len(names) != 1 {
		t.Errorf("expected 1 enricher (host), got %d", len(names))
	}
}

func TestHostEnricher(t *testing.T) {
	config := HostEnricherConfig{
		Enabled:        true,
		IncludeOS:      true,
		IncludeNetwork: false,
	}

	enricher := NewHostEnricher(config, nil)
	
	if enricher.Name() != "host" {
		t.Errorf("expected name 'host', got %s", enricher.Name())
	}

	ctx := context.Background()
	if err := enricher.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	metadata := enricher.GetMetadata()
	if metadata == nil {
		t.Fatal("metadata should not be nil")
	}

	if metadata.Hostname == "" {
		t.Error("hostname should not be empty")
	}
	if metadata.CPUCount == 0 {
		t.Error("cpu count should not be 0")
	}
	if metadata.Arch == "" {
		t.Error("arch should not be empty")
	}

	// Test enrichment.
	resource := pcommon.NewResource()
	if err := enricher.Enrich(ctx, resource); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	attrs := resource.Attributes()
	
	if _, ok := attrs.Get("host.name"); !ok {
		t.Error("host.name attribute missing")
	}
	if _, ok := attrs.Get("host.arch"); !ok {
		t.Error("host.arch attribute missing")
	}

	if err := enricher.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestK8sEnricherNotInK8s(t *testing.T) {
	config := K8sEnricherConfig{
		Enabled:   true,
		InCluster: true,
	}

	enricher := NewK8sEnricher(config, nil)
	
	if enricher.Name() != "kubernetes" {
		t.Errorf("expected name 'kubernetes', got %s", enricher.Name())
	}

	ctx := context.Background()
	if err := enricher.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Should not fail even if not in K8s.
	resource := pcommon.NewResource()
	if err := enricher.Enrich(ctx, resource); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if err := enricher.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestCloudEnricherNoCloud(t *testing.T) {
	config := CloudEnricherConfig{
		Enabled: true,
		Timeout: 100 * time.Millisecond, // Short timeout for test.
	}

	enricher := NewCloudEnricher(config, nil)
	
	if enricher.Name() != "cloud" {
		t.Errorf("expected name 'cloud', got %s", enricher.Name())
	}

	ctx := context.Background()
	// Should not fail even if no cloud detected.
	if err := enricher.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// No cloud, so no metadata.
	if enricher.IsDetected() {
		t.Log("cloud detected (running in cloud environment)")
	}

	// Should not fail even with no metadata.
	resource := pcommon.NewResource()
	if err := enricher.Enrich(ctx, resource); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if err := enricher.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestEnrichmentPipelineStartStop(t *testing.T) {
	config := DefaultEnricherConfig()
	config.Cloud.Timeout = 100 * time.Millisecond // Short timeout.

	pipeline, err := NewEnrichmentPipeline(config, nil)
	if err != nil {
		t.Fatalf("NewEnrichmentPipeline failed: %v", err)
	}

	if err := pipeline.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Test enrichment.
	ctx := context.Background()
	resource := pcommon.NewResource()
	if err := pipeline.Enrich(ctx, resource); err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	// Host enrichment should have added attributes.
	attrs := resource.Attributes()
	if _, ok := attrs.Get("host.name"); !ok {
		t.Error("host.name attribute missing after pipeline enrichment")
	}

	if err := pipeline.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestAddCustomEnricher(t *testing.T) {
	config := DefaultEnricherConfig()
	config.Cloud.Enabled = false
	config.Kubernetes.Enabled = false
	config.Host.Enabled = false

	pipeline, err := NewEnrichmentPipeline(config, nil)
	if err != nil {
		t.Fatalf("NewEnrichmentPipeline failed: %v", err)
	}

	if len(pipeline.EnricherNames()) != 0 {
		t.Error("expected 0 enrichers")
	}

	// Add custom enricher.
	custom := &customTestEnricher{name: "custom"}
	pipeline.AddEnricher(custom)

	if len(pipeline.EnricherNames()) != 1 {
		t.Error("expected 1 enricher after adding custom")
	}
}

type customTestEnricher struct {
	name string
}

func (c *customTestEnricher) Name() string { return c.name }
func (c *customTestEnricher) Start(ctx context.Context) error { return nil }
func (c *customTestEnricher) Stop() error { return nil }
func (c *customTestEnricher) Enrich(ctx context.Context, resource pcommon.Resource) error {
	resource.Attributes().PutStr("custom.attribute", "test")
	return nil
}

func TestDefaultEnricherConfig(t *testing.T) {
	config := DefaultEnricherConfig()

	if !config.Enabled {
		t.Error("expected enabled by default")
	}
	if !config.Cloud.Enabled {
		t.Error("expected cloud enabled by default")
	}
	if !config.Kubernetes.Enabled {
		t.Error("expected kubernetes enabled by default")
	}
	if !config.Host.Enabled {
		t.Error("expected host enabled by default")
	}
	if config.CacheTTL != 5*time.Minute {
		t.Errorf("expected cache TTL 5m, got %v", config.CacheTTL)
	}
}
