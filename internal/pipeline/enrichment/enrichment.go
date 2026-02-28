// Package enrichment provides metadata enrichment for V3 pipeline signals.
package enrichment

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Enricher is the interface for all metadata enrichers.
type Enricher interface {
	// Name returns the enricher name.
	Name() string
	// Enrich adds metadata to the resource attributes.
	Enrich(ctx context.Context, resource pcommon.Resource) error
	// Start starts the enricher (for caching, watchers, etc.).
	Start(ctx context.Context) error
	// Stop stops the enricher.
	Stop() error
}

// EnricherConfig configures the enrichment pipeline.
type EnricherConfig struct {
	// Enabled enables metadata enrichment.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Cloud configures cloud metadata enrichment.
	Cloud CloudEnricherConfig `yaml:"cloud" json:"cloud"`
	// Kubernetes configures K8s metadata enrichment.
	Kubernetes K8sEnricherConfig `yaml:"kubernetes" json:"kubernetes"`
	// Host configures host metadata enrichment.
	Host HostEnricherConfig `yaml:"host" json:"host"`
	// CacheTTL is the metadata cache TTL.
	CacheTTL time.Duration `yaml:"cache_ttl" json:"cache_ttl"`
	// RefreshInterval is the interval to refresh metadata.
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`
}

// CloudEnricherConfig configures cloud metadata enrichment.
type CloudEnricherConfig struct {
	// Enabled enables cloud metadata enrichment.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Provider forces a specific cloud provider (auto-detect if empty).
	Provider string `yaml:"provider" json:"provider"`
	// Timeout for cloud metadata requests.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
}

// K8sEnricherConfig configures Kubernetes metadata enrichment.
type K8sEnricherConfig struct {
	// Enabled enables K8s metadata enrichment.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// InCluster uses in-cluster config.
	InCluster bool `yaml:"in_cluster" json:"in_cluster"`
	// Kubeconfig path (for out-of-cluster).
	Kubeconfig string `yaml:"kubeconfig" json:"kubeconfig"`
}

// HostEnricherConfig configures host metadata enrichment.
type HostEnricherConfig struct {
	// Enabled enables host metadata enrichment.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// IncludeOS includes OS details.
	IncludeOS bool `yaml:"include_os" json:"include_os"`
	// IncludeNetwork includes network interface info.
	IncludeNetwork bool `yaml:"include_network" json:"include_network"`
}

// DefaultEnricherConfig returns reasonable defaults.
func DefaultEnricherConfig() EnricherConfig {
	return EnricherConfig{
		Enabled: true,
		Cloud: CloudEnricherConfig{
			Enabled: true,
			Timeout: 2 * time.Second,
		},
		Kubernetes: K8sEnricherConfig{
			Enabled:   true,
			InCluster: true,
		},
		Host: HostEnricherConfig{
			Enabled:        true,
			IncludeOS:      true,
			IncludeNetwork: false,
		},
		CacheTTL:        5 * time.Minute,
		RefreshInterval: 1 * time.Minute,
	}
}

// EnrichmentPipeline manages all enrichers.
type EnrichmentPipeline struct {
	config    EnricherConfig
	logger    *slog.Logger
	enrichers []Enricher
	mu        sync.RWMutex
	running   bool
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewEnrichmentPipeline creates a new enrichment pipeline.
func NewEnrichmentPipeline(config EnricherConfig, logger *slog.Logger) (*EnrichmentPipeline, error) {
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	ep := &EnrichmentPipeline{
		config:    config,
		logger:    logger,
		enrichers: make([]Enricher, 0),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Register enrichers based on config.
	if config.Cloud.Enabled {
		cloudEnricher := NewCloudEnricher(config.Cloud, logger)
		ep.enrichers = append(ep.enrichers, cloudEnricher)
	}

	if config.Kubernetes.Enabled {
		k8sEnricher := NewK8sEnricher(config.Kubernetes, logger)
		ep.enrichers = append(ep.enrichers, k8sEnricher)
	}

	if config.Host.Enabled {
		hostEnricher := NewHostEnricher(config.Host, logger)
		ep.enrichers = append(ep.enrichers, hostEnricher)
	}

	logger.Info("created enrichment pipeline",
		"enrichers", len(ep.enrichers),
		"cloud", config.Cloud.Enabled,
		"k8s", config.Kubernetes.Enabled,
		"host", config.Host.Enabled)

	return ep, nil
}

// Start starts all enrichers.
func (ep *EnrichmentPipeline) Start() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.running {
		return nil
	}

	for _, enricher := range ep.enrichers {
		if err := enricher.Start(ep.ctx); err != nil {
			ep.logger.Warn("failed to start enricher",
				"enricher", enricher.Name(),
				"error", err)
			// Continue with other enrichers.
		} else {
			ep.logger.Debug("started enricher", "enricher", enricher.Name())
		}
	}

	ep.running = true
	return nil
}

// Stop stops all enrichers.
func (ep *EnrichmentPipeline) Stop() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if !ep.running {
		return nil
	}

	ep.cancel()

	for _, enricher := range ep.enrichers {
		if err := enricher.Stop(); err != nil {
			ep.logger.Warn("failed to stop enricher",
				"enricher", enricher.Name(),
				"error", err)
		}
	}

	ep.running = false
	return nil
}

// Enrich applies all enrichers to the resource.
func (ep *EnrichmentPipeline) Enrich(ctx context.Context, resource pcommon.Resource) error {
	ep.mu.RLock()
	enrichers := ep.enrichers
	ep.mu.RUnlock()

	for _, enricher := range enrichers {
		if err := enricher.Enrich(ctx, resource); err != nil {
			ep.logger.Debug("enricher failed",
				"enricher", enricher.Name(),
				"error", err)
			// Continue with other enrichers.
		}
	}

	return nil
}

// AddEnricher adds a custom enricher.
func (ep *EnrichmentPipeline) AddEnricher(enricher Enricher) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.enrichers = append(ep.enrichers, enricher)
}

// EnricherNames returns the names of all registered enrichers.
func (ep *EnrichmentPipeline) EnricherNames() []string {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	names := make([]string, len(ep.enrichers))
	for i, e := range ep.enrichers {
		names[i] = e.Name()
	}
	return names
}
