// Package collector provides adapters for wiring V2 collectors to the V3 unified export pipeline.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

// Adapter is the interface for collector mode adapters that bridge V2 collectors
// to the V3 unified export pipeline.
type Adapter interface {
	// Name returns the adapter name for identification and logging.
	Name() string

	// Start begins collecting and forwarding metrics.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the adapter.
	Stop(ctx context.Context) error

	// Health returns the adapter's health status.
	Health() AdapterHealth
}

// AdapterHealth represents the health status of a collector adapter.
type AdapterHealth struct {
	Name            string            `json:"name"`
	Status          string            `json:"status"` // "healthy", "degraded", "unhealthy"
	LastCollection  time.Time         `json:"last_collection"`
	CollectionCount int64             `json:"collection_count"`
	ErrorCount      int64             `json:"error_count"`
	LastError       string            `json:"last_error,omitempty"`
	Targets         map[string]string `json:"targets,omitempty"` // target -> status
}

// MetricSink is the interface for sending metrics to the unified exporter.
type MetricSink interface {
	// SendMetrics sends metrics to the unified export pipeline.
	SendMetrics(ctx context.Context, metrics pmetric.Metrics) error
}

// AdapterConfig is the base configuration for all collector adapters.
type AdapterConfig struct {
	// Enabled controls whether this adapter is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CollectInterval is how often to collect metrics.
	CollectInterval time.Duration `yaml:"collect_interval" json:"collect_interval"`

	// Timeout for collection operations.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// RetryCount is the number of collection retries.
	RetryCount int `yaml:"retry_count" json:"retry_count"`

	// RetryInterval is the interval between retries.
	RetryInterval time.Duration `yaml:"retry_interval" json:"retry_interval"`
}

// DefaultAdapterConfig returns sensible defaults.
func DefaultAdapterConfig() AdapterConfig {
	return AdapterConfig{
		Enabled:         true,
		CollectInterval: 60 * time.Second,
		Timeout:         30 * time.Second,
		RetryCount:      3,
		RetryInterval:   5 * time.Second,
	}
}

// AdapterRegistry manages all collector adapters.
type AdapterRegistry struct {
	adapters map[string]Adapter
	sink     MetricSink
	log      *slog.Logger
	mu       sync.RWMutex
	running  bool
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewAdapterRegistry creates a new adapter registry.
func NewAdapterRegistry(sink MetricSink, log *slog.Logger) *AdapterRegistry {
	if log == nil {
		log = slog.Default()
	}
	return &AdapterRegistry{
		adapters: make(map[string]Adapter),
		sink:     sink,
		log:      log.With("component", "adapter-registry"),
	}
}

// Register adds an adapter to the registry.
func (r *AdapterRegistry) Register(adapter Adapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := adapter.Name()
	if _, exists := r.adapters[name]; exists {
		return fmt.Errorf("adapter %s already registered", name)
	}

	r.adapters[name] = adapter
	r.log.Info("registered adapter", "name", name)
	return nil
}

// Start starts all registered adapters.
func (r *AdapterRegistry) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return nil
	}

	r.ctx, r.cancel = context.WithCancel(ctx)
	r.running = true

	var startErrors []error
	for name, adapter := range r.adapters {
		r.wg.Add(1)
		go func(name string, a Adapter) {
			defer r.wg.Done()
			if err := a.Start(r.ctx); err != nil {
				r.log.Error("failed to start adapter", "name", name, "error", err)
			}
		}(name, adapter)
	}

	if len(startErrors) > 0 {
		r.log.Warn("some adapters failed to start", "count", len(startErrors))
	}

	r.log.Info("started adapter registry", "adapter_count", len(r.adapters))
	return nil
}

// Stop stops all registered adapters.
func (r *AdapterRegistry) Stop(ctx context.Context) error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	r.cancel()
	r.running = false
	r.mu.Unlock()

	// Stop all adapters in parallel
	var stopWg sync.WaitGroup
	for name, adapter := range r.adapters {
		stopWg.Add(1)
		go func(name string, a Adapter) {
			defer stopWg.Done()
			if err := a.Stop(ctx); err != nil {
				r.log.Error("failed to stop adapter", "name", name, "error", err)
			}
		}(name, adapter)
	}
	stopWg.Wait()

	r.wg.Wait()
	r.log.Info("stopped adapter registry")
	return nil
}

// Health returns health status for all adapters.
func (r *AdapterRegistry) Health() map[string]AdapterHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()

	health := make(map[string]AdapterHealth)
	for name, adapter := range r.adapters {
		health[name] = adapter.Health()
	}
	return health
}

// Get returns an adapter by name.
func (r *AdapterRegistry) Get(name string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	adapter, ok := r.adapters[name]
	return adapter, ok
}

// List returns all adapter names.
func (r *AdapterRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.adapters))
	for name := range r.adapters {
		names = append(names, name)
	}
	return names
}
