// Package adapters provides bridges between V2 collectors and the V3 unified pipeline.
// Each adapter wraps a V2 collector's output and converts it to the Signal interface
// for routing through the UnifiedExporter.
package adapters

import (
	"context"
	"sync"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// CollectorType identifies the type of collector.
type CollectorType string

const (
	// Agent mode collectors.
	CollectorEBPFTraces   CollectorType = "ebpf_traces"
	CollectorEBPFProfiling CollectorType = "ebpf_profiling"
	CollectorJFRProfiling  CollectorType = "jfr_profiling"
	CollectorFileLogs      CollectorType = "file_logs"
	CollectorHostMetrics   CollectorType = "host_metrics"
	CollectorKubeMetrics   CollectorType = "kube_metrics"
	CollectorNetworkFlows  CollectorType = "network_flows"

	// V2 recent features.
	CollectorKafkaLogs       CollectorType = "kafka_logs"
	CollectorSecurity        CollectorType = "security"
	CollectorGPU             CollectorType = "gpu"
	CollectorDatabaseTracing CollectorType = "database_tracing"
	CollectorLogTrace        CollectorType = "log_trace_correlation"
)

// SignalSink receives signals from collectors and routes them to the unified exporter.
type SignalSink interface {
	// SendTraces sends trace data to the pipeline.
	SendTraces(ctx context.Context, traces ptrace.Traces) error
	// SendLogs sends log data to the pipeline.
	SendLogs(ctx context.Context, logs plog.Logs) error
	// SendMetrics sends metric data to the pipeline.
	SendMetrics(ctx context.Context, metrics pmetric.Metrics) error
}

// CollectorAdapter adapts a V2 collector to the V3 unified pipeline.
type CollectorAdapter interface {
	// Type returns the collector type.
	Type() CollectorType
	// Name returns a human-readable name.
	Name() string
	// Start starts the collector adapter.
	Start(ctx context.Context, sink SignalSink) error
	// Stop stops the collector adapter.
	Stop(ctx context.Context) error
	// IsRunning returns whether the adapter is running.
	IsRunning() bool
}

// AdapterRegistry manages all collector adapters.
type AdapterRegistry struct {
	mu       sync.RWMutex
	adapters map[CollectorType]CollectorAdapter
	sink     SignalSink
}

// NewAdapterRegistry creates a new adapter registry.
func NewAdapterRegistry(sink SignalSink) *AdapterRegistry {
	return &AdapterRegistry{
		adapters: make(map[CollectorType]CollectorAdapter),
		sink:     sink,
	}
}

// Register registers a collector adapter.
func (r *AdapterRegistry) Register(adapter CollectorAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[adapter.Type()] = adapter
}

// Get returns a collector adapter by type.
func (r *AdapterRegistry) Get(t CollectorType) (CollectorAdapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	adapter, ok := r.adapters[t]
	return adapter, ok
}

// StartAll starts all registered adapters.
func (r *AdapterRegistry) StartAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, adapter := range r.adapters {
		if err := adapter.Start(ctx, r.sink); err != nil {
			return err
		}
	}
	return nil
}

// StopAll stops all registered adapters.
func (r *AdapterRegistry) StopAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, adapter := range r.adapters {
		if err := adapter.Stop(ctx); err != nil {
			return err
		}
	}
	return nil
}

// List returns all registered adapter types.
func (r *AdapterRegistry) List() []CollectorType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]CollectorType, 0, len(r.adapters))
	for t := range r.adapters {
		types = append(types, t)
	}
	return types
}
