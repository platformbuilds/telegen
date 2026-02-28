package adapters

import (
	"context"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// BaseAdapter provides common functionality for all collector adapters.
type BaseAdapter struct {
	collectorType CollectorType
	name          string
	running       atomic.Bool
	mu            sync.Mutex
	sink          SignalSink
	stopCh        chan struct{}
}

// NewBaseAdapter creates a new base adapter.
func NewBaseAdapter(collectorType CollectorType, name string) *BaseAdapter {
	return &BaseAdapter{
		collectorType: collectorType,
		name:          name,
	}
}

// Type returns the collector type.
func (a *BaseAdapter) Type() CollectorType {
	return a.collectorType
}

// Name returns a human-readable name.
func (a *BaseAdapter) Name() string {
	return a.name
}

// IsRunning returns whether the adapter is running.
func (a *BaseAdapter) IsRunning() bool {
	return a.running.Load()
}

// startBase initializes the base adapter.
func (a *BaseAdapter) startBase(sink SignalSink) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sink = sink
	a.stopCh = make(chan struct{})
	a.running.Store(true)
}

// stopBase stops the base adapter.
func (a *BaseAdapter) stopBase() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopCh != nil {
		close(a.stopCh)
	}
	a.running.Store(false)
}

// Sink returns the signal sink.
func (a *BaseAdapter) Sink() SignalSink {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sink
}

// StopCh returns the stop channel.
func (a *BaseAdapter) StopCh() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopCh
}

// EBPFTracesAdapter adapts V2 eBPF traces to the unified pipeline.
type EBPFTracesAdapter struct {
	*BaseAdapter
}

// NewEBPFTracesAdapter creates a new eBPF traces adapter.
func NewEBPFTracesAdapter() *EBPFTracesAdapter {
	return &EBPFTracesAdapter{
		BaseAdapter: NewBaseAdapter(CollectorEBPFTraces, "eBPF Traces"),
	}
}

// Start starts the eBPF traces adapter.
func (a *EBPFTracesAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	// V2 tracer integration point:
	// The existing V2 tracer calls Export(spans) which goes to p.ot.CollectorTraces.
	// We intercept by registering this adapter as the trace sink.
	return nil
}

// Stop stops the eBPF traces adapter.
func (a *EBPFTracesAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnTraces receives traces from V2 tracer and forwards to unified pipeline.
func (a *EBPFTracesAdapter) OnTraces(ctx context.Context, traces ptrace.Traces) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendTraces(ctx, traces)
}

// EBPFProfilingAdapter adapts V2 eBPF profiling to the unified pipeline.
type EBPFProfilingAdapter struct {
	*BaseAdapter
}

// NewEBPFProfilingAdapter creates a new eBPF profiling adapter.
func NewEBPFProfilingAdapter() *EBPFProfilingAdapter {
	return &EBPFProfilingAdapter{
		BaseAdapter: NewBaseAdapter(CollectorEBPFProfiling, "eBPF Profiling"),
	}
}

// Start starts the eBPF profiling adapter.
func (a *EBPFProfilingAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	return nil
}

// Stop stops the eBPF profiling adapter.
func (a *EBPFProfilingAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnProfiles receives profiles from V2 profiler and forwards as logs.
func (a *EBPFProfilingAdapter) OnProfiles(ctx context.Context, profiles plog.Logs) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendLogs(ctx, profiles)
}

// OnProfileMetrics receives profile metrics and forwards to pipeline.
func (a *EBPFProfilingAdapter) OnProfileMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendMetrics(ctx, metrics)
}

// JFRProfilingAdapter adapts V2 JFR profiling to the unified pipeline.
type JFRProfilingAdapter struct {
	*BaseAdapter
}

// NewJFRProfilingAdapter creates a new JFR profiling adapter.
func NewJFRProfilingAdapter() *JFRProfilingAdapter {
	return &JFRProfilingAdapter{
		BaseAdapter: NewBaseAdapter(CollectorJFRProfiling, "JFR Profiling"),
	}
}

// Start starts the JFR profiling adapter.
func (a *JFRProfilingAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	return nil
}

// Stop stops the JFR profiling adapter.
func (a *JFRProfilingAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnJFREvents receives JFR events from V2 parser and forwards as logs.
func (a *JFRProfilingAdapter) OnJFREvents(ctx context.Context, events plog.Logs) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendLogs(ctx, events)
}

// FileLogsAdapter adapts V2 file log tailing to the unified pipeline.
type FileLogsAdapter struct {
	*BaseAdapter
}

// NewFileLogsAdapter creates a new file logs adapter.
func NewFileLogsAdapter() *FileLogsAdapter {
	return &FileLogsAdapter{
		BaseAdapter: NewBaseAdapter(CollectorFileLogs, "File Logs"),
	}
}

// Start starts the file logs adapter.
func (a *FileLogsAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	return nil
}

// Stop stops the file logs adapter.
func (a *FileLogsAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnLogs receives logs from V2 file tailer and forwards to pipeline.
func (a *FileLogsAdapter) OnLogs(ctx context.Context, logs plog.Logs) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendLogs(ctx, logs)
}

// HostMetricsAdapter adapts V2 host metrics to the unified pipeline.
type HostMetricsAdapter struct {
	*BaseAdapter
}

// NewHostMetricsAdapter creates a new host metrics adapter.
func NewHostMetricsAdapter() *HostMetricsAdapter {
	return &HostMetricsAdapter{
		BaseAdapter: NewBaseAdapter(CollectorHostMetrics, "Host Metrics"),
	}
}

// Start starts the host metrics adapter.
func (a *HostMetricsAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	return nil
}

// Stop stops the host metrics adapter.
func (a *HostMetricsAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnMetrics receives metrics from V2 node_exporter and forwards to pipeline.
func (a *HostMetricsAdapter) OnMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendMetrics(ctx, metrics)
}

// KubeMetricsAdapter adapts V2 Kubernetes metrics to the unified pipeline.
type KubeMetricsAdapter struct {
	*BaseAdapter
}

// NewKubeMetricsAdapter creates a new Kubernetes metrics adapter.
func NewKubeMetricsAdapter() *KubeMetricsAdapter {
	return &KubeMetricsAdapter{
		BaseAdapter: NewBaseAdapter(CollectorKubeMetrics, "Kubernetes Metrics"),
	}
}

// Start starts the Kubernetes metrics adapter.
func (a *KubeMetricsAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	return nil
}

// Stop stops the Kubernetes metrics adapter.
func (a *KubeMetricsAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnMetrics receives metrics from V2 kube-state-metrics and forwards to pipeline.
func (a *KubeMetricsAdapter) OnMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendMetrics(ctx, metrics)
}

// NetworkFlowsAdapter adapts V2 network flow data to the unified pipeline.
type NetworkFlowsAdapter struct {
	*BaseAdapter
}

// NewNetworkFlowsAdapter creates a new network flows adapter.
func NewNetworkFlowsAdapter() *NetworkFlowsAdapter {
	return &NetworkFlowsAdapter{
		BaseAdapter: NewBaseAdapter(CollectorNetworkFlows, "Network Flows"),
	}
}

// Start starts the network flows adapter.
func (a *NetworkFlowsAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	return nil
}

// Stop stops the network flows adapter.
func (a *NetworkFlowsAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnFlows receives flow data from V2 netolly and forwards as logs.
func (a *NetworkFlowsAdapter) OnFlows(ctx context.Context, flows plog.Logs) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendLogs(ctx, flows)
}

// OnFlowMetrics receives flow metrics and forwards to pipeline.
func (a *NetworkFlowsAdapter) OnFlowMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendMetrics(ctx, metrics)
}
