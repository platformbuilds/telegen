package adapters

import (
	"context"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// KafkaLogsAdapter adapts V2 Kafka logs receiver to the unified pipeline.
type KafkaLogsAdapter struct {
	*BaseAdapter
}

// NewKafkaLogsAdapter creates a new Kafka logs adapter.
func NewKafkaLogsAdapter() *KafkaLogsAdapter {
	return &KafkaLogsAdapter{
		BaseAdapter: NewBaseAdapter(CollectorKafkaLogs, "Kafka Logs"),
	}
}

// Start starts the Kafka logs adapter.
func (a *KafkaLogsAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	// V2 Kafka receiver uses franz-go consumer.
	// Integration point: kafka.Consumer.OnMessage → this adapter.
	return nil
}

// Stop stops the Kafka logs adapter.
func (a *KafkaLogsAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnLogs receives logs from V2 Kafka consumer and forwards to pipeline.
func (a *KafkaLogsAdapter) OnLogs(ctx context.Context, logs plog.Logs) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendLogs(ctx, logs)
}

// SecurityAdapter adapts V2 security monitoring to the unified pipeline.
type SecurityAdapter struct {
	*BaseAdapter
}

// NewSecurityAdapter creates a new security adapter.
func NewSecurityAdapter() *SecurityAdapter {
	return &SecurityAdapter{
		BaseAdapter: NewBaseAdapter(CollectorSecurity, "Security Monitoring"),
	}
}

// Start starts the security adapter.
func (a *SecurityAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	// V2 security subsystem monitors:
	// - Syscalls (execve, ptrace, etc.)
	// - File integrity monitoring
	// - Container escape detection
	return nil
}

// Stop stops the security adapter.
func (a *SecurityAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnSecurityEvents receives security events from V2 and forwards as logs.
func (a *SecurityAdapter) OnSecurityEvents(ctx context.Context, events plog.Logs) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendLogs(ctx, events)
}

// OnSecurityMetrics receives security metrics and forwards to pipeline.
func (a *SecurityAdapter) OnSecurityMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendMetrics(ctx, metrics)
}

// GPUAdapter adapts V2 GPU/AI-ML tracing to the unified pipeline.
type GPUAdapter struct {
	*BaseAdapter
}

// NewGPUAdapter creates a new GPU adapter.
func NewGPUAdapter() *GPUAdapter {
	return &GPUAdapter{
		BaseAdapter: NewBaseAdapter(CollectorGPU, "GPU/AI-ML Tracing"),
	}
}

// Start starts the GPU adapter.
func (a *GPUAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	// V2 GPU tracer monitors:
	// - CUDA kernel launches
	// - LLM inference operations
	// - GPU memory allocations
	return nil
}

// Stop stops the GPU adapter.
func (a *GPUAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnGPUTraces receives GPU traces from V2 and forwards to pipeline.
func (a *GPUAdapter) OnGPUTraces(ctx context.Context, traces ptrace.Traces) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendTraces(ctx, traces)
}

// OnGPUMetrics receives GPU metrics and forwards to pipeline.
func (a *GPUAdapter) OnGPUMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendMetrics(ctx, metrics)
}

// DatabaseTracingAdapter adapts V2 database tracing to the unified pipeline.
type DatabaseTracingAdapter struct {
	*BaseAdapter
}

// NewDatabaseTracingAdapter creates a new database tracing adapter.
func NewDatabaseTracingAdapter() *DatabaseTracingAdapter {
	return &DatabaseTracingAdapter{
		BaseAdapter: NewBaseAdapter(CollectorDatabaseTracing, "Database Tracing"),
	}
}

// Start starts the database tracing adapter.
func (a *DatabaseTracingAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	// V2 database tracer monitors:
	// - MySQL, PostgreSQL, MongoDB queries via eBPF
	// - Query parsing and SQL pruning
	return nil
}

// Stop stops the database tracing adapter.
func (a *DatabaseTracingAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnDatabaseTraces receives database traces from V2 and forwards to pipeline.
func (a *DatabaseTracingAdapter) OnDatabaseTraces(ctx context.Context, traces ptrace.Traces) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendTraces(ctx, traces)
}

// LogTraceCorrelationAdapter adapts V2 log-trace correlation to the unified pipeline.
type LogTraceCorrelationAdapter struct {
	*BaseAdapter
}

// NewLogTraceCorrelationAdapter creates a new log-trace correlation adapter.
func NewLogTraceCorrelationAdapter() *LogTraceCorrelationAdapter {
	return &LogTraceCorrelationAdapter{
		BaseAdapter: NewBaseAdapter(CollectorLogTrace, "Log-Trace Correlation"),
	}
}

// Start starts the log-trace correlation adapter.
func (a *LogTraceCorrelationAdapter) Start(ctx context.Context, sink SignalSink) error {
	a.startBase(sink)
	// V2 log enricher:
	// - Injects trace_id/span_id into logs based on eBPF-detected context
	// - Uses logenricher package
	return nil
}

// Stop stops the log-trace correlation adapter.
func (a *LogTraceCorrelationAdapter) Stop(ctx context.Context) error {
	a.stopBase()
	return nil
}

// OnCorrelatedLogs receives correlated logs from V2 and forwards to pipeline.
func (a *LogTraceCorrelationAdapter) OnCorrelatedLogs(ctx context.Context, logs plog.Logs) error {
	if !a.IsRunning() {
		return nil
	}
	return a.Sink().SendLogs(ctx, logs)
}
