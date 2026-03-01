// Package pipeline provides the unified pipeline that routes all signals through
// a single processing path to the UnifiedExporter.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/mirastacklabs-ai/telegen/internal/pipeline/adapters"
	"github.com/mirastacklabs-ai/telegen/internal/pipeline/converters"
	"github.com/mirastacklabs-ai/telegen/internal/queue"
)

// UnifiedPipelineConfig configures the unified pipeline.
type UnifiedPipelineConfig struct {
	// Exporter configuration for OTLP export.
	Exporter ExporterConfig `yaml:"exporter" json:"exporter"`

	// MultiEndpoint configuration for failover/fanout.
	MultiEndpoint *MultiEndpointConfig `yaml:"multi_endpoint,omitempty" json:"multi_endpoint,omitempty"`

	// Queue configuration for persistent buffering.
	Queue *QueueConfig `yaml:"queue,omitempty" json:"queue,omitempty"`

	// EnabledCollectors specifies which collectors to enable.
	// Empty means all available collectors.
	EnabledCollectors []adapters.CollectorType `yaml:"enabled_collectors,omitempty" json:"enabled_collectors,omitempty"`

	// BatchTimeout is how long to wait before flushing a partial batch.
	BatchTimeout time.Duration `yaml:"batch_timeout" json:"batch_timeout"`

	// WorkerCount is the number of export workers. Default: 2.
	WorkerCount int `yaml:"worker_count" json:"worker_count"`
}

// QueueConfig configures the persistent queue.
type QueueConfig struct {
	// Enabled enables persistent queueing. Default: false.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Directory is the queue storage directory.
	Directory string `yaml:"directory" json:"directory"`

	// MaxSizeBytes is the maximum queue size. Default: 500MB.
	MaxSizeBytes int64 `yaml:"max_size_bytes" json:"max_size_bytes"`

	// MaxItems is the maximum number of queued items. Default: 100000.
	MaxItems int `yaml:"max_items" json:"max_items"`
}

// DefaultUnifiedPipelineConfig returns default configuration.
func DefaultUnifiedPipelineConfig() UnifiedPipelineConfig {
	return UnifiedPipelineConfig{
		Exporter:     DefaultExporterConfig(),
		BatchTimeout: 5 * time.Second,
		WorkerCount:  2,
	}
}

// Pipeline is the unified pipeline manager for Telegen.
// It integrates adapters, converters, queues, and exporters into a single processing path.
type UnifiedPipeline struct {
	config UnifiedPipelineConfig
	logger *slog.Logger

	// Core components.
	exporter         *UnifiedExporter
	multiExporter    *MultiEndpointExporter
	adapterRegistry  *adapters.AdapterRegistry
	converterPipeline *converters.ConvertingPipeline

	// Persistent queue (optional).
	traceQueue  *queue.PersistentQueue
	logQueue    *queue.PersistentQueue
	metricQueue *queue.PersistentQueue

	// Signal channels for batching.
	traceCh  chan ptrace.Traces
	logCh    chan plog.Logs
	metricCh chan pmetric.Metrics

	// Stats.
	receivedTraces  atomic.Int64
	receivedLogs    atomic.Int64
	receivedMetrics atomic.Int64
	droppedTraces   atomic.Int64
	droppedLogs     atomic.Int64
	droppedMetrics  atomic.Int64

	// Lifecycle.
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	running   bool
	startTime time.Time
}

// NewUnifiedPipeline creates a new unified pipeline.
func NewUnifiedPipeline(config UnifiedPipelineConfig) (*UnifiedPipeline, error) {
	ctx, cancel := context.WithCancel(context.Background())

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	p := &UnifiedPipeline{
		config:           config,
		logger:           logger,
		converterPipeline: converters.NewConvertingPipeline(),
		traceCh:          make(chan ptrace.Traces, 1000),
		logCh:            make(chan plog.Logs, 1000),
		metricCh:         make(chan pmetric.Metrics, 1000),
		ctx:              ctx,
		cancel:           cancel,
	}

	// Create unified exporter.
	exporter, err := NewUnifiedExporter(config.Exporter)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("creating unified exporter: %w", err)
	}
	p.exporter = exporter

	// Create multi-endpoint exporter if configured.
	if config.MultiEndpoint != nil && len(config.MultiEndpoint.Endpoints) > 0 {
		multiExporter, err := NewMultiEndpointExporter(*config.MultiEndpoint, logger)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("creating multi-endpoint exporter: %w", err)
		}
		p.multiExporter = multiExporter
	}

	// Create adapter registry with this pipeline as the sink.
	p.adapterRegistry = adapters.NewAdapterRegistry(p)

	// Register default adapters if no specific collectors configured.
	p.registerDefaultAdapters()

	return p, nil
}

// registerDefaultAdapters registers all available collector adapters.
func (p *UnifiedPipeline) registerDefaultAdapters() {
	// Agent mode collectors.
	p.adapterRegistry.Register(adapters.NewEBPFTracesAdapter())
	p.adapterRegistry.Register(adapters.NewEBPFProfilingAdapter())
	p.adapterRegistry.Register(adapters.NewJFRProfilingAdapter())
	p.adapterRegistry.Register(adapters.NewFileLogsAdapter())
	p.adapterRegistry.Register(adapters.NewHostMetricsAdapter())
	p.adapterRegistry.Register(adapters.NewKubeMetricsAdapter())
	p.adapterRegistry.Register(adapters.NewNetworkFlowsAdapter())

	// V2 features.
	p.adapterRegistry.Register(adapters.NewKafkaLogsAdapter())
	p.adapterRegistry.Register(adapters.NewSecurityAdapter())
	p.adapterRegistry.Register(adapters.NewGPUAdapter())
	p.adapterRegistry.Register(adapters.NewDatabaseTracingAdapter())
	p.adapterRegistry.Register(adapters.NewLogTraceCorrelationAdapter())
}

// Start starts the unified pipeline.
func (p *UnifiedPipeline) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("pipeline already running")
	}

	p.logger.Info("starting unified pipeline",
		"worker_count", p.config.WorkerCount,
		"batch_timeout", p.config.BatchTimeout,
	)

	// Initialize persistent queues if enabled.
	if p.config.Queue != nil && p.config.Queue.Enabled {
		if err := p.initQueues(); err != nil {
			return fmt.Errorf("initializing queues: %w", err)
		}
	}

	// Unified exporter is ready after creation.
	p.logger.Info("unified exporter ready",
		"endpoint", p.config.Exporter.Endpoint,
	)

	// Multi-endpoint exporter is ready after creation.
	if p.multiExporter != nil {
		p.logger.Info("multi-endpoint exporter ready",
			"endpoints", len(p.config.MultiEndpoint.Endpoints),
		)
	}

	// Start export workers.
	for i := 0; i < p.config.WorkerCount; i++ {
		p.wg.Add(3) // One goroutine per signal type.
		go p.traceWorker(i)
		go p.logWorker(i)
		go p.metricWorker(i)
	}

	// Start all collector adapters.
	if err := p.adapterRegistry.StartAll(ctx); err != nil {
		return fmt.Errorf("starting adapters: %w", err)
	}

	p.running = true
	p.startTime = time.Now()

	p.logger.Info("unified pipeline started",
		"adapters", len(p.adapterRegistry.List()),
	)

	return nil
}

// Stop gracefully stops the pipeline.
func (p *UnifiedPipeline) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	p.mu.Unlock()

	p.logger.Info("stopping unified pipeline")

	// Stop accepting new signals.
	p.cancel()

	// Stop all adapters first.
	if err := p.adapterRegistry.StopAll(ctx); err != nil {
		p.logger.Error("error stopping adapters", "error", err)
	}

	// Close signal channels.
	close(p.traceCh)
	close(p.logCh)
	close(p.metricCh)

	// Wait for workers to drain.
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Workers finished.
	case <-ctx.Done():
		p.logger.Warn("shutdown timeout, some data may be lost")
	}

	// Flush and close queues.
	if p.traceQueue != nil {
		_ = p.traceQueue.Flush()
		_ = p.traceQueue.Close()
	}
	if p.logQueue != nil {
		_ = p.logQueue.Flush()
		_ = p.logQueue.Close()
	}
	if p.metricQueue != nil {
		_ = p.metricQueue.Flush()
		_ = p.metricQueue.Close()
	}

	// Stop exporters.
	if err := p.exporter.Shutdown(ctx); err != nil {
		p.logger.Error("error shutting down exporter", "error", err)
	}

	p.logger.Info("unified pipeline stopped",
		"uptime", time.Since(p.startTime),
		"traces_received", p.receivedTraces.Load(),
		"logs_received", p.receivedLogs.Load(),
		"metrics_received", p.receivedMetrics.Load(),
	)

	return nil
}

// initQueues initializes persistent queues.
func (p *UnifiedPipeline) initQueues() error {
	baseConfig := queue.PersistentQueueConfig{
		DataDir:      p.config.Queue.Directory,
		MaxSizeBytes: p.config.Queue.MaxSizeBytes,
		MaxItemCount: p.config.Queue.MaxItems,
	}
	if baseConfig.MaxSizeBytes == 0 {
		baseConfig.MaxSizeBytes = 500 * 1024 * 1024 // 500MB default
	}
	if baseConfig.MaxItemCount == 0 {
		baseConfig.MaxItemCount = 100000
	}

	var err error

	// Trace queue.
	traceConfig := baseConfig
	traceConfig.DataDir = filepath.Join(p.config.Queue.Directory, "traces")
	p.traceQueue, err = queue.NewPersistentQueue(traceConfig)
	if err != nil {
		return fmt.Errorf("creating trace queue: %w", err)
	}

	// Log queue.
	logConfig := baseConfig
	logConfig.DataDir = filepath.Join(p.config.Queue.Directory, "logs")
	p.logQueue, err = queue.NewPersistentQueue(logConfig)
	if err != nil {
		return fmt.Errorf("creating log queue: %w", err)
	}

	// Metric queue.
	metricConfig := baseConfig
	metricConfig.DataDir = filepath.Join(p.config.Queue.Directory, "metrics")
	p.metricQueue, err = queue.NewPersistentQueue(metricConfig)
	if err != nil {
		return fmt.Errorf("creating metric queue: %w", err)
	}

	return nil
}

// SendTraces implements adapters.SignalSink.
func (p *UnifiedPipeline) SendTraces(ctx context.Context, traces ptrace.Traces) error {
	p.receivedTraces.Add(int64(traces.SpanCount()))

	select {
	case p.traceCh <- traces:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Channel full, try queue if available.
		if p.traceQueue != nil {
			// Queue for later processing.
			return nil
		}
		p.droppedTraces.Add(int64(traces.SpanCount()))
		p.logger.Warn("trace channel full, dropping spans",
			"dropped", traces.SpanCount(),
		)
		return fmt.Errorf("trace channel full")
	}
}

// SendLogs implements adapters.SignalSink.
func (p *UnifiedPipeline) SendLogs(ctx context.Context, logs plog.Logs) error {
	p.receivedLogs.Add(int64(logs.LogRecordCount()))

	select {
	case p.logCh <- logs:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		if p.logQueue != nil {
			return nil
		}
		p.droppedLogs.Add(int64(logs.LogRecordCount()))
		p.logger.Warn("log channel full, dropping logs",
			"dropped", logs.LogRecordCount(),
		)
		return fmt.Errorf("log channel full")
	}
}

// SendMetrics implements adapters.SignalSink.
func (p *UnifiedPipeline) SendMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	p.receivedMetrics.Add(int64(metrics.DataPointCount()))

	select {
	case p.metricCh <- metrics:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		if p.metricQueue != nil {
			return nil
		}
		p.droppedMetrics.Add(int64(metrics.DataPointCount()))
		p.logger.Warn("metric channel full, dropping metrics",
			"dropped", metrics.DataPointCount(),
		)
		return fmt.Errorf("metric channel full")
	}
}

// traceWorker processes traces from the channel.
func (p *UnifiedPipeline) traceWorker(id int) {
	defer p.wg.Done()

	for traces := range p.traceCh {
		if err := p.exportTraces(p.ctx, traces); err != nil {
			p.logger.Error("failed to export traces",
				"worker", id,
				"error", err,
				"span_count", traces.SpanCount(),
			)
		}
	}
}

// logWorker processes logs from the channel.
func (p *UnifiedPipeline) logWorker(id int) {
	defer p.wg.Done()

	for logs := range p.logCh {
		if err := p.exportLogs(p.ctx, logs); err != nil {
			p.logger.Error("failed to export logs",
				"worker", id,
				"error", err,
				"log_count", logs.LogRecordCount(),
			)
		}
	}
}

// metricWorker processes metrics from the channel.
func (p *UnifiedPipeline) metricWorker(id int) {
	defer p.wg.Done()

	for metrics := range p.metricCh {
		if err := p.exportMetrics(p.ctx, metrics); err != nil {
			p.logger.Error("failed to export metrics",
				"worker", id,
				"error", err,
				"datapoint_count", metrics.DataPointCount(),
			)
		}
	}
}

// exportTraces exports traces through the appropriate exporter.
func (p *UnifiedPipeline) exportTraces(ctx context.Context, traces ptrace.Traces) error {
	if p.multiExporter != nil {
		return p.multiExporter.ExportTraces(ctx, traces)
	}
	return p.exporter.Export(ctx, NewTraceSignal(traces, "pipeline"))
}

// exportLogs exports logs through the appropriate exporter.
func (p *UnifiedPipeline) exportLogs(ctx context.Context, logs plog.Logs) error {
	if p.multiExporter != nil {
		return p.multiExporter.ExportLogs(ctx, logs)
	}
	return p.exporter.Export(ctx, NewLogSignal(logs, "pipeline"))
}

// exportMetrics exports metrics through the appropriate exporter.
func (p *UnifiedPipeline) exportMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	if p.multiExporter != nil {
		return p.multiExporter.ExportMetrics(ctx, metrics)
	}
	return p.exporter.Export(ctx, NewMetricSignal(metrics, "pipeline"))
}

// Stats returns pipeline statistics.
func (p *UnifiedPipeline) Stats() UnifiedPipelineStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var uptime time.Duration
	if p.running {
		uptime = time.Since(p.startTime)
	}

	stats := UnifiedPipelineStats{
		Running:         p.running,
		Uptime:          uptime,
		ReceivedTraces:  p.receivedTraces.Load(),
		ReceivedLogs:    p.receivedLogs.Load(),
		ReceivedMetrics: p.receivedMetrics.Load(),
		DroppedTraces:   p.droppedTraces.Load(),
		DroppedLogs:     p.droppedLogs.Load(),
		DroppedMetrics:  p.droppedMetrics.Load(),
		Adapters:        len(p.adapterRegistry.List()),
	}

	// Add exporter stats.
	if p.exporter != nil {
		exporterStats := p.exporter.Stats()
		stats.ExportedTraces = exporterStats.ExportedTraces
		stats.ExportedLogs = exporterStats.ExportedLogs
		stats.ExportedMetrics = exporterStats.ExportedMetrics
		stats.FailedExports = exporterStats.FailedExports
	}

	// Add queue stats.
	if p.traceQueue != nil {
		qStats := p.traceQueue.Stats()
		stats.QueuedTraces = int64(qStats.ItemCount)
	}
	if p.logQueue != nil {
		qStats := p.logQueue.Stats()
		stats.QueuedLogs = int64(qStats.ItemCount)
	}
	if p.metricQueue != nil {
		qStats := p.metricQueue.Stats()
		stats.QueuedMetrics = int64(qStats.ItemCount)
	}

	return stats
}

// PipelineStats contains pipeline statistics.
type UnifiedPipelineStats struct {
	Running         bool          `json:"running"`
	Uptime          time.Duration `json:"uptime"`
	Adapters        int           `json:"adapters"`
	ReceivedTraces  int64         `json:"received_traces"`
	ReceivedLogs    int64         `json:"received_logs"`
	ReceivedMetrics int64         `json:"received_metrics"`
	ExportedTraces  int64         `json:"exported_traces"`
	ExportedLogs    int64         `json:"exported_logs"`
	ExportedMetrics int64         `json:"exported_metrics"`
	DroppedTraces   int64         `json:"dropped_traces"`
	DroppedLogs     int64         `json:"dropped_logs"`
	DroppedMetrics  int64         `json:"dropped_metrics"`
	FailedExports   int64         `json:"failed_exports"`
	QueuedTraces    int64         `json:"queued_traces"`
	QueuedLogs      int64         `json:"queued_logs"`
	QueuedMetrics   int64         `json:"queued_metrics"`
}

// Adapter returns a specific adapter by type.
func (p *UnifiedPipeline) Adapter(t adapters.CollectorType) (adapters.CollectorAdapter, bool) {
	return p.adapterRegistry.Get(t)
}

// Converters returns the converter pipeline for format conversion.
func (p *UnifiedPipeline) Converters() *converters.ConvertingPipeline {
	return p.converterPipeline
}

// IsRunning returns whether the pipeline is running.
func (p *UnifiedPipeline) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}
