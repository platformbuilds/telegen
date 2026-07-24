// Package pipeline provides the unified pipeline that routes all signals through
// a single processing path to the UnifiedExporter.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	localrequest "github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/prometheus/prometheus/prompb"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	localsvc "github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	"github.com/mirastacklabs-ai/telegen/internal/config"
	exportotlp "github.com/mirastacklabs-ai/telegen/internal/exporters/otlp"
	"github.com/mirastacklabs-ai/telegen/internal/exporters/remotewrite"
	"github.com/mirastacklabs-ai/telegen/internal/kube"
	"github.com/mirastacklabs-ai/telegen/internal/logs/filetailer"
	awsm "github.com/mirastacklabs-ai/telegen/internal/metadata/aws"
	"github.com/mirastacklabs-ai/telegen/internal/metrics/host"
	"github.com/mirastacklabs-ai/telegen/internal/nodeexporter"
	"github.com/mirastacklabs-ai/telegen/internal/pipeline/adapters"
	"github.com/mirastacklabs-ai/telegen/internal/pipeline/converters"
	"github.com/mirastacklabs-ai/telegen/internal/queue"
	"github.com/mirastacklabs-ai/telegen/pkg/export/instrumentations"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/otelcfg"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/tracesgen"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/global"
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

	// RemoteWrite preserves legacy Prometheus Remote Write transport for
	// prompb-based metric producers that have not yet been ported to pmetric.
	RemoteWrite *config.RemoteWrite `yaml:"remote_write,omitempty" json:"remote_write,omitempty"`

	// Integration controls limits/transform/PII routing before export.
	Integration *IntegrationConfig `yaml:"integration,omitempty" json:"integration,omitempty"`

	// RuntimeConfig provides source wiring parity with the legacy pipeline Start path.
	// It is not loaded from YAML directly and should be set by the caller.
	RuntimeConfig *config.Config `yaml:"-" json:"-"`
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
	exporter          *UnifiedExporter
	multiExporter     *MultiEndpointExporter
	adapterRegistry   *adapters.AdapterRegistry
	converterPipeline *converters.ConvertingPipeline
	integration       *Integration
	rw                *remotewrite.Client
	qMetrics          *queue.Ring[*prompb.WriteRequest]
	nodeExp           *nodeexporter.Exporter
	awsLabels         map[string]string
	sharedOTLP        *exportotlp.Clients
	ebpfCtxInfo       *global.ContextInfo
	stopCh            chan struct{}
	traceAttrCache    *expirable2.LRU[localsvc.UID, []attribute.KeyValue]

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
		config:            config,
		logger:            logger,
		converterPipeline: converters.NewConvertingPipeline(),
		traceCh:           make(chan ptrace.Traces, 1000),
		logCh:             make(chan plog.Logs, 1000),
		metricCh:          make(chan pmetric.Metrics, 1000),
		ctx:               ctx,
		cancel:            cancel,
		stopCh:            make(chan struct{}),
		qMetrics:          queue.NewRing[*prompb.WriteRequest](8192, func(_ uint64, _ queue.DropReason) {}),
		traceAttrCache: expirable2.NewLRU[localsvc.UID, []attribute.KeyValue](
			1024,
			nil,
			5*time.Minute,
		),
	}

	// Initialize integration layer (limits/transform/PII). Default is enabled
	// and acts as pass-through until explicit rules/limits are configured.
	intCfg := DefaultIntegrationConfig()
	if config.Integration != nil {
		intCfg = *config.Integration
	}
	integration, err := NewIntegration(intCfg, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("creating integration layer: %w", err)
	}
	p.integration = integration

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

	// Initialize shared OTLP accessors used by downstream subsystems in main.go.
	if err := p.initSharedOTLPClients(ctx); err != nil {
		p.logger.Warn("shared OTLP clients unavailable; some downstream integrations may degrade", "error", err)
	}

	// Initialize legacy remote-write transport if configured.
	if p.config.RemoteWrite != nil {
		p.rw = remotewrite.New()
		_ = p.rw.WithTLS(remotewrite.TLSConfig{
			Enable:             p.config.RemoteWrite.TLS.Enable,
			CAFile:             p.config.RemoteWrite.TLS.CAFile,
			CertFile:           p.config.RemoteWrite.TLS.CertFile,
			KeyFile:            p.config.RemoteWrite.TLS.KeyFile,
			InsecureSkipVerify: p.config.RemoteWrite.TLS.InsecureSkipVerify,
		})
		p.wg.Add(1)
		go p.remoteWriteWorker()
	}

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

	// Start persistent queue drain workers when WAL is enabled.
	if p.traceQueue != nil {
		p.wg.Add(1)
		go p.traceQueueWorker()
	}
	if p.logQueue != nil {
		p.wg.Add(1)
		go p.logQueueWorker()
	}
	if p.metricQueue != nil {
		p.wg.Add(1)
		go p.metricQueueWorker()
	}

	// Start all collector adapters.
	if err := p.adapterRegistry.StartAll(ctx); err != nil {
		return fmt.Errorf("starting adapters: %w", err)
	}

	// Start legacy-parity sources (host metrics, file logs, JFR, eBPF queue bridge)
	// when the runtime config is provided by the binary.
	if err := p.startRuntimeSources(ctx); err != nil {
		p.logger.Warn("runtime sources started with degradation", "error", err)
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
	close(p.stopCh)
	p.cancel()

	if p.nodeExp != nil {
		if err := p.nodeExp.Shutdown(ctx); err != nil {
			p.logger.Error("error stopping node exporter", "error", err)
		}
	}

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
	if p.integration != nil {
		var err error
		traces, err = p.integration.ProcessTraces(ctx, traces)
		if err != nil {
			return err
		}
		if traces.SpanCount() == 0 {
			return nil
		}
	}
	p.receivedTraces.Add(int64(traces.SpanCount()))

	select {
	case p.traceCh <- traces:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Channel full, try queue if available.
		if p.traceQueue != nil {
			return p.enqueuePersistentTraces(traces)
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
	if p.integration != nil {
		var err error
		logs, err = p.integration.ProcessLogs(ctx, logs)
		if err != nil {
			return err
		}
		if logs.LogRecordCount() == 0 {
			return nil
		}
	}
	p.receivedLogs.Add(int64(logs.LogRecordCount()))

	select {
	case p.logCh <- logs:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		if p.logQueue != nil {
			return p.enqueuePersistentLogs(logs)
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
	if p.integration != nil {
		var err error
		metrics, err = p.integration.ProcessMetrics(ctx, metrics)
		if err != nil {
			return err
		}
		if metrics.DataPointCount() == 0 {
			return nil
		}
	}
	p.receivedMetrics.Add(int64(metrics.DataPointCount()))

	select {
	case p.metricCh <- metrics:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		if p.metricQueue != nil {
			return p.enqueuePersistentMetrics(metrics)
		}
		p.droppedMetrics.Add(int64(metrics.DataPointCount()))
		p.logger.Warn("metric channel full, dropping metrics",
			"dropped", metrics.DataPointCount(),
		)
		return fmt.Errorf("metric channel full")
	}
}

func (p *UnifiedPipeline) enqueuePersistentTraces(traces ptrace.Traces) error {
	if p.traceQueue == nil {
		return nil
	}
	req := ptraceotlp.NewExportRequestFromTraces(traces)
	b, err := req.MarshalProto()
	if err != nil {
		return fmt.Errorf("marshal traces for persistent queue: %w", err)
	}
	return p.traceQueue.Push("traces", b)
}

func (p *UnifiedPipeline) enqueuePersistentLogs(logs plog.Logs) error {
	if p.logQueue == nil {
		return nil
	}
	req := plogotlp.NewExportRequestFromLogs(logs)
	b, err := req.MarshalProto()
	if err != nil {
		return fmt.Errorf("marshal logs for persistent queue: %w", err)
	}
	return p.logQueue.Push("logs", b)
}

func (p *UnifiedPipeline) enqueuePersistentMetrics(metrics pmetric.Metrics) error {
	if p.metricQueue == nil {
		return nil
	}
	req := pmetricotlp.NewExportRequestFromMetrics(metrics)
	b, err := req.MarshalProto()
	if err != nil {
		return fmt.Errorf("marshal metrics for persistent queue: %w", err)
	}
	return p.metricQueue.Push("metrics", b)
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

func (p *UnifiedPipeline) traceQueueWorker() {
	defer p.wg.Done()
	for p.ctx.Err() == nil {
		item, err := p.traceQueue.Pop(p.ctx)
		if err != nil {
			p.logger.Warn("trace WAL pop failed", "error", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if item == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		req := ptraceotlp.NewExportRequest()
		if err := req.UnmarshalProto(item.Data); err != nil {
			p.logger.Warn("trace WAL decode failed", "error", err)
			continue
		}
		if err := p.exportTraces(p.ctx, req.Traces()); err != nil {
			p.logger.Warn("trace WAL export failed", "error", err)
			_ = p.traceQueue.Push("traces", item.Data)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (p *UnifiedPipeline) logQueueWorker() {
	defer p.wg.Done()
	for p.ctx.Err() == nil {
		item, err := p.logQueue.Pop(p.ctx)
		if err != nil {
			p.logger.Warn("log WAL pop failed", "error", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if item == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		req := plogotlp.NewExportRequest()
		if err := req.UnmarshalProto(item.Data); err != nil {
			p.logger.Warn("log WAL decode failed", "error", err)
			continue
		}
		if err := p.exportLogs(p.ctx, req.Logs()); err != nil {
			p.logger.Warn("log WAL export failed", "error", err)
			_ = p.logQueue.Push("logs", item.Data)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (p *UnifiedPipeline) metricQueueWorker() {
	defer p.wg.Done()
	for p.ctx.Err() == nil {
		item, err := p.metricQueue.Pop(p.ctx)
		if err != nil {
			p.logger.Warn("metric WAL pop failed", "error", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if item == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		req := pmetricotlp.NewExportRequest()
		if err := req.UnmarshalProto(item.Data); err != nil {
			p.logger.Warn("metric WAL decode failed", "error", err)
			continue
		}
		if err := p.exportMetrics(p.ctx, req.Metrics()); err != nil {
			p.logger.Warn("metric WAL export failed", "error", err)
			_ = p.metricQueue.Push("metrics", item.Data)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (p *UnifiedPipeline) remoteWriteWorker() {
	defer p.wg.Done()
	for p.ctx.Err() == nil {
		p.qMetrics.DropExpired(5 * time.Minute)
		batch := p.qMetrics.PopBatch(500, 1*time.Second)
		if len(batch) == 0 {
			continue
		}

		var wr prompb.WriteRequest
		for _, it := range batch {
			if it.V == nil {
				continue
			}
			wr.Timeseries = append(wr.Timeseries, it.V.Timeseries...)
			wr.Metadata = append(wr.Metadata, it.V.Metadata...)
		}
		if p.config.RemoteWrite == nil || len(p.config.RemoteWrite.Endpoints) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}
		ep := p.config.RemoteWrite.Endpoints[0]
		if err := p.rw.Send(p.ctx, &wr, remotewrite.Endpoint{
			URL:         ep.URL,
			Timeout:     mustDur(ep.Timeout),
			Headers:     ep.Headers,
			Tenant:      ep.Tenant,
			Compression: ep.Compression,
		}); err != nil {
			p.logger.Warn("remote write send failed", "error", err, "timeseries", len(wr.Timeseries))
			p.qMetrics.Push(&wr)
			time.Sleep(2 * time.Second)
			continue
		}
	}
}

// EnqueueMetrics allows legacy prompb producers to use V3's preserved remote-write transport.
func (p *UnifiedPipeline) EnqueueMetrics(wr *prompb.WriteRequest) {
	if wr == nil || p.qMetrics == nil {
		return
	}
	if len(p.awsLabels) > 0 {
		for i := range wr.Timeseries {
			have := map[string]struct{}{}
			for _, l := range wr.Timeseries[i].Labels {
				have[l.Name] = struct{}{}
			}
			for k, v := range p.awsLabels {
				if _, ok := have[k]; ok {
					continue
				}
				wr.Timeseries[i].Labels = append(wr.Timeseries[i].Labels, prompb.Label{Name: k, Value: v})
			}
		}
	}
	p.qMetrics.Push(wr)
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

func (p *UnifiedPipeline) initSharedOTLPClients(ctx context.Context) error {
	if p.sharedOTLP != nil {
		return nil
	}
	opts := exportotlp.TraceOpts{}
	opts.Mode = "failover"
	opts.TLS.Enable = !p.config.Exporter.Insecure
	opts.TLS.InsecureSkipVerify = p.config.Exporter.Insecure
	opts.GRPC.Enabled = true
	opts.GRPC.Endpoint = p.config.Exporter.Endpoint
	opts.GRPC.Headers = p.config.Exporter.Headers
	opts.GRPC.Insecure = p.config.Exporter.Insecure
	opts.GRPC.Gzip = true
	opts.GRPC.Timeout = p.config.Exporter.Timeout

	// Best-effort HTTP fallback when endpoint is URL-formatted.
	if strings.HasPrefix(p.config.Exporter.Endpoint, "http://") || strings.HasPrefix(p.config.Exporter.Endpoint, "https://") {
		opts.GRPC.Enabled = false
		opts.HTTP.Enabled = true
		opts.HTTP.Endpoint = strings.TrimPrefix(strings.TrimPrefix(p.config.Exporter.Endpoint, "http://"), "https://")
		opts.HTTP.Insecure = p.config.Exporter.Insecure
		opts.HTTP.TracesURL = "/v1/traces"
		opts.HTTP.LogsURL = "/v1/logs"
		opts.HTTP.Headers = p.config.Exporter.Headers
		opts.HTTP.Gzip = true
		opts.HTTP.Timeout = p.config.Exporter.Timeout
	}

	clients, err := exportotlp.New(ctx, opts, nil)
	if err != nil {
		return err
	}
	p.sharedOTLP = clients
	return nil
}

func (p *UnifiedPipeline) startRuntimeSources(ctx context.Context) error {
	if p.config.RuntimeConfig == nil {
		return nil
	}
	var errs []error
	rcfg := p.config.RuntimeConfig

	// Optional cloud metadata enrichment parity from the legacy pipeline.
	if rcfg.Cloud.AWS.Enabled {
		aopts := awsm.Options{}
		if d, err := time.ParseDuration(rcfg.Cloud.AWS.Timeout); err == nil {
			aopts.Timeout = d
		}
		if d, err := time.ParseDuration(rcfg.Cloud.AWS.RefreshInterval); err == nil {
			aopts.RefreshInterval = d
		}
		aopts.CollectTags = rcfg.Cloud.AWS.CollectTags
		aopts.TagAllowlist = rcfg.Cloud.AWS.TagAllowlist
		aopts.BaseURL = rcfg.Cloud.AWS.IMDSBaseURL
		aopts.DisableProbe = rcfg.Cloud.AWS.DisableProbe
		prov := awsm.New(aopts)
		if meta, err := prov.Fetch(ctx); err == nil {
			p.awsLabels = meta.Labels()
		} else {
			p.logger.Warn("aws metadata fetch failed", "error", err)
		}
	}

	// Host metrics: OTLP-native path via the node_exporter subsystem.
	// The legacy prompb -> remote-write collector is used only when a
	// remote-write endpoint is configured and node_exporter streaming is disabled.
	if rcfg.NodeExporter.Enabled && rcfg.NodeExporter.Export.Enabled {
		ne, err := nodeexporter.New(rcfg.NodeExporter)
		if err != nil {
			errs = append(errs, fmt.Errorf("create node exporter: %w", err))
		} else if err := ne.ConfigureOTLPStreaming(ctx, p.GetMetricsExporter()); err != nil {
			errs = append(errs, fmt.Errorf("start node exporter OTLP streaming: %w", err))
		} else {
			p.nodeExp = ne
			p.logger.Info("node_exporter OTLP host metrics started", "interval", rcfg.NodeExporter.Export.Interval)
		}
	} else if len(rcfg.Exports.RemoteWrite.Endpoints) > 0 {
		if hostname, _ := os.Hostname(); true {
			col := host.New("telegen", hostname, 15*time.Second, p.EnqueueMetrics)
			if len(p.awsLabels) > 0 {
				col.SetExtraLabels(p.awsLabels)
			}
			go col.Run(p.stopCh)
		}
	}

	// File logs parity: keep using shared SDK LoggerProvider.
	if rcfg.Pipelines.Logs.Enabled {
		lp := p.GetLogsLoggerProvider()
		if lp == nil {
			errs = append(errs, fmt.Errorf("file logs enabled but shared logs provider is nil"))
		} else {
			fCfg := rcfg.Pipelines.Logs.Filelog
			opts := filetailer.Options{
				Globs:                fCfg.Include,
				Excludes:             fCfg.Exclude,
				PositionFile:         fCfg.PositionFile,
				LoggerProvider:       lp,
				ShipHistoricalEvents: fCfg.ShipHistoricalEvents,
				StartTime:            time.Now(),
				PollInterval:         fCfg.PollIntervalDuration(),
				ParserConfig:         filetailer.DefaultParserConfig(),
			}
			ft := filetailer.NewWithOptions(opts)
			go func() { _ = ft.Run(p.stopCh) }()
		}
	}

	if rcfg.Pipelines.JFR.Enabled {
		if err := p.startJFRSource(ctx); err != nil {
			errs = append(errs, fmt.Errorf("start jfr source: %w", err))
		}
	}
	if rcfg.EBPF.Enabled && runtime.GOOS == "linux" {
		if err := p.startEBPFSource(ctx); err != nil {
			errs = append(errs, fmt.Errorf("start ebpf source: %w", err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (p *UnifiedPipeline) forwardOBISpanBatch(ctx context.Context, batch []localrequest.Span) error {
	if len(batch) == 0 {
		return nil
	}

	// Convert OBI request spans into OTLP traces and route through V3.
	grouped := tracesgen.GroupSpans(
		ctx,
		batch,
		nil,
		sdktrace.AlwaysSample(),
		instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{instrumentations.InstrumentationALL}),
	)
	for _, spans := range grouped {
		if len(spans) == 0 || spans[0].Span == nil {
			continue
		}
		hostID := ""
		if p.ebpfCtxInfo != nil {
			hostID = p.ebpfCtxInfo.HostID
		}
		envAttrs := otelcfg.ResourceAttrsFromEnv(&spans[0].Span.Service)
		td := tracesgen.GenerateTracesWithAttributes(
			p.traceAttrCache,
			&spans[0].Span.Service,
			envAttrs,
			hostID,
			spans,
			"go.opentelemetry.io/obi",
		)
		if err := p.SendTraces(ctx, td); err != nil {
			return err
		}
	}
	return nil
}

// GetMetricsExporter returns the shared SDK metrics exporter for downstream components.
func (p *UnifiedPipeline) GetMetricsExporter() sdkmetric.Exporter {
	if p.sharedOTLP == nil {
		return nil
	}
	return p.sharedOTLP.Metrics
}

// GetLogsLoggerProvider returns the shared SDK logs provider for downstream components.
func (p *UnifiedPipeline) GetLogsLoggerProvider() *sdklog.LoggerProvider {
	if p.sharedOTLP == nil {
		return nil
	}
	return p.sharedOTLP.Log
}

// GetTracesExporter returns the collector traces exporter shared across subsystems.
func (p *UnifiedPipeline) GetTracesExporter() exporter.Traces {
	if p.sharedOTLP == nil {
		return nil
	}
	return p.sharedOTLP.CollectorTraces
}

// GetKubeStore returns kube metadata store from OBI context for profiler reuse.
func (p *UnifiedPipeline) GetKubeStore(ctx context.Context) (*kube.Store, error) {
	if p.ebpfCtxInfo == nil || p.ebpfCtxInfo.K8sInformer == nil {
		return nil, nil
	}
	return p.ebpfCtxInfo.K8sInformer.Get(ctx)
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

// Close provides compatibility with the legacy pipeline lifecycle.
func (p *UnifiedPipeline) Close() {
	_ = p.Stop(context.Background())
}
