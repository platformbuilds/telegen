package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"

	appollycore "github.com/mirastacklabs-ai/telegen/internal/appolly/core"
	"github.com/mirastacklabs-ai/telegen/internal/config"
	"github.com/mirastacklabs-ai/telegen/internal/exporters/otlp"
	"github.com/mirastacklabs-ai/telegen/internal/exporters/remotewrite"
	"github.com/mirastacklabs-ai/telegen/internal/instrumenter"
	"github.com/mirastacklabs-ai/telegen/internal/jfr/converter"
	"github.com/mirastacklabs-ai/telegen/internal/jfr/watcher"
	"github.com/mirastacklabs-ai/telegen/internal/kafka"
	"github.com/mirastacklabs-ai/telegen/internal/kube"
	"github.com/mirastacklabs-ai/telegen/internal/logs/filetailer"
	awsm "github.com/mirastacklabs-ai/telegen/internal/metadata/aws"
	"github.com/mirastacklabs-ai/telegen/internal/metrics/host"
	"github.com/mirastacklabs-ai/telegen/internal/obi"
	"github.com/mirastacklabs-ai/telegen/internal/queue"
	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/global"

	"github.com/prometheus/prometheus/prompb"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/zap"
)

// Package-level JSON logger for pipeline
var logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

// SignalStatus tracks the health of individual signals
type SignalStatus struct {
	Name    string
	Enabled bool
	Running bool
	Error   string
}

type Pipeline struct {
	cfg *config.Config
	st  *selftelemetry.Registry

	qMetrics *queue.Ring[*prompb.WriteRequest]
	stop     chan struct{}

	rw *remotewrite.Client
	ot *otlp.Clients

	awsLabels map[string]string

	// Signal status tracking for graceful degradation
	signals map[string]*SignalStatus

	// eBPF instrumenter for auto-instrumentation
	ebpfInstrumenter *appollycore.Instrumenter
	ebpfCtxInfo      *global.ContextInfo
}

func New(cfg *config.Config, st *selftelemetry.Registry) *Pipeline {
	qm := queue.NewRing[*prompb.WriteRequest](8192, func(_ uint64, reason queue.DropReason) {
		st.QueueDropped.WithLabelValues("metrics", string(reason)).Inc()
	})
	return &Pipeline{
		cfg:      cfg,
		st:       st,
		qMetrics: qm,
		stop:     make(chan struct{}),
		signals:  make(map[string]*SignalStatus),
	}
}

// SignalsStarted returns the count of successfully started signals
func (p *Pipeline) SignalsStarted() int {
	count := 0
	for _, s := range p.signals {
		if s.Running {
			count++
		}
	}
	return count
}

// GetSignalStatus returns the status of all signals for health reporting
func (p *Pipeline) GetSignalStatus() []SignalStatus {
	result := make([]SignalStatus, 0, len(p.signals))
	for _, s := range p.signals {
		result = append(result, *s)
	}
	return result
}

func (p *Pipeline) Start(ctx context.Context) error {
	p.rw = remotewrite.New()
	_ = p.rw.WithTLS(remotewrite.TLSConfig{
		Enable:             p.cfg.Exports.RemoteWrite.TLS.Enable,
		CAFile:             p.cfg.Exports.RemoteWrite.TLS.CAFile,
		CertFile:           p.cfg.Exports.RemoteWrite.TLS.CertFile,
		KeyFile:            p.cfg.Exports.RemoteWrite.TLS.KeyFile,
		InsecureSkipVerify: p.cfg.Exports.RemoteWrite.TLS.InsecureSkipVerify,
	})

	// OTLP exporters
	o := p.cfg.Exports.OTLP
	var topts otlp.TraceOpts
	topts.Mode = o.SendMode
	topts.TLS.Enable = o.TLS.Enable
	topts.TLS.CAFile, topts.TLS.CertFile, topts.TLS.KeyFile = o.TLS.CAFile, o.TLS.CertFile, o.TLS.KeyFile
	topts.TLS.InsecureSkipVerify = o.TLS.InsecureSkipVerify
	topts.GRPC.Enabled, topts.GRPC.Endpoint, topts.GRPC.Headers = o.GRPC.Enabled, o.GRPC.Endpoint, o.GRPC.Headers
	topts.GRPC.Insecure, topts.GRPC.Gzip = o.GRPC.Insecure, o.GRPC.Gzip
	topts.GRPC.Timeout, _ = time.ParseDuration(o.GRPC.Timeout)
	topts.HTTP.Enabled, topts.HTTP.Endpoint = o.HTTP.Enabled, o.HTTP.Endpoint
	topts.HTTP.Insecure = o.HTTP.Insecure
	topts.HTTP.TracesURL, topts.HTTP.LogsURL = o.HTTP.TracesPath, o.HTTP.LogsPath
	topts.HTTP.Headers, topts.HTTP.Gzip = o.HTTP.Headers, o.HTTP.Gzip
	topts.HTTP.Timeout, _ = time.ParseDuration(o.HTTP.Timeout)
	// Cloud/AWS metadata (optional)
	var resRsrc *resource.Resource
	if p.cfg.Cloud.AWS.Enabled {
		aopts := awsm.Options{}
		if d, err := time.ParseDuration(p.cfg.Cloud.AWS.Timeout); err == nil {
			aopts.Timeout = d
		}
		if d, err := time.ParseDuration(p.cfg.Cloud.AWS.RefreshInterval); err == nil {
			aopts.RefreshInterval = d
		}
		aopts.CollectTags = p.cfg.Cloud.AWS.CollectTags
		aopts.TagAllowlist = p.cfg.Cloud.AWS.TagAllowlist
		aopts.BaseURL = p.cfg.Cloud.AWS.IMDSBaseURL
		aopts.DisableProbe = p.cfg.Cloud.AWS.DisableProbe
		prov := awsm.New(aopts)
		if meta, err := prov.Fetch(ctx); err == nil && meta != nil {
			p.awsLabels = meta.Labels()
			resRsrc = meta.Resource()
		} else if err != nil {
			logger.Warn("aws metadata fetch failed", "error", err)
		}
	}

	var err error
	p.ot, err = otlp.New(ctx, topts, resRsrc)
	if err != nil {
		logger.Error("otlp init failed", "error", err)
		p.signals["otlp"] = &SignalStatus{Name: "otlp", Enabled: true, Running: false, Error: err.Error()}
	} else {
		p.signals["otlp"] = &SignalStatus{Name: "otlp", Enabled: true, Running: true}
	}

	go p.runRemoteWrite(ctx)

	// Host metrics (always enabled as baseline)
	if hostname, _ := os.Hostname(); true {
		col := host.New("telegen", hostname, 15*time.Second, p.EnqueueMetrics)
		if len(p.awsLabels) > 0 {
			col.SetExtraLabels(p.awsLabels)
		}
		go col.Run(p.stop)
		p.signals["host_metrics"] = &SignalStatus{Name: "host_metrics", Enabled: true, Running: true}
	}

	// File logs signal
	p.signals["logs"] = &SignalStatus{Name: "logs", Enabled: p.cfg.Pipelines.Logs.Enabled, Running: false}
	if p.cfg.Pipelines.Logs.Enabled {
		if p.ot != nil && p.ot.Log != nil {
			fCfg := p.cfg.Pipelines.Logs.Filelog

			opts := filetailer.Options{
				Globs:                fCfg.Include,
				Excludes:             fCfg.Exclude,
				PositionFile:         fCfg.PositionFile,
				LoggerProvider:       p.ot.Log,
				ShipHistoricalEvents: fCfg.ShipHistoricalEvents,
				StartTime:            time.Now(),
				PollInterval:         fCfg.PollIntervalDuration(),
				ParserConfig:         filetailer.DefaultParserConfig(),
			}

			ft := filetailer.NewWithOptions(opts)
			go func() { _ = ft.Run(p.stop) }()
			p.signals["logs"].Running = true
			logger.Info("logs file tailer started",
				"include", fCfg.Include,
				"exclude", fCfg.Exclude,
				"k8s_discovery", fCfg.Kubernetes != nil)
		} else {
			p.signals["logs"].Error = "OTLP log exporter not available"
			logger.Warn("logs enabled but OTLP log exporter not available", "status", "continuing_without_logs")
		}
	}

	// JFR (Java Flight Recorder) profiling signal
	p.signals["jfr"] = &SignalStatus{Name: "jfr", Enabled: p.cfg.Pipelines.JFR.Enabled, Running: false}
	if p.cfg.Pipelines.JFR.Enabled {
		if err := p.startJFRPipeline(ctx); err != nil {
			p.signals["jfr"].Error = err.Error()
			logger.Warn("jfr failed to start", "error", err, "status", "continuing_without_jfr")
		} else {
			p.signals["jfr"].Running = true
		}
	}

	// eBPF instrumentation (OBI-based auto-instrumentation)
	p.signals["ebpf"] = &SignalStatus{Name: "ebpf", Enabled: p.cfg.EBPF.Enabled, Running: false}
	if p.cfg.EBPF.Enabled {
		if err := p.startEBPFPipeline(ctx); err != nil {
			p.signals["ebpf"].Error = err.Error()
			logger.Error("ebpf instrumentation failed to start", "error", err, "status", "continuing_without_ebpf")
		} else {
			p.signals["ebpf"].Running = true
			logger.Info("ebpf instrumentation started", "features", "auto_instrumentation,context_propagation,protocol_detection")
		}
	}

	// Log summary of signal status
	running := p.SignalsStarted()
	total := len(p.signals)
	logger.Info("pipeline signal summary", "running", running, "total", total)
	for name, status := range p.signals {
		if status.Enabled && !status.Running {
			logger.Warn("signal degraded", "signal", name, "error", status.Error)
		}
	}

	p.st.SetReady(true)
	return nil
}

func (p *Pipeline) runRemoteWrite(ctx context.Context) {
	for ctx.Err() == nil {
		p.st.QueueSize.WithLabelValues("metrics").Set(float64(p.qMetrics.Len()))
		p.qMetrics.DropExpired(p.cfg.Queues.Metrics.MaxAge())
		batch := p.qMetrics.PopBatch(500, 1*time.Second)
		if len(batch) == 0 {
			continue
		}
		var wr prompb.WriteRequest
		for _, it := range batch {
			wr.Timeseries = append(wr.Timeseries, it.V.Timeseries...)
			wr.Metadata = append(wr.Metadata, it.V.Metadata...)
		}
		if len(p.cfg.Exports.RemoteWrite.Endpoints) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}
		ep := p.cfg.Exports.RemoteWrite.Endpoints[0]
		if err := p.rw.Send(ctx, &wr, remotewrite.Endpoint{URL: ep.URL, Timeout: mustDur(ep.Timeout), Headers: ep.Headers, Tenant: ep.Tenant, Compression: ep.Compression}); err != nil {
			p.st.ExportFails.WithLabelValues("metrics", "remote_write").Inc()
			time.Sleep(2 * time.Second)
			p.qMetrics.Push(&wr)
			continue
		}
		p.st.ObserveLatency("metrics", "remote_write", 100*time.Millisecond)
	}
}

func mustDur(s string) time.Duration { d, _ := time.ParseDuration(s); return d }

func (p *Pipeline) EnqueueMetrics(wr *prompb.WriteRequest) {
	if len(p.awsLabels) > 0 && wr != nil {
		for i := range wr.Timeseries {
			// Build a set of existing labels for quick lookup
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

func (p *Pipeline) startJFRPipeline(ctx context.Context) error {
	jfrCfg := p.cfg.Pipelines.JFR

	// Set defaults
	outputDir := jfrCfg.OutputDir
	if outputDir == "" {
		outputDir = "/var/log/jfr-json"
	}
	workers := jfrCfg.Workers
	if workers <= 0 {
		workers = 2
	}
	sampleIntervalMs := jfrCfg.SampleIntervalMs
	if sampleIntervalMs <= 0 {
		sampleIntervalMs = 10
	}
	jfrCommand := jfrCfg.JFRCommand
	if jfrCommand == "" {
		jfrCommand = "jfr"
	}

	// Create logger for JFR components
	zapLogger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Get K8s metadata from environment (standard downward API)
	podName := os.Getenv("K8S_POD_NAME")
	namespace := os.Getenv("K8S_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	containerName := os.Getenv("K8S_CONTAINER_NAME")
	nodeName := os.Getenv("K8S_NODE_NAME")

	// Create converter
	conv := converter.New(converter.Options{
		ServiceName:      p.cfg.Agent.ServiceName,
		PodName:          podName,
		Namespace:        namespace,
		ContainerName:    containerName,
		NodeName:         nodeName,
		SampleIntervalMs: sampleIntervalMs,
		JFRCommand:       jfrCommand,
		PrettyJSON:       jfrCfg.PrettyJSON,
		Logger:           zapLogger,
	})

	// Get all input directories
	inputDirs := jfrCfg.GetInputDirs()
	if len(inputDirs) == 0 {
		inputDirs = []string{"/var/log/jfr"} // Default if none configured
	}

	// Use IsRecursive() which defaults to true if not explicitly set
	recursive := jfrCfg.IsRecursive()

	logger.Info("jfr scanning configuration", "recursive", recursive, "input_dirs", inputDirs)

	// Build watcher options
	watcherOpts := watcher.Options{
		InputDirs:    inputDirs,
		Recursive:    recursive,
		OutputDir:    outputDir,
		PollInterval: jfrCfg.PollIntervalDuration(),
		Workers:      workers,
		Converter:    conv,
		Logger:       zapLogger,
	}

	// Configure direct export if enabled
	if jfrCfg.DirectExport.Enabled {
		watcherOpts.DirectExport = true
		watcherOpts.SkipFileOutput = jfrCfg.DirectExport.SkipFileOutput

		// Create profile exporter for direct OTLP export
		if jfrCfg.DirectExport.Endpoint != "" {
			profileExporter, err := p.createJFRProfileExporter(jfrCfg.DirectExport, zapLogger)
			if err != nil {
				logger.Error("jfr failed to create profile exporter", "error", err)
			} else {
				watcherOpts.Exporter = profileExporter
				logger.Info("jfr direct OTLP export enabled", "endpoint", jfrCfg.DirectExport.Endpoint)
			}
		}

		// Configure log export if enabled
		if jfrCfg.DirectExport.LogExport.Enabled {
			logExporter, err := p.createJFRLogExporter(jfrCfg.DirectExport.LogExport, podName, namespace, containerName, nodeName, zapLogger)
			if err != nil {
				logger.Error("jfr failed to create log exporter", "error", err)
			} else {
				watcherOpts.LogExportEnabled = true
				watcherOpts.LogExporter = logExporter
				logger.Info("jfr OTLP log export enabled", "endpoint", jfrCfg.DirectExport.LogExport.Endpoint)
			}
		}
	}

	// Create watcher
	w := watcher.New(watcherOpts)

	logger.Info("jfr starting pipeline",
		"input_dirs", inputDirs,
		"recursive", recursive,
		"output", outputDir,
		"workers", workers,
		"direct_export", jfrCfg.DirectExport.Enabled,
		"log_export", jfrCfg.DirectExport.LogExport.Enabled)

	// Run watcher in background
	go func() {
		if err := w.Run(ctx); err != nil && err != context.Canceled {
			logger.Warn("jfr watcher error", "error", err, "status", "signal_degraded")
		}
	}()

	return nil
}

// createJFRProfileExporter creates an OTLP profile exporter for JFR
func (p *Pipeline) createJFRProfileExporter(cfg config.DirectExportConfig, zapLogger *zap.Logger) (watcher.ProfileExporter, error) {
	slogger := slogFromZap(zapLogger)

	// Determine protocol from endpoint URL
	protocol := otlp.ProtocolGRPC
	if strings.HasPrefix(cfg.Endpoint, "http://") || strings.HasPrefix(cfg.Endpoint, "https://") {
		protocol = otlp.ProtocolHTTPProtobuf
	}

	// Create the base OTLP exporter
	exporterCfg := otlp.Config{
		Endpoint: cfg.Endpoint,
		Protocol: protocol,
		Headers:  cfg.Headers,
		Timeout:  cfg.TimeoutDuration(),
		Profiles: otlp.SignalConfig{
			Enabled: true,
		},
	}

	if cfg.Compression == "gzip" {
		exporterCfg.Compression = otlp.CompressionGzip
	}

	exporter, err := otlp.NewExporter(exporterCfg, slogger)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Start the exporter to initialize the transport
	if err := exporter.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to start OTLP exporter: %w", err)
	}

	// Create the profile exporter wrapper
	profileCfg := otlp.DefaultProfileExporterConfig()
	if cfg.BatchSize > 0 {
		profileCfg.BatchSize = cfg.BatchSize
	}
	profileCfg.FlushInterval = cfg.FlushIntervalDuration()

	return otlp.NewProfileExporter(exporter, profileCfg, slogger), nil
}

// createJFRLogExporter creates a multi-destination log exporter for JFR events
func (p *Pipeline) createJFRLogExporter(cfg config.LogExportConfig, podName, namespace, containerName, nodeName string, zapLogger *zap.Logger) (watcher.LogExporter, error) {
	slogger := slogFromZap(zapLogger)

	// Determine OTLP endpoint
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:4318/v1/logs"
	}

	// Build OTLP config
	otlpCfg := converter.OTLPLogExporterConfig{
		Endpoint:          endpoint,
		Headers:           cfg.Headers,
		Compression:       cfg.Compression,
		Timeout:           cfg.TimeoutDuration(),
		BatchSize:         cfg.BatchSize,
		FlushInterval:     cfg.FlushIntervalDuration(),
		IncludeStackTrace: cfg.IncludeStackTrace,
		IncludeRawJSON:    cfg.IncludeRawJSON,
		ServiceName:       p.cfg.Agent.ServiceName,
		Namespace:         namespace,
		PodName:           podName,
		ContainerName:     containerName,
		NodeName:          nodeName,
	}

	// Set defaults
	if otlpCfg.BatchSize <= 0 {
		otlpCfg.BatchSize = 100
	}
	if otlpCfg.Compression == "" {
		otlpCfg.Compression = "gzip"
	}

	// Build multi-exporter config
	multiCfg := converter.MultiLogExporterConfig{
		// Stdout output
		StdoutEnabled: cfg.StdoutEnabled,
		StdoutFormat:  cfg.StdoutFormat,

		// Disk output
		DiskEnabled:    cfg.DiskEnabled,
		DiskPath:       cfg.DiskPath,
		DiskRotateSize: cfg.DiskRotateSizeBytes(),
		DiskMaxFiles:   cfg.DiskMaxFiles,

		// OTLP output
		OTLPEnabled: cfg.IsOTLPEnabled(),
		OTLPConfig:  otlpCfg,

		// Common settings
		BatchSize:     otlpCfg.BatchSize,
		FlushInterval: otlpCfg.FlushInterval,

		// Service metadata
		ServiceName:   p.cfg.Agent.ServiceName,
		Namespace:     namespace,
		PodName:       podName,
		ContainerName: containerName,
		NodeName:      nodeName,
	}

	// Set default disk max files
	if multiCfg.DiskMaxFiles <= 0 {
		multiCfg.DiskMaxFiles = 5
	}

	// Set default stdout format
	if multiCfg.StdoutFormat == "" {
		multiCfg.StdoutFormat = "json"
	}

	// Log enabled outputs
	logger.Info("jfr log export destinations",
		"stdout_enabled", multiCfg.StdoutEnabled,
		"disk_enabled", multiCfg.DiskEnabled,
		"disk_path", multiCfg.DiskPath,
		"otlp_enabled", multiCfg.OTLPEnabled,
		"otlp_endpoint", endpoint)

	return converter.NewMultiLogExporter(multiCfg, slogger)
}

// slogFromZap creates a basic slog.Logger (adapter pattern)
func slogFromZap(zapLogger *zap.Logger) *slog.Logger {
	return slog.Default()
}

// GetMetricsExporter returns the OTLP metrics exporter for use by kube_metrics, node_exporter, ebpf, etc.
// Returns nil if OTLP was not initialized or metrics export is not available.
// This enables the telegen design principle: all signals share one exporter connection.
func (p *Pipeline) GetMetricsExporter() sdkmetric.Exporter {
	if p.ot == nil {
		return nil
	}
	return p.ot.Metrics
}

// GetLogsConsumer returns a logs consumer that can be used by the Kafka receiver to export logs.
// Returns nil if OTLP was not initialized or logs export is not available.
// This enables the telegen design principle: all signals share one exporter connection.
func (p *Pipeline) GetLogsConsumer() consumer.Logs {
	if p.ot == nil || p.ot.Log == nil {
		return nil
	}
	// Use the kafka adapter to convert plog.Logs to SDK log records
	return kafka.NewLogsConsumerAdapter(p.ot.Log)
}

// GetLogsLoggerProvider returns the SDK LoggerProvider for use by the Kafka receiver.
// Returns nil if OTLP was not initialized or logs export is not available.
// This provides direct access to the LoggerProvider bypassing the consumer.Logs adapter.
func (p *Pipeline) GetLogsLoggerProvider() *sdklog.LoggerProvider {
	if p.ot == nil || p.ot.Log == nil {
		return nil
	}
	return p.ot.Log
}

// GetTracesExporter returns the Collector-compatible OTLP traces exporter for use by eBPF traces.
// Returns nil if OTLP was not initialized or traces export is not available.
// This follows the OpenTelemetry Collector standard (exporter.Traces interface) and enables
// the telegen design principle: all signals share one exporter connection.
func (p *Pipeline) GetTracesExporter() exporter.Traces {
	if p.ot == nil {
		return nil
	}
	return p.ot.CollectorTraces
}

// GetKubeStore returns the Kubernetes metadata store used by eBPF instrumentation.
// Returns nil if eBPF is not enabled or Kubernetes is not configured.
// The profiler can use this to access the same kube.Store for namespace resolution.
func (p *Pipeline) GetKubeStore(ctx context.Context) (*kube.Store, error) {
	if p.ebpfCtxInfo == nil || p.ebpfCtxInfo.K8sInformer == nil {
		return nil, nil
	}
	return p.ebpfCtxInfo.K8sInformer.Get(ctx)
}

// startEBPFPipeline initializes and starts the eBPF auto-instrumentation pipeline
func (p *Pipeline) startEBPFPipeline(ctx context.Context) error {
	// Build obi.Config from telegen config
	obiCfg, err := p.buildOBIConfig()
	if err != nil {
		return fmt.Errorf("failed to build OBI config: %w", err)
	}

	// Get the shared OTEL exporters from the unified pipeline
	// This enables the telegen design principle: all signals share one exporter connection
	var sharedMetricsExporter = p.GetMetricsExporter()
	var sharedTracesExporter = p.GetTracesExporter()

	// Build common context info with shared OTEL exporters
	ctxInfo, err := instrumenter.BuildCommonContextInfoWithExporter(ctx, obiCfg, sharedMetricsExporter, sharedTracesExporter)
	if err != nil {
		return fmt.Errorf("failed to build context info: %w", err)
	}
	p.ebpfCtxInfo = ctxInfo

	// Create the instrumenter
	instr, err := appollycore.New(ctx, ctxInfo, obiCfg)
	if err != nil {
		return fmt.Errorf("failed to create instrumenter: %w", err)
	}
	p.ebpfInstrumenter = instr

	// Start process discovery and instrumentation
	if err := instr.FindAndInstrument(ctx); err != nil {
		return fmt.Errorf("failed to start process discovery: %w", err)
	}

	// Start reading and forwarding traces/metrics in background
	go func() {
		if err := instr.ReadAndForward(ctx); err != nil && ctx.Err() == nil {
			logger.Error("ebpf read and forward error", "error", err)
		}
	}()

	// Wait for instrumenter to finish in background
	go func() {
		if err := instr.WaitUntilFinished(); err != nil {
			logger.Error("ebpf pipeline finished with error", "error", err)
		} else {
			logger.Info("ebpf pipeline finished")
		}
	}()

	return nil
}

// buildOBIConfig creates an obi.Config from the telegen config.EBPFConfig
func (p *Pipeline) buildOBIConfig() (*obi.Config, error) {
	ebpfCfg := p.cfg.EBPF

	// Start with default config and override with telegen settings
	cfg := obi.DefaultConfig

	// Propagate Kubernetes settings from pipeline config to OBI config
	// This bridges the two config systems for k8s metadata decoration
	if p.cfg.Kubernetes.ClusterName != "" {
		cfg.Attributes.Kubernetes.ClusterName = p.cfg.Kubernetes.ClusterName
	}
	if p.cfg.Kubernetes.Enable {
		cfg.Attributes.Kubernetes.Enable = "true"
	}

	// Merge tracer settings - only override non-zero values to preserve defaults
	// like BatchLength=100, BatchTimeout=1s, DNSRequestTimeout=5s
	if ebpfCfg.Tracer.BpfDebug {
		cfg.EBPF.BpfDebug = ebpfCfg.Tracer.BpfDebug
	}
	if ebpfCfg.Tracer.WakeupLen > 0 {
		cfg.EBPF.WakeupLen = ebpfCfg.Tracer.WakeupLen
	}
	if ebpfCfg.Tracer.BatchLength > 0 {
		cfg.EBPF.BatchLength = ebpfCfg.Tracer.BatchLength
	}
	if ebpfCfg.Tracer.BatchTimeout > 0 {
		cfg.EBPF.BatchTimeout = ebpfCfg.Tracer.BatchTimeout
	}
	if ebpfCfg.Tracer.HTTPRequestTimeout > 0 {
		cfg.EBPF.HTTPRequestTimeout = ebpfCfg.Tracer.HTTPRequestTimeout
	}
	if ebpfCfg.Tracer.DNSRequestTimeout > 0 {
		cfg.EBPF.DNSRequestTimeout = ebpfCfg.Tracer.DNSRequestTimeout
	}
	if ebpfCfg.Tracer.ContextPropagation != 0 {
		cfg.EBPF.ContextPropagation = ebpfCfg.Tracer.ContextPropagation
	}
	if ebpfCfg.Tracer.TCBackend != 0 {
		cfg.EBPF.TCBackend = ebpfCfg.Tracer.TCBackend
	}
	if ebpfCfg.Tracer.MaxTransactionTime > 0 {
		cfg.EBPF.MaxTransactionTime = ebpfCfg.Tracer.MaxTransactionTime
	}
	if ebpfCfg.Tracer.MySQLPreparedStatementsCacheSize > 0 {
		cfg.EBPF.MySQLPreparedStatementsCacheSize = ebpfCfg.Tracer.MySQLPreparedStatementsCacheSize
	}
	if ebpfCfg.Tracer.PostgresPreparedStatementsCacheSize > 0 {
		cfg.EBPF.PostgresPreparedStatementsCacheSize = ebpfCfg.Tracer.PostgresPreparedStatementsCacheSize
	}
	if ebpfCfg.Tracer.MongoRequestsCacheSize > 0 {
		cfg.EBPF.MongoRequestsCacheSize = ebpfCfg.Tracer.MongoRequestsCacheSize
	}
	if ebpfCfg.Tracer.KafkaTopicUUIDCacheSize > 0 {
		cfg.EBPF.KafkaTopicUUIDCacheSize = ebpfCfg.Tracer.KafkaTopicUUIDCacheSize
	}
	if ebpfCfg.Tracer.CouchbaseDBCacheSize > 0 {
		cfg.EBPF.CouchbaseDBCacheSize = ebpfCfg.Tracer.CouchbaseDBCacheSize
	}
	// Boolean flags that can be explicitly set
	cfg.EBPF.TrackRequestHeaders = ebpfCfg.Tracer.TrackRequestHeaders
	cfg.EBPF.OverrideBPFLoopEnabled = ebpfCfg.Tracer.OverrideBPFLoopEnabled
	cfg.EBPF.DisableBlackBoxCP = ebpfCfg.Tracer.DisableBlackBoxCP
	cfg.EBPF.HighRequestVolume = ebpfCfg.Tracer.HighRequestVolume
	cfg.EBPF.HeuristicSQLDetect = ebpfCfg.Tracer.HeuristicSQLDetect
	cfg.EBPF.InstrumentGPU = ebpfCfg.Tracer.InstrumentGPU
	cfg.EBPF.ProtocolDebug = ebpfCfg.Tracer.ProtocolDebug
	// Nested configs
	cfg.EBPF.RedisDBCache = ebpfCfg.Tracer.RedisDBCache
	cfg.EBPF.BufferSizes = ebpfCfg.Tracer.BufferSizes
	cfg.EBPF.PayloadExtraction = ebpfCfg.Tracer.PayloadExtraction
	cfg.EBPF.LogEnricher = ebpfCfg.Tracer.LogEnricher

	// Discovery configuration - these are usually user-defined, safe to overwrite
	cfg.Discovery = ebpfCfg.Discovery

	// Name resolver
	if ebpfCfg.NameResolver != nil {
		cfg.NameResolver = ebpfCfg.NameResolver
	}

	// Routes - only override if user provided one
	if ebpfCfg.Routes != nil {
		cfg.Routes = ebpfCfg.Routes
	}

	// Filters
	cfg.Filters = ebpfCfg.Filters

	// OTEL Metrics export - merge with defaults to preserve ReportersCacheLen etc
	// Only override fields that are explicitly set in ebpfCfg
	if ebpfCfg.OTELMetrics.CommonEndpoint != "" {
		cfg.OTELMetrics.CommonEndpoint = ebpfCfg.OTELMetrics.CommonEndpoint
	}
	if ebpfCfg.OTELMetrics.MetricsEndpoint != "" {
		cfg.OTELMetrics.MetricsEndpoint = ebpfCfg.OTELMetrics.MetricsEndpoint
	}
	if ebpfCfg.OTELMetrics.Protocol != "" {
		cfg.OTELMetrics.Protocol = ebpfCfg.OTELMetrics.Protocol
	}
	if ebpfCfg.OTELMetrics.MetricsProtocol != "" {
		cfg.OTELMetrics.MetricsProtocol = ebpfCfg.OTELMetrics.MetricsProtocol
	}
	if ebpfCfg.OTELMetrics.Interval > 0 {
		cfg.OTELMetrics.Interval = ebpfCfg.OTELMetrics.Interval
	}
	if ebpfCfg.OTELMetrics.ReportersCacheLen > 0 {
		cfg.OTELMetrics.ReportersCacheLen = ebpfCfg.OTELMetrics.ReportersCacheLen
	}
	if ebpfCfg.OTELMetrics.TTL > 0 {
		cfg.OTELMetrics.TTL = ebpfCfg.OTELMetrics.TTL
	}
	if len(ebpfCfg.OTELMetrics.Instrumentations) > 0 {
		cfg.OTELMetrics.Instrumentations = ebpfCfg.OTELMetrics.Instrumentations
	}
	cfg.OTELMetrics.InsecureSkipVerify = ebpfCfg.OTELMetrics.InsecureSkipVerify

	// Note: The shared exporter from GetMetricsExporter() is now passed directly to
	// BuildCommonContextInfoWithExporter() in startEBPFPipeline(), so endpoint/insecure
	// propagation here is only needed as a fallback for when SharedExporter is nil.
	// This legacy code path will be removed once all callers use the shared exporter.
	if !cfg.OTELMetrics.EndpointEnabled() && p.cfg.Exports.OTLP.GRPC.Enabled {
		cfg.OTELMetrics.CommonEndpoint = p.cfg.Exports.OTLP.GRPC.Endpoint
		// Also propagate insecure setting from shared OTLP config
		if p.cfg.Exports.OTLP.GRPC.Insecure {
			cfg.OTELMetrics.Insecure = true
		}
	}

	// Traces export - merge with defaults to preserve ReportersCacheLen etc
	if ebpfCfg.Traces.CommonEndpoint != "" {
		cfg.Traces.CommonEndpoint = ebpfCfg.Traces.CommonEndpoint
	}
	if ebpfCfg.Traces.TracesEndpoint != "" {
		cfg.Traces.TracesEndpoint = ebpfCfg.Traces.TracesEndpoint
	}
	if ebpfCfg.Traces.Protocol != "" {
		cfg.Traces.Protocol = ebpfCfg.Traces.Protocol
	}
	if ebpfCfg.Traces.TracesProtocol != "" {
		cfg.Traces.TracesProtocol = ebpfCfg.Traces.TracesProtocol
	}
	if ebpfCfg.Traces.MaxQueueSize > 0 {
		cfg.Traces.MaxQueueSize = ebpfCfg.Traces.MaxQueueSize
	}
	if ebpfCfg.Traces.BatchTimeout > 0 {
		cfg.Traces.BatchTimeout = ebpfCfg.Traces.BatchTimeout
	}
	if ebpfCfg.Traces.ReportersCacheLen > 0 {
		cfg.Traces.ReportersCacheLen = ebpfCfg.Traces.ReportersCacheLen
	}
	if len(ebpfCfg.Traces.Instrumentations) > 0 {
		cfg.Traces.Instrumentations = ebpfCfg.Traces.Instrumentations
	}
	cfg.Traces.InsecureSkipVerify = ebpfCfg.Traces.InsecureSkipVerify
	// Use shared OTLP endpoint from exports.otlp if not set
	tracesEp, _ := cfg.Traces.OTLPTracesEndpoint()
	if tracesEp == "" && p.cfg.Exports.OTLP.GRPC.Enabled {
		cfg.Traces.CommonEndpoint = p.cfg.Exports.OTLP.GRPC.Endpoint
		// Also propagate insecure setting from shared OTLP config
		if p.cfg.Exports.OTLP.GRPC.Insecure {
			cfg.Traces.Insecure = true
		}
	}

	// Prometheus export - merge with defaults to preserve Path, Buckets, TTL, SpanMetricsServiceCacheSize
	if ebpfCfg.Prometheus.Port > 0 {
		cfg.Prometheus.Port = ebpfCfg.Prometheus.Port
	}
	if ebpfCfg.Prometheus.Path != "" {
		cfg.Prometheus.Path = ebpfCfg.Prometheus.Path
	}
	if ebpfCfg.Prometheus.Buckets.DurationHistogram != nil {
		cfg.Prometheus.Buckets.DurationHistogram = ebpfCfg.Prometheus.Buckets.DurationHistogram
	}
	if ebpfCfg.Prometheus.Buckets.RequestSizeHistogram != nil {
		cfg.Prometheus.Buckets.RequestSizeHistogram = ebpfCfg.Prometheus.Buckets.RequestSizeHistogram
	}
	if ebpfCfg.Prometheus.TTL > 0 {
		cfg.Prometheus.TTL = ebpfCfg.Prometheus.TTL
	}
	if ebpfCfg.Prometheus.SpanMetricsServiceCacheSize > 0 {
		cfg.Prometheus.SpanMetricsServiceCacheSize = ebpfCfg.Prometheus.SpanMetricsServiceCacheSize
	}
	if len(ebpfCfg.Prometheus.Instrumentations) > 0 {
		cfg.Prometheus.Instrumentations = ebpfCfg.Prometheus.Instrumentations
	}
	if len(ebpfCfg.Prometheus.ExtraResourceLabels) > 0 {
		cfg.Prometheus.ExtraResourceLabels = ebpfCfg.Prometheus.ExtraResourceLabels
	}
	if len(ebpfCfg.Prometheus.ExtraSpanResourceLabels) > 0 {
		cfg.Prometheus.ExtraSpanResourceLabels = ebpfCfg.Prometheus.ExtraSpanResourceLabels
	}
	cfg.Prometheus.DisableBuildInfo = ebpfCfg.Prometheus.DisableBuildInfo
	cfg.Prometheus.AllowServiceGraphSelfReferences = ebpfCfg.Prometheus.AllowServiceGraphSelfReferences
	// Registry is only for Grafana Agent embedding
	if ebpfCfg.Prometheus.Registry != nil {
		cfg.Prometheus.Registry = ebpfCfg.Prometheus.Registry
	}

	// Network flows (for network observability)
	if ebpfCfg.NetworkFlows.Enabled {
		// Enable network observability feature
		cfg.NetworkFlows.Enable = true
	}

	return &cfg, nil
}

func (p *Pipeline) Close() {
	close(p.stop)
}
