package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/config"
	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	otlp "github.com/mirastacklabs-ai/telegen/internal/exporters/otlp"
	"github.com/mirastacklabs-ai/telegen/internal/instrumenter"
	"github.com/mirastacklabs-ai/telegen/internal/jfr/converter"
	"github.com/mirastacklabs-ai/telegen/internal/jfr/watcher"
	"github.com/mirastacklabs-ai/telegen/internal/obi"
	obiconfig "github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
	"go.uber.org/zap"
)

func (p *UnifiedPipeline) startJFRSource(ctx context.Context) error {
	if p.config.RuntimeConfig == nil {
		return nil
	}
	rcfg := p.config.RuntimeConfig
	jfrCfg := rcfg.Pipelines.JFR

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

	zapLogger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("failed to create JFR logger: %w", err)
	}

	podName := os.Getenv("K8S_POD_NAME")
	namespace := os.Getenv("K8S_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	containerName := os.Getenv("K8S_CONTAINER_NAME")
	nodeName := os.Getenv("K8S_NODE_NAME")

	conv := converter.New(converter.Options{
		ServiceName:      rcfg.Agent.ServiceName,
		PodName:          podName,
		Namespace:        namespace,
		ContainerName:    containerName,
		NodeName:         nodeName,
		SampleIntervalMs: sampleIntervalMs,
		JFRCommand:       jfrCommand,
		PrettyJSON:       jfrCfg.PrettyJSON,
		Logger:           zapLogger,
	})

	inputDirs := jfrCfg.GetInputDirs()
	if len(inputDirs) == 0 {
		inputDirs = []string{"/var/log/jfr"}
	}
	recursive := jfrCfg.IsRecursive()

	p.logger.Info("jfr scanning configuration", "recursive", recursive, "input_dirs", inputDirs)

	watcherOpts := watcher.Options{
		InputDirs:    inputDirs,
		Recursive:    recursive,
		OutputDir:    outputDir,
		PollInterval: jfrCfg.PollIntervalDuration(),
		Workers:      workers,
		Converter:    conv,
		Logger:       zapLogger,
	}

	if jfrCfg.DirectExport.Enabled {
		watcherOpts.DirectExport = true
		watcherOpts.SkipFileOutput = jfrCfg.DirectExport.SkipFileOutput

		if jfrCfg.DirectExport.Endpoint != "" {
			profileExporter, err := p.createJFRProfileExporter(jfrCfg.DirectExport, zapLogger)
			if err != nil {
				p.logger.Error("jfr failed to create profile exporter", "error", err)
			} else {
				watcherOpts.Exporter = profileExporter
				p.logger.Info("jfr direct OTLP export enabled", "endpoint", jfrCfg.DirectExport.Endpoint)
			}
		}

		if jfrCfg.DirectExport.LogExport.Enabled {
			logExporter, err := p.createJFRLogExporter(jfrCfg.DirectExport.LogExport, podName, namespace, containerName, nodeName, zapLogger)
			if err != nil {
				p.logger.Error("jfr failed to create log exporter", "error", err)
			} else {
				watcherOpts.LogExportEnabled = true
				watcherOpts.LogExporter = logExporter
				p.logger.Info("jfr OTLP log export enabled", "endpoint", jfrCfg.DirectExport.LogExport.Endpoint)
			}
		}
	}

	w := watcher.New(watcherOpts)
	p.logger.Info("jfr starting pipeline",
		"input_dirs", inputDirs,
		"recursive", recursive,
		"output", outputDir,
		"workers", workers,
		"direct_export", jfrCfg.DirectExport.Enabled,
		"log_export", jfrCfg.DirectExport.LogExport.Enabled,
	)
	go func() {
		if err := w.Run(ctx); err != nil && err != context.Canceled {
			p.logger.Warn("jfr watcher error", "error", err, "status", "signal_degraded")
		}
	}()
	return nil
}

func (p *UnifiedPipeline) createJFRProfileExporter(cfg config.DirectExportConfig, zapLogger *zap.Logger) (watcher.ProfileExporter, error) {
	slogger := slogFromZapLogger(zapLogger)

	protocol := otlp.ProtocolGRPC
	if strings.HasPrefix(cfg.Endpoint, "http://") || strings.HasPrefix(cfg.Endpoint, "https://") {
		protocol = otlp.ProtocolHTTPProtobuf
	}

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
	if err := exporter.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to start OTLP exporter: %w", err)
	}

	profileCfg := otlp.DefaultProfileExporterConfig()
	if cfg.BatchSize > 0 {
		profileCfg.BatchSize = cfg.BatchSize
	}
	profileCfg.FlushInterval = cfg.FlushIntervalDuration()

	return otlp.NewProfileExporter(exporter, profileCfg, slogger), nil
}

func (p *UnifiedPipeline) createJFRLogExporter(cfg config.LogExportConfig, podName, namespace, containerName, nodeName string, zapLogger *zap.Logger) (watcher.LogExporter, error) {
	slogger := slogFromZapLogger(zapLogger)

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:4318/v1/logs"
	}

	otlpCfg := converter.OTLPLogExporterConfig{
		Endpoint:          endpoint,
		Headers:           cfg.Headers,
		Compression:       cfg.Compression,
		Timeout:           cfg.TimeoutDuration(),
		BatchSize:         cfg.BatchSize,
		FlushInterval:     cfg.FlushIntervalDuration(),
		IncludeStackTrace: cfg.IncludeStackTrace,
		IncludeRawJSON:    cfg.IncludeRawJSON,
		ServiceName:       p.config.RuntimeConfig.Agent.ServiceName,
		Namespace:         namespace,
		PodName:           podName,
		ContainerName:     containerName,
		NodeName:          nodeName,
	}
	if otlpCfg.BatchSize <= 0 {
		otlpCfg.BatchSize = 100
	}
	if otlpCfg.Compression == "" {
		otlpCfg.Compression = "gzip"
	}

	multiCfg := converter.MultiLogExporterConfig{
		StdoutEnabled:  cfg.StdoutEnabled,
		StdoutFormat:   cfg.StdoutFormat,
		DiskEnabled:    cfg.DiskEnabled,
		DiskPath:       cfg.DiskPath,
		DiskRotateSize: cfg.DiskRotateSizeBytes(),
		DiskMaxFiles:   cfg.DiskMaxFiles,
		OTLPEnabled:    cfg.IsOTLPEnabled(),
		OTLPConfig:     otlpCfg,
		BatchSize:      otlpCfg.BatchSize,
		FlushInterval:  otlpCfg.FlushInterval,
		ServiceName:    p.config.RuntimeConfig.Agent.ServiceName,
		Namespace:      namespace,
		PodName:        podName,
		ContainerName:  containerName,
		NodeName:       nodeName,
	}
	if multiCfg.DiskMaxFiles <= 0 {
		multiCfg.DiskMaxFiles = 5
	}
	if multiCfg.StdoutFormat == "" {
		multiCfg.StdoutFormat = "json"
	}

	p.logger.Info("jfr log export destinations",
		"stdout_enabled", multiCfg.StdoutEnabled,
		"disk_enabled", multiCfg.DiskEnabled,
		"disk_path", multiCfg.DiskPath,
		"otlp_enabled", multiCfg.OTLPEnabled,
		"otlp_endpoint", endpoint,
	)
	return converter.NewMultiLogExporter(multiCfg, slogger)
}

func (p *UnifiedPipeline) startEBPFSource(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("ebpf instrumentation is supported on linux only")
	}
	obiCfg, err := p.buildOBIConfig()
	if err != nil {
		return fmt.Errorf("failed to build OBI config: %w", err)
	}

	ctxInfo, err := instrumenter.BuildCommonContextInfo(ctx, obiCfg)
	if err != nil {
		return fmt.Errorf("failed to build context info: %w", err)
	}
	p.ebpfCtxInfo = ctxInfo

	appQueue := msg.NewQueue[[]request.Span](
		msg.ChannelBufferLen(256),
		msg.Name("telegen.obi.app_export"),
	)
	go instrumenter.ConsumeUpstreamSpanQueue(ctx, appQueue, func(_ context.Context, batch []request.Span) error {
		if err := p.forwardOBISpanBatch(ctx, batch); err != nil {
			return err
		}
		p.logger.Debug("upstream OBI span batch received", "batch_size", len(batch))
		return nil
	})

	sharedMetricsExporter := p.GetMetricsExporter()
	go func() {
		if err := instrumenter.RunUpstream(ctx, obiCfg, sharedMetricsExporter, appQueue); err != nil && ctx.Err() == nil {
			p.logger.Error("ebpf upstream OBI runtime error", "error", err)
		}
	}()
	return nil
}

func (p *UnifiedPipeline) buildOBIConfig() (*obi.Config, error) {
	if p.config.RuntimeConfig == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}
	rcfg := p.config.RuntimeConfig
	ebpfCfg := rcfg.EBPF

	cfg := obi.DefaultConfig

	if rcfg.Kubernetes.ClusterName != "" {
		cfg.Attributes.Kubernetes.ClusterName = rcfg.Kubernetes.ClusterName
	}
	if rcfg.Kubernetes.Enable {
		cfg.Attributes.Kubernetes.Enable = "true"
	}

	if ebpfCfg.Tracer.BpfDebug {
		cfg.EBPF.BpfDebug = ebpfCfg.Tracer.BpfDebug
	}
	if ebpfCfg.Tracer.WakeupLen > 0 {
		cfg.EBPF.WakeupLen = ebpfCfg.Tracer.WakeupLen
	}
	if ebpfCfg.Tracer.StatsWakeupDataBytes > 0 {
		cfg.EBPF.StatsWakeupDataBytes = ebpfCfg.Tracer.StatsWakeupDataBytes
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
	if ebpfCfg.Tracer.MSSQLPreparedStatementsCacheSize > 0 {
		cfg.EBPF.MSSQLPreparedStatementsCacheSize = ebpfCfg.Tracer.MSSQLPreparedStatementsCacheSize
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
	cfg.EBPF.TrackRequestHeaders = ebpfCfg.Tracer.TrackRequestHeaders
	cfg.EBPF.OverrideBPFLoopEnabled = ebpfCfg.Tracer.OverrideBPFLoopEnabled
	cfg.EBPF.DisableBlackBoxCP = ebpfCfg.Tracer.DisableBlackBoxCP
	cfg.EBPF.HighRequestVolume = ebpfCfg.Tracer.HighRequestVolume
	cfg.EBPF.HeuristicSQLDetect = ebpfCfg.Tracer.HeuristicSQLDetect
	if ebpfCfg.Tracer.InstrumentCuda != 0 {
		cfg.EBPF.InstrumentCuda = ebpfCfg.Tracer.InstrumentCuda
	}
	if ebpfCfg.Tracer.InstrumentGPU {
		cfg.EBPF.InstrumentCuda = obiconfig.CudaModeOn
	}
	cfg.EBPF.InstrumentGPU = ebpfCfg.Tracer.InstrumentGPU
	cfg.EBPF.ProtocolDebug = ebpfCfg.Tracer.ProtocolDebug
	cfg.EBPF.RedisDBCache = ebpfCfg.Tracer.RedisDBCache
	cfg.EBPF.BufferSizes = ebpfCfg.Tracer.BufferSizes
	cfg.EBPF.PayloadExtraction = ebpfCfg.Tracer.PayloadExtraction
	cfg.EBPF.LogEnricher = ebpfCfg.Tracer.LogEnricher
	if ebpfCfg.Tracer.BPFFSPath != "" {
		cfg.EBPF.BPFFSPath = ebpfCfg.Tracer.BPFFSPath
	}
	if ebpfCfg.Tracer.ForceBPFMapReader != 0 {
		cfg.EBPF.ForceBPFMapReader = ebpfCfg.Tracer.ForceBPFMapReader
	}
	if ebpfCfg.Tracer.MapsConfig.GlobalScaleFactor != 0 {
		cfg.EBPF.MapsConfig.GlobalScaleFactor = ebpfCfg.Tracer.MapsConfig.GlobalScaleFactor
	}

	cfg.Discovery = ebpfCfg.Discovery
	if ebpfCfg.NameResolver != nil {
		cfg.NameResolver = ebpfCfg.NameResolver
	}
	if ebpfCfg.Routes != nil {
		cfg.Routes = ebpfCfg.Routes
	}
	cfg.Filters = ebpfCfg.Filters

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
	if !cfg.OTELMetrics.EndpointEnabled() && rcfg.Exports.OTLP.GRPC.Enabled {
		cfg.OTELMetrics.CommonEndpoint = rcfg.Exports.OTLP.GRPC.Endpoint
		if rcfg.Exports.OTLP.GRPC.Insecure {
			cfg.OTELMetrics.Insecure = true
		}
	}

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
	tracesEp, _ := cfg.Traces.OTLPTracesEndpoint()
	if tracesEp == "" && rcfg.Exports.OTLP.GRPC.Enabled {
		cfg.Traces.CommonEndpoint = rcfg.Exports.OTLP.GRPC.Endpoint
		if rcfg.Exports.OTLP.GRPC.Insecure {
			cfg.Traces.Insecure = true
		}
	}

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
	if ebpfCfg.Prometheus.Registry != nil {
		cfg.Prometheus.Registry = ebpfCfg.Prometheus.Registry
	}

	if ebpfCfg.NetworkFlows.Enabled {
		cfg.NetworkFlows.Enable = true
	}
	return &cfg, nil
}

func slogFromZapLogger(_ *zap.Logger) *slog.Logger {
	return slog.Default()
}
