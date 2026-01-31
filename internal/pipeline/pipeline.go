package pipeline

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/platformbuilds/telegen/internal/config"
	"github.com/platformbuilds/telegen/internal/exporters/otlp"
	"github.com/platformbuilds/telegen/internal/exporters/remotewrite"
	"github.com/platformbuilds/telegen/internal/jfr/converter"
	"github.com/platformbuilds/telegen/internal/jfr/watcher"
	"github.com/platformbuilds/telegen/internal/logs/filetailer"
	awsm "github.com/platformbuilds/telegen/internal/metadata/aws"
	"github.com/platformbuilds/telegen/internal/metrics/host"
	"github.com/platformbuilds/telegen/internal/queue"
	"github.com/platformbuilds/telegen/internal/selftelemetry"

	"github.com/prometheus/prometheus/prompb"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/zap"
)

type Pipeline struct {
	cfg *config.Config
	st  *selftelemetry.Registry

	qMetrics *queue.Ring[*prompb.WriteRequest]
	stop     chan struct{}

	rw *remotewrite.Client
	ot *otlp.Clients

	awsLabels map[string]string
}

func New(cfg *config.Config, st *selftelemetry.Registry) *Pipeline {
	qm := queue.NewRing[*prompb.WriteRequest](8192, func(_ uint64, reason queue.DropReason) {
		st.QueueDropped.WithLabelValues("metrics", string(reason)).Inc()
	})
	return &Pipeline{cfg: cfg, st: st, qMetrics: qm, stop: make(chan struct{})}
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
			log.Printf("aws metadata: %v", err)
		}
	}

	var err error
	p.ot, err = otlp.New(ctx, topts, resRsrc)
	if err != nil {
		log.Printf("otlp init: %v", err)
	}

	go p.runRemoteWrite(ctx)

	if hostname, _ := os.Hostname(); true {
		col := host.New("telegen", hostname, 15*time.Second, p.EnqueueMetrics)
		if len(p.awsLabels) > 0 {
			col.SetExtraLabels(p.awsLabels)
		}
		go col.Run(p.stop)
	}
	if p.cfg.Pipelines.Logs.Enabled && p.ot != nil && p.ot.Log != nil {
		ft := filetailer.New(p.cfg.Pipelines.Logs.Filelog.Include, p.cfg.Pipelines.Logs.Filelog.PositionFile, p.ot.Log)
		go func() { _ = ft.Run(p.stop) }()
	}

	// JFR (Java Flight Recorder) profiling signal
	if p.cfg.Pipelines.JFR.Enabled {
		p.startJFRPipeline(ctx)
	}

	// eBPF instrumentation (OBI-based auto-instrumentation)
	if p.cfg.EBPF.Enabled {
		log.Printf("eBPF instrumentation enabled (context propagation, protocol detection)")
		// TODO: Initialize and start the OBI instrumenter pipeline
		// This will be done by calling internal/appolly.Build() with the config
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

func (p *Pipeline) startJFRPipeline(ctx context.Context) {
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
		log.Printf("jfr: failed to create logger: %v", err)
		return
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

	log.Printf("jfr: recursive scanning = %v, inputDirs = %v", recursive, inputDirs)

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
				log.Printf("jfr: failed to create profile exporter: %v", err)
			} else {
				watcherOpts.Exporter = profileExporter
				log.Printf("jfr: direct OTLP export enabled (endpoint=%s)", jfrCfg.DirectExport.Endpoint)
			}
		}

		// Configure log export if enabled
		if jfrCfg.DirectExport.LogExport.Enabled {
			logExporter, err := p.createJFRLogExporter(jfrCfg.DirectExport.LogExport, podName, namespace, containerName, nodeName, zapLogger)
			if err != nil {
				log.Printf("jfr: failed to create log exporter: %v", err)
			} else {
				watcherOpts.LogExportEnabled = true
				watcherOpts.LogExporter = logExporter
				log.Printf("jfr: OTLP log export enabled (endpoint=%s)", jfrCfg.DirectExport.LogExport.Endpoint)
			}
		}
	}

	// Create watcher
	w := watcher.New(watcherOpts)

	log.Printf("jfr: starting pipeline (inputDirs=%v, recursive=%v, output=%s, workers=%d, directExport=%v, logExport=%v)",
		inputDirs, recursive, outputDir, workers, jfrCfg.DirectExport.Enabled, jfrCfg.DirectExport.LogExport.Enabled)

	// Run watcher in background
	go func() {
		if err := w.Run(ctx); err != nil && err != context.Canceled {
			log.Printf("jfr: watcher error: %v", err)
		}
	}()
}

// createJFRProfileExporter creates an OTLP profile exporter for JFR
func (p *Pipeline) createJFRProfileExporter(cfg config.DirectExportConfig, zapLogger *zap.Logger) (watcher.ProfileExporter, error) {
	slogger := slogFromZap(zapLogger)

	// Create the base OTLP exporter
	exporterCfg := otlp.Config{
		Endpoint: cfg.Endpoint,
		Headers:  cfg.Headers,
		Timeout:  cfg.TimeoutDuration(),
		Profiles: otlp.SignalConfig{
			Enabled: true,
		},
	}

	if cfg.Compression == "gzip" {
		exporterCfg.Compression = "gzip"
	}

	exporter, err := otlp.NewExporter(exporterCfg, slogger)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
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
	log.Printf("jfr: log export destinations - stdout=%v, disk=%v (path=%s), otlp=%v (endpoint=%s)",
		multiCfg.StdoutEnabled,
		multiCfg.DiskEnabled, multiCfg.DiskPath,
		multiCfg.OTLPEnabled, endpoint)

	return converter.NewMultiLogExporter(multiCfg, slogger)
}

// slogFromZap creates a basic slog.Logger (adapter pattern)
func slogFromZap(zapLogger *zap.Logger) *slog.Logger {
	return slog.Default()
}

func (p *Pipeline) Close() { close(p.stop) }
