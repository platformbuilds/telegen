// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"

	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// StreamingConfig holds configuration for streaming export to OTLP
type StreamingConfig struct {
	// Enabled enables streaming metrics to OTLP endpoint
	Enabled bool `yaml:"enabled"`

	// Interval is how often to push metrics
	Interval time.Duration `yaml:"interval"`

	// BatchSize is the maximum number of metrics per batch
	BatchSize int `yaml:"batch_size"`

	// FlushTimeout is the maximum time to wait for a flush
	FlushTimeout time.Duration `yaml:"flush_timeout"`

	// UseOTLP indicates whether to use the OTLP exporter
	UseOTLP bool `yaml:"use_otlp"`

	// IncludeSignalMetadata adds telegen.* metadata attributes
	IncludeSignalMetadata bool `yaml:"include_signal_metadata"`

	// MetadataConfig controls which metadata fields are exported
	MetadataConfig sigdef.MetadataFieldsConfig `yaml:"metadata_config"`
}

// DefaultStreamingConfig returns sensible defaults for streaming
func DefaultStreamingConfig() StreamingConfig {
	return StreamingConfig{
		Enabled:               false,
		Interval:              15 * time.Second,
		BatchSize:             1000,
		FlushTimeout:          5 * time.Second,
		UseOTLP:               true,
		IncludeSignalMetadata: true,
		MetadataConfig:        sigdef.DefaultMetadataFieldsConfig(),
	}
}

// StreamingExporter streams kubemetrics to OTLP collector
type StreamingExporter struct {
	config   *StreamingConfig
	provider *Provider
	exporter sdkmetric.Exporter
	resource *resource.Resource
	logger   *slog.Logger

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}

	// Stats
	collectCount    int64
	collectDuration time.Duration
	exportCount     int64
	exportDuration  time.Duration
	lastExportTime  time.Time
	lastError       error
}

// NewStreamingExporter creates a new streaming exporter for kubemetrics
func NewStreamingExporter(
	cfg *StreamingConfig,
	provider *Provider,
	exporter sdkmetric.Exporter,
	logger *slog.Logger,
) (*StreamingExporter, error) {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1000
	}
	if cfg.FlushTimeout == 0 {
		cfg.FlushTimeout = 5 * time.Second
	}

	// Build resource with Kubernetes metadata
	res, err := buildKubeResource()
	if err != nil {
		return nil, err
	}

	return &StreamingExporter{
		config:   cfg,
		provider: provider,
		exporter: exporter,
		resource: res,
		logger:   logger,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}, nil
}

// buildKubeResource creates an OTEL resource with Kubernetes metadata.
// Uses NewSchemaless to avoid schema URL conflicts with SDK internal detectors.
// The shared OTLP exporter already has the proper resource with schema URL.
func buildKubeResource() (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("telegen-kubemetrics"),
		semconv.ServiceVersion("1.0.0"),
	}

	// Add Kubernetes attributes from environment
	if nodeName := getEnvOrDefault("KUBERNETES_NODE_NAME", ""); nodeName != "" {
		attrs = append(attrs, semconv.K8SNodeName(nodeName))
	}
	if namespace := getEnvOrDefault("KUBERNETES_NAMESPACE", ""); namespace != "" {
		attrs = append(attrs, semconv.K8SNamespaceName(namespace))
	}
	if podName := getEnvOrDefault("KUBERNETES_POD_NAME", ""); podName != "" {
		attrs = append(attrs, semconv.K8SPodName(podName))
	}
	if clusterName := getEnvOrDefault("KUBERNETES_CLUSTER_NAME", ""); clusterName != "" {
		attrs = append(attrs, semconv.K8SClusterName(clusterName))
	}

	return resource.NewSchemaless(attrs...), nil
}

// Start begins the streaming export loop
func (s *StreamingExporter) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	s.mu.Unlock()

	go s.run(ctx)

	s.logger.Info("kubemetrics streaming exporter started",
		"interval", s.config.Interval,
		"use_otlp", s.config.UseOTLP,
		"include_metadata", s.config.IncludeSignalMetadata)

	return nil
}

// Stop stops the streaming exporter
func (s *StreamingExporter) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	<-s.doneCh
	s.logger.Info("kubemetrics streaming exporter stopped")
}

// run is the main loop for periodic export
func (s *StreamingExporter) run(ctx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	// Export immediately on start
	s.collectAndExport(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.collectAndExport(ctx)
		}
	}
}

// collectAndExport collects metrics and exports them via OTLP
func (s *StreamingExporter) collectAndExport(ctx context.Context) {
	if s.exporter == nil {
		return
	}

	collectStart := time.Now()

	// Collect metrics from kubestate and cadvisor
	rm := s.collectResourceMetrics()
	if rm == nil || len(rm.ScopeMetrics) == 0 {
		return
	}

	collectDuration := time.Since(collectStart)
	s.collectCount++
	s.collectDuration += collectDuration

	// Export with timeout
	exportCtx, cancel := context.WithTimeout(ctx, s.config.FlushTimeout)
	defer cancel()

	exportStart := time.Now()
	err := s.exporter.Export(exportCtx, rm)
	exportDuration := time.Since(exportStart)

	s.exportCount++
	s.exportDuration += exportDuration
	s.lastExportTime = time.Now()

	if err != nil {
		s.lastError = err
		s.logger.Error("failed to export kubemetrics",
			"error", err,
			"collect_ms", collectDuration.Milliseconds(),
			"export_ms", exportDuration.Milliseconds())
	} else {
		s.lastError = nil
		metricCount := countMetrics(rm)
		s.logger.Debug("kubemetrics exported",
			"metrics", metricCount,
			"collect_ms", collectDuration.Milliseconds(),
			"export_ms", exportDuration.Milliseconds())
	}
}

// collectResourceMetrics collects all metrics and converts to OTEL format
func (s *StreamingExporter) collectResourceMetrics() *metricdata.ResourceMetrics {
	scopeMetrics := make([]metricdata.ScopeMetrics, 0, 2)

	// Collect kubestate metrics
	if s.provider.kubestate != nil {
		kubeMetrics := s.collectKubestateMetrics()
		if len(kubeMetrics) > 0 {
			scopeMetrics = append(scopeMetrics, metricdata.ScopeMetrics{
				Scope: instrumentation.Scope{
					Name:    "github.com/mirastacklabs-ai/telegen/kubestate",
					Version: "1.0.0",
				},
				Metrics: kubeMetrics,
			})
		}
	}

	// Collect cadvisor metrics
	if s.provider.cadvisor != nil {
		cadvisorMetrics := s.collectCadvisorMetrics()
		if len(cadvisorMetrics) > 0 {
			scopeMetrics = append(scopeMetrics, metricdata.ScopeMetrics{
				Scope: instrumentation.Scope{
					Name:    "github.com/mirastacklabs-ai/telegen/cadvisor",
					Version: "1.0.0",
				},
				Metrics: cadvisorMetrics,
			})
		}
	}

	if len(scopeMetrics) == 0 {
		return nil
	}

	return &metricdata.ResourceMetrics{
		Resource:     s.resource,
		ScopeMetrics: scopeMetrics,
	}
}

// collectKubestateMetrics collects kubestate metrics in OTEL format
func (s *StreamingExporter) collectKubestateMetrics() []metricdata.Metrics {
	metrics := make([]metricdata.Metrics, 0)

	// Get stats from kubestate stores
	stats := s.provider.kubestate.Stats()
	storeCount, _ := stats["stores"].(int)

	// Add signal metadata if enabled
	var signalAttrs []attribute.KeyValue
	if s.config.IncludeSignalMetadata {
		meta := &sigdef.SignalMetadata{
			Category:      "Kubernetes State",
			SubCategory:   "Object Metrics",
			SourceModule:  "github.com/mirastacklabs-ai/telegen/internal/kubestate",
			CollectorType: sigdef.CollectorTypeAPI,
			SignalType:    sigdef.SignalMetrics,
		}
		signalAttrs = meta.ToAttributesWithConfig(s.config.MetadataConfig)
	}

	// Create a self-telemetry metric for kubestate
	metrics = append(metrics, metricdata.Metrics{
		Name:        "telegen_kubestate_stores_total",
		Description: "Number of active kubestate metrics stores",
		Unit:        "1",
		Data: metricdata.Gauge[int64]{
			DataPoints: []metricdata.DataPoint[int64]{
				{
					Time:       time.Now(),
					Value:      int64(storeCount),
					Attributes: attribute.NewSet(signalAttrs...),
				},
			},
		},
	})

	// TODO: Parse actual kubestate metrics from WriteMetrics output
	// For now, kubestate exposes via Prometheus format - full OTLP conversion
	// requires parsing the prometheus text format to OTEL datapoints

	return metrics
}

// collectCadvisorMetrics collects cadvisor metrics in OTEL format
func (s *StreamingExporter) collectCadvisorMetrics() []metricdata.Metrics {
	metrics := make([]metricdata.Metrics, 0)

	// Collect container stats
	containerStats, err := s.provider.cadvisor.CollectAll()
	if err != nil {
		s.logger.Debug("failed to collect cadvisor stats", "error", err)
		return metrics
	}

	// Add signal metadata if enabled
	var signalAttrs []attribute.KeyValue
	if s.config.IncludeSignalMetadata {
		meta := &sigdef.SignalMetadata{
			Category:      "Container Metrics",
			SubCategory:   "Resource Utilization",
			SourceModule:  "github.com/mirastacklabs-ai/telegen/internal/cadvisor",
			CollectorType: sigdef.CollectorTypeProcFS,
			SignalType:    sigdef.SignalMetrics,
		}
		signalAttrs = meta.ToAttributesWithConfig(s.config.MetadataConfig)
	}

	now := time.Now()

	// Convert container stats to OTEL metrics
	for _, stat := range containerStats {
		containerAttrs := []attribute.KeyValue{
			attribute.String("container_id", stat.Container.ContainerID),
			attribute.String("pod", stat.Container.PodName),
			attribute.String("namespace", stat.Container.Namespace),
			attribute.String("container", stat.Container.ContainerName),
		}
		containerAttrs = append(containerAttrs, signalAttrs...)
		attrSet := attribute.NewSet(containerAttrs...)

		// CPU metrics
		if stat.CPU != nil {
			metrics = append(metrics, metricdata.Metrics{
				Name:        "container_cpu_usage_seconds_total",
				Description: "Cumulative cpu time consumed in seconds",
				Unit:        "s",
				Data: metricdata.Sum[float64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
					DataPoints: []metricdata.DataPoint[float64]{
						{
							Time:       now,
							Value:      float64(stat.CPU.UsageNanoseconds) / 1e9,
							Attributes: attrSet,
						},
					},
				},
			})
		}

		// Memory metrics
		if stat.Memory != nil {
			// Memory values are uint64 but OTLP uses int64. Cap at MaxInt64
			// (>9 exabytes, practically impossible for container memory)
			usageBytes := stat.Memory.UsageBytes
			if usageBytes > uint64(math.MaxInt64) {
				usageBytes = uint64(math.MaxInt64)
			}
			workingSetBytes := stat.Memory.WorkingSetBytes
			if workingSetBytes > uint64(math.MaxInt64) {
				workingSetBytes = uint64(math.MaxInt64)
			}
			metrics = append(metrics, metricdata.Metrics{
				Name:        "container_memory_usage_bytes",
				Description: "Current memory usage in bytes",
				Unit:        "By",
				Data: metricdata.Gauge[int64]{
					DataPoints: []metricdata.DataPoint[int64]{
						{
							Time:       now,
							Value:      int64(usageBytes),
							Attributes: attrSet,
						},
					},
				},
			})
			metrics = append(metrics, metricdata.Metrics{
				Name:        "container_memory_working_set_bytes",
				Description: "Current working set in bytes",
				Unit:        "By",
				Data: metricdata.Gauge[int64]{
					DataPoints: []metricdata.DataPoint[int64]{
						{
							Time:       now,
							Value:      int64(workingSetBytes),
							Attributes: attrSet,
						},
					},
				},
			})
		}

		// Network metrics
		if stat.Network != nil {
			for ifaceName, iface := range stat.Network.Interfaces {
				netAttrs := append(containerAttrs, attribute.String("interface", ifaceName))
				netAttrSet := attribute.NewSet(netAttrs...)

				metrics = append(metrics, metricdata.Metrics{
					Name:        "container_network_receive_bytes_total",
					Description: "Cumulative count of bytes received",
					Unit:        "By",
					Data: metricdata.Sum[int64]{
						Temporality: metricdata.CumulativeTemporality,
						IsMonotonic: true,
						DataPoints: []metricdata.DataPoint[int64]{
							{
								Time:       now,
								Value:      int64(iface.RxBytes),
								Attributes: netAttrSet,
							},
						},
					},
				})
				metrics = append(metrics, metricdata.Metrics{
					Name:        "container_network_transmit_bytes_total",
					Description: "Cumulative count of bytes transmitted",
					Unit:        "By",
					Data: metricdata.Sum[int64]{
						Temporality: metricdata.CumulativeTemporality,
						IsMonotonic: true,
						DataPoints: []metricdata.DataPoint[int64]{
							{
								Time:       now,
								Value:      int64(iface.TxBytes),
								Attributes: netAttrSet,
							},
						},
					},
				})
			}
		}

		// Disk I/O metrics
		if stat.DiskIO != nil {
			metrics = append(metrics, metricdata.Metrics{
				Name:        "container_fs_reads_bytes_total",
				Description: "Cumulative count of bytes read",
				Unit:        "By",
				Data: metricdata.Sum[int64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
					DataPoints: []metricdata.DataPoint[int64]{
						{
							Time:       now,
							Value:      int64(stat.DiskIO.ReadBytes),
							Attributes: attrSet,
						},
					},
				},
			})
			metrics = append(metrics, metricdata.Metrics{
				Name:        "container_fs_writes_bytes_total",
				Description: "Cumulative count of bytes written",
				Unit:        "By",
				Data: metricdata.Sum[int64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
					DataPoints: []metricdata.DataPoint[int64]{
						{
							Time:       now,
							Value:      int64(stat.DiskIO.WriteBytes),
							Attributes: attrSet,
						},
					},
				},
			})
		}
	}

	return metrics
}

// Stats returns exporter statistics
func (s *StreamingExporter) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"running":          s.running,
		"collect_count":    s.collectCount,
		"collect_duration": s.collectDuration.String(),
		"export_count":     s.exportCount,
		"export_duration":  s.exportDuration.String(),
		"last_export_time": s.lastExportTime,
		"last_error":       s.lastError,
	}
}

// countMetrics counts the total number of metrics in ResourceMetrics
func countMetrics(rm *metricdata.ResourceMetrics) int {
	count := 0
	for _, sm := range rm.ScopeMetrics {
		count += len(sm.Metrics)
	}
	return count
}
