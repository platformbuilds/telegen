// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package profiler provides eBPF-based profiling with metrics export capabilities.
// The MetricsExporter converts profiling data into OTLP metrics for observability.
package profiler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"

	"github.com/platformbuilds/telegen/internal/helpers/container"
	"github.com/platformbuilds/telegen/internal/version"
)

// MetricsExporterConfig holds configuration for the profile metrics exporter
type MetricsExporterConfig struct {
	// Enabled enables metrics export from profiling data
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Endpoint is the OTLP metrics endpoint (e.g., "http://localhost:4318/v1/metrics")
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`

	// Headers are custom HTTP headers to send with requests
	Headers map[string]string `mapstructure:"headers" yaml:"headers"`

	// Compression algorithm: "gzip" or "" (none)
	Compression string `mapstructure:"compression" yaml:"compression"`

	// Timeout for HTTP requests
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`

	// HistogramBuckets for duration/size distributions (in appropriate units per metric)
	// Default: latency-optimized buckets for seconds
	HistogramBuckets []float64 `mapstructure:"histogram_buckets" yaml:"histogram_buckets"`

	// MemoryHistogramBuckets for allocation size distributions (in bytes)
	// Default: power-of-2 buckets from 64B to 64MB
	MemoryHistogramBuckets []float64 `mapstructure:"memory_histogram_buckets" yaml:"memory_histogram_buckets"`

	// IncludeProcessAttributes includes process-level attributes (pid, comm, executable)
	IncludeProcessAttributes bool `mapstructure:"include_process_attributes" yaml:"include_process_attributes"`

	// IncludeStackAttributes includes top-of-stack attributes (function, class)
	IncludeStackAttributes bool `mapstructure:"include_stack_attributes" yaml:"include_stack_attributes"`

	// Service metadata
	ServiceName   string
	Namespace     string
	PodName       string
	ContainerName string
	NodeName      string
	ClusterName   string
	Deployment    string
	HostName      string

	// CPU sample rate for duration calculation
	CPUSampleRate int
}

// DefaultMetricsExporterConfig returns default configuration
func DefaultMetricsExporterConfig() MetricsExporterConfig {
	return MetricsExporterConfig{
		Enabled:     false,
		Endpoint:    "http://localhost:4318/v1/metrics",
		Compression: "gzip",
		Timeout:     30 * time.Second,
		// Default histogram buckets for latency (seconds): 1ms to 60s
		HistogramBuckets: []float64{
			0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
		},
		// Default histogram buckets for memory (bytes): 64B to 64MB
		MemoryHistogramBuckets: []float64{
			64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864,
		},
		IncludeProcessAttributes: true,
		IncludeStackAttributes:   true,
		CPUSampleRate:            99,
	}
}

// MetricsExporter exports profiling data as OTLP metrics.
// It aggregates profile samples and produces metrics like:
// - profiler.cpu.samples (counter)
// - profiler.cpu.duration_seconds (histogram)
// - profiler.offcpu.duration_seconds (histogram)
// - profiler.memory.allocation_bytes (counter)
// - profiler.memory.allocation_size_bytes (histogram)
// - profiler.mutex.wait_time_seconds (histogram)
type MetricsExporter struct {
	config           MetricsExporterConfig
	exporter         sdkmetric.Exporter
	resource         *resource.Resource
	log              *slog.Logger
	metadataResolver *ProcessMetadataResolver // Shared resolver for app name correlation
	ownsExporter     bool                     // true if we created the exporter and should close it

	mu sync.Mutex
}

// NewMetricsExporter creates a new profile metrics exporter.
// It creates its own OTLP HTTP metrics exporter based on the endpoint configuration.
func NewMetricsExporter(
	cfg MetricsExporterConfig,
	log *slog.Logger,
	metadataResolver *ProcessMetadataResolver,
) (*MetricsExporter, error) {
	if log == nil {
		log = slog.Default()
	}

	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("metrics endpoint cannot be empty")
	}

	// Apply defaults for histogram buckets if not set
	defaults := DefaultMetricsExporterConfig()
	if len(cfg.HistogramBuckets) == 0 {
		cfg.HistogramBuckets = defaults.HistogramBuckets
		log.Info("using default histogram buckets", "count", len(cfg.HistogramBuckets))
	}
	if len(cfg.MemoryHistogramBuckets) == 0 {
		cfg.MemoryHistogramBuckets = defaults.MemoryHistogramBuckets
		log.Info("using default memory histogram buckets", "count", len(cfg.MemoryHistogramBuckets))
	}

	// Create shared metadata resolver if not provided
	if metadataResolver == nil {
		metadataResolver = NewProcessMetadataResolver(log)
	}

	// Parse endpoint to extract host and path
	endpoint, urlPath := parseEndpoint(cfg.Endpoint)

	log.Info("creating OTLP metrics exporter",
		"original_endpoint", cfg.Endpoint,
		"parsed_host", endpoint,
		"parsed_path", urlPath,
		"compression", cfg.Compression,
		"insecure", strings.HasPrefix(cfg.Endpoint, "http://"))

	// Build OTLP HTTP options
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(endpoint),
		otlpmetrichttp.WithURLPath(urlPath),
	}

	// Check if endpoint is insecure (http://)
	if strings.HasPrefix(cfg.Endpoint, "http://") {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	// Add headers if configured
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
	}

	// Add compression if configured
	if cfg.Compression == "gzip" {
		opts = append(opts, otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression))
	}

	// Add timeout if configured
	if cfg.Timeout > 0 {
		opts = append(opts, otlpmetrichttp.WithTimeout(cfg.Timeout))
	}

	// Create the OTLP metrics exporter
	ctx := context.Background()
	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP metrics exporter: %w", err)
	}

	// Build resource from config
	res, err := buildProfilerResource(cfg)
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, fmt.Errorf("failed to build resource: %w", err)
	}

	return &MetricsExporter{
		config:           cfg,
		exporter:         exporter,
		resource:         res,
		log:              log.With("component", "profiler_metrics_exporter"),
		metadataResolver: metadataResolver,
		ownsExporter:     true,
	}, nil
}

// parseEndpoint extracts host:port and URL path from endpoint URL
func parseEndpoint(endpoint string) (host, path string) {
	// Remove scheme
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")

	// Split host and path
	idx := strings.Index(endpoint, "/")
	if idx == -1 {
		return endpoint, "/v1/metrics"
	}
	return endpoint[:idx], endpoint[idx:]
}

// buildProfilerResource creates an OTEL resource for profiler metrics
func buildProfilerResource(cfg MetricsExporterConfig) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(version.Version()),
		semconv.TelemetrySDKName("telegen"),
		semconv.TelemetrySDKVersion(version.Version()),
		semconv.TelemetrySDKLanguageGo,
	}

	// Add Kubernetes attributes if available
	if cfg.Namespace != "" {
		attrs = append(attrs, semconv.K8SNamespaceName(cfg.Namespace))
	}
	if cfg.PodName != "" {
		attrs = append(attrs, semconv.K8SPodName(cfg.PodName))
	}
	if cfg.NodeName != "" {
		attrs = append(attrs, semconv.K8SNodeName(cfg.NodeName))
	}
	if cfg.ClusterName != "" {
		attrs = append(attrs, semconv.K8SClusterName(cfg.ClusterName))
	}
	if cfg.ContainerName != "" {
		attrs = append(attrs, semconv.K8SContainerName(cfg.ContainerName))
	}
	if cfg.Deployment != "" {
		attrs = append(attrs, semconv.K8SDeploymentName(cfg.Deployment))
	}

	// Add hostname for non-k8s environments
	if cfg.HostName != "" {
		attrs = append(attrs, semconv.HostName(cfg.HostName))
	}

	return resource.NewSchemaless(attrs...), nil
}

// Export exports a profile as OTLP metrics
func (e *MetricsExporter) Export(ctx context.Context, profile *Profile) error {
	if profile == nil || len(profile.Samples) == 0 {
		e.log.Debug("no samples to export", "profile", profile == nil)
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("exporting profile metrics",
		"profile_type", profile.Type,
		"samples", len(profile.Samples),
		"endpoint", e.config.Endpoint)

	// Convert profile to metrics based on type
	rm := e.convertToResourceMetrics(profile)

	// Log what we're about to send
	metricCount := 0
	if rm != nil && len(rm.ScopeMetrics) > 0 {
		metricCount = len(rm.ScopeMetrics[0].Metrics)
	}
	e.log.Info("converted profile to metrics",
		"profile_type", profile.Type,
		"metric_count", metricCount)

	// Export via the OTEL exporter
	if err := e.exporter.Export(ctx, rm); err != nil {
		e.log.Error("failed to export profile metrics",
			"error", err,
			"profile_type", profile.Type,
			"samples", len(profile.Samples),
			"endpoint", e.config.Endpoint)
		return err
	}

	e.log.Info("successfully exported profile metrics",
		"profile_type", profile.Type,
		"samples", len(profile.Samples),
		"metrics", metricCount)

	return nil
}

// convertToResourceMetrics converts a profile to OTEL ResourceMetrics
func (e *MetricsExporter) convertToResourceMetrics(profile *Profile) *metricdata.ResourceMetrics {
	timestamp := profile.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	var metrics []metricdata.Metrics

	switch profile.Type {
	case ProfileTypeCPU:
		metrics = e.cpuProfileToMetrics(profile, timestamp)
	case ProfileTypeOffCPU:
		metrics = e.offCPUProfileToMetrics(profile, timestamp)
	case ProfileTypeMemory, ProfileTypeHeap, ProfileTypeAllocs, ProfileTypeAllocBytes, ProfileTypeAllocCount:
		metrics = e.memoryProfileToMetrics(profile, timestamp)
	case ProfileTypeMutex:
		metrics = e.mutexProfileToMetrics(profile, timestamp)
	case ProfileTypeWall:
		metrics = e.wallProfileToMetrics(profile, timestamp)
	default:
		e.log.Warn("unsupported profile type for metrics", "type", profile.Type)
		return &metricdata.ResourceMetrics{Resource: e.resource}
	}

	return &metricdata.ResourceMetrics{
		Resource: e.resource,
		ScopeMetrics: []metricdata.ScopeMetrics{
			{
				Scope: instrumentation.Scope{
					Name:    "github.com/platformbuilds/telegen/profiler",
					Version: version.Version(),
				},
				Metrics: metrics,
			},
		},
	}
}

// cpuProfileToMetrics converts CPU profile samples to metrics
func (e *MetricsExporter) cpuProfileToMetrics(profile *Profile, timestamp time.Time) []metricdata.Metrics {
	// Aggregate samples by attributes
	type aggregation struct {
		sampleCount  int64
		durationNs   int64
		durationHist []float64 // individual durations for histogram
	}
	aggregations := make(map[string]*aggregation)

	samplePeriodNs := samplePeriodFromHz(e.config.CPUSampleRate)

	for _, sample := range profile.Samples {
		key := e.buildAggregationKey(sample, profile.Type)
		agg, ok := aggregations[key]
		if !ok {
			agg = &aggregation{durationHist: make([]float64, 0)}
			aggregations[key] = agg
		}
		agg.sampleCount += sample.Count
		durationNs := sample.Value * samplePeriodNs
		agg.durationNs += durationNs
		// Store duration in seconds for histogram
		agg.durationHist = append(agg.durationHist, float64(durationNs)/1e9)
	}

	metrics := make([]metricdata.Metrics, 0, 2)

	// Build counter datapoints for sample count
	sampleCountDPs := make([]metricdata.DataPoint[int64], 0, len(aggregations))
	durationHistDPs := make([]metricdata.HistogramDataPoint[float64], 0, len(aggregations))

	for key, agg := range aggregations {
		attrs := e.parseAggregationKey(key, profile.Type)

		// Sample count datapoint
		sampleCountDPs = append(sampleCountDPs, metricdata.DataPoint[int64]{
			Attributes: attrs,
			Time:       timestamp,
			Value:      agg.sampleCount,
		})

		// Duration histogram datapoint
		histDP := e.buildHistogramDataPoint(agg.durationHist, e.config.HistogramBuckets, attrs, timestamp)
		durationHistDPs = append(durationHistDPs, histDP)
	}

	// Add sample count metric
	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.cpu.samples",
		Description: "Number of CPU profile samples",
		Unit:        "1",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints:  sampleCountDPs,
		},
	})

	// Add duration histogram metric
	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.cpu.duration_seconds",
		Description: "Distribution of on-CPU time",
		Unit:        "s",
		Data: metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints:  durationHistDPs,
		},
	})

	return metrics
}

// offCPUProfileToMetrics converts off-CPU profile samples to metrics
func (e *MetricsExporter) offCPUProfileToMetrics(profile *Profile, timestamp time.Time) []metricdata.Metrics {
	type aggregation struct {
		sampleCount  int64
		durationHist []float64
	}
	aggregations := make(map[string]*aggregation)

	for _, sample := range profile.Samples {
		key := e.buildAggregationKey(sample, profile.Type)
		agg, ok := aggregations[key]
		if !ok {
			agg = &aggregation{durationHist: make([]float64, 0)}
			aggregations[key] = agg
		}
		agg.sampleCount += sample.Count
		// Off-CPU value is block time in ns
		agg.durationHist = append(agg.durationHist, float64(sample.Value)/1e9)
	}

	metrics := make([]metricdata.Metrics, 0, 2)

	sampleCountDPs := make([]metricdata.DataPoint[int64], 0, len(aggregations))
	durationHistDPs := make([]metricdata.HistogramDataPoint[float64], 0, len(aggregations))

	for key, agg := range aggregations {
		attrs := e.parseAggregationKey(key, profile.Type)

		sampleCountDPs = append(sampleCountDPs, metricdata.DataPoint[int64]{
			Attributes: attrs,
			Time:       timestamp,
			Value:      agg.sampleCount,
		})

		histDP := e.buildHistogramDataPoint(agg.durationHist, e.config.HistogramBuckets, attrs, timestamp)
		durationHistDPs = append(durationHistDPs, histDP)
	}

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.offcpu.samples",
		Description: "Number of off-CPU profile samples (blocked threads)",
		Unit:        "1",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints:  sampleCountDPs,
		},
	})

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.offcpu.duration_seconds",
		Description: "Distribution of blocked/off-CPU time",
		Unit:        "s",
		Data: metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints:  durationHistDPs,
		},
	})

	return metrics
}

// memoryProfileToMetrics converts memory profile samples to metrics
func (e *MetricsExporter) memoryProfileToMetrics(profile *Profile, timestamp time.Time) []metricdata.Metrics {
	type aggregation struct {
		allocCount int64
		allocBytes int64
		sizeHist   []float64
	}
	aggregations := make(map[string]*aggregation)

	for _, sample := range profile.Samples {
		key := e.buildAggregationKey(sample, profile.Type)
		agg, ok := aggregations[key]
		if !ok {
			agg = &aggregation{sizeHist: make([]float64, 0)}
			aggregations[key] = agg
		}
		agg.allocCount += sample.Count
		agg.allocBytes += sample.Value
		// Value is bytes allocated
		agg.sizeHist = append(agg.sizeHist, float64(sample.Value))
	}

	metrics := make([]metricdata.Metrics, 0, 3)

	allocCountDPs := make([]metricdata.DataPoint[int64], 0, len(aggregations))
	allocBytesDPs := make([]metricdata.DataPoint[int64], 0, len(aggregations))
	sizeHistDPs := make([]metricdata.HistogramDataPoint[float64], 0, len(aggregations))

	for key, agg := range aggregations {
		attrs := e.parseAggregationKey(key, profile.Type)

		allocCountDPs = append(allocCountDPs, metricdata.DataPoint[int64]{
			Attributes: attrs,
			Time:       timestamp,
			Value:      agg.allocCount,
		})

		allocBytesDPs = append(allocBytesDPs, metricdata.DataPoint[int64]{
			Attributes: attrs,
			Time:       timestamp,
			Value:      agg.allocBytes,
		})

		histDP := e.buildHistogramDataPoint(agg.sizeHist, e.config.MemoryHistogramBuckets, attrs, timestamp)
		sizeHistDPs = append(sizeHistDPs, histDP)
	}

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.memory.allocations",
		Description: "Number of memory allocations",
		Unit:        "1",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints:  allocCountDPs,
		},
	})

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.memory.allocation_bytes",
		Description: "Total bytes allocated",
		Unit:        "By",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints:  allocBytesDPs,
		},
	})

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.memory.allocation_size_bytes",
		Description: "Distribution of allocation sizes",
		Unit:        "By",
		Data: metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints:  sizeHistDPs,
		},
	})

	return metrics
}

// mutexProfileToMetrics converts mutex profile samples to metrics
func (e *MetricsExporter) mutexProfileToMetrics(profile *Profile, timestamp time.Time) []metricdata.Metrics {
	type aggregation struct {
		contentionCount int64
		waitTimeHist    []float64
	}
	aggregations := make(map[string]*aggregation)

	for _, sample := range profile.Samples {
		key := e.buildAggregationKey(sample, profile.Type)
		agg, ok := aggregations[key]
		if !ok {
			agg = &aggregation{waitTimeHist: make([]float64, 0)}
			aggregations[key] = agg
		}
		agg.contentionCount += sample.Count
		// Value is wait time in ns
		agg.waitTimeHist = append(agg.waitTimeHist, float64(sample.Value)/1e9)
	}

	metrics := make([]metricdata.Metrics, 0, 2)

	contentionDPs := make([]metricdata.DataPoint[int64], 0, len(aggregations))
	waitTimeHistDPs := make([]metricdata.HistogramDataPoint[float64], 0, len(aggregations))

	for key, agg := range aggregations {
		attrs := e.parseAggregationKey(key, profile.Type)

		contentionDPs = append(contentionDPs, metricdata.DataPoint[int64]{
			Attributes: attrs,
			Time:       timestamp,
			Value:      agg.contentionCount,
		})

		histDP := e.buildHistogramDataPoint(agg.waitTimeHist, e.config.HistogramBuckets, attrs, timestamp)
		waitTimeHistDPs = append(waitTimeHistDPs, histDP)
	}

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.mutex.contentions",
		Description: "Number of mutex contentions",
		Unit:        "1",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints:  contentionDPs,
		},
	})

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.mutex.wait_time_seconds",
		Description: "Distribution of mutex wait time",
		Unit:        "s",
		Data: metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints:  waitTimeHistDPs,
		},
	})

	return metrics
}

func (e *MetricsExporter) wallProfileToMetrics(profile *Profile, timestamp time.Time) []metricdata.Metrics {
	type aggregation struct {
		sampleCount    int64
		wallTimeHist   []float64
		cpuTimeHist    []float64
		offCPUTimeHist []float64
	}
	aggregations := make(map[string]*aggregation)

	for _, sample := range profile.Samples {
		key := e.buildAggregationKey(sample, profile.Type)
		agg, ok := aggregations[key]
		if !ok {
			agg = &aggregation{
				wallTimeHist:   make([]float64, 0),
				cpuTimeHist:    make([]float64, 0),
				offCPUTimeHist: make([]float64, 0),
			}
			aggregations[key] = agg
		}
		agg.sampleCount += sample.Count
		// Wall time in ns converted to seconds
		agg.wallTimeHist = append(agg.wallTimeHist, float64(sample.WallTimeNs)/1e9)
		if sample.CPUTimeNs > 0 {
			agg.cpuTimeHist = append(agg.cpuTimeHist, float64(sample.CPUTimeNs)/1e9)
		}
		if sample.OffCPUTimeNs > 0 {
			agg.offCPUTimeHist = append(agg.offCPUTimeHist, float64(sample.OffCPUTimeNs)/1e9)
		}
	}

	metrics := make([]metricdata.Metrics, 0, 4)

	sampleDPs := make([]metricdata.DataPoint[int64], 0, len(aggregations))
	wallTimeHistDPs := make([]metricdata.HistogramDataPoint[float64], 0, len(aggregations))
	cpuTimeHistDPs := make([]metricdata.HistogramDataPoint[float64], 0, len(aggregations))
	offCPUTimeHistDPs := make([]metricdata.HistogramDataPoint[float64], 0, len(aggregations))

	for key, agg := range aggregations {
		attrs := e.parseAggregationKey(key, profile.Type)

		sampleDPs = append(sampleDPs, metricdata.DataPoint[int64]{
			Attributes: attrs,
			Time:       timestamp,
			Value:      agg.sampleCount,
		})

		wallHistDP := e.buildHistogramDataPoint(agg.wallTimeHist, e.config.HistogramBuckets, attrs, timestamp)
		wallTimeHistDPs = append(wallTimeHistDPs, wallHistDP)

		if len(agg.cpuTimeHist) > 0 {
			cpuHistDP := e.buildHistogramDataPoint(agg.cpuTimeHist, e.config.HistogramBuckets, attrs, timestamp)
			cpuTimeHistDPs = append(cpuTimeHistDPs, cpuHistDP)
		}

		if len(agg.offCPUTimeHist) > 0 {
			offCPUHistDP := e.buildHistogramDataPoint(agg.offCPUTimeHist, e.config.HistogramBuckets, attrs, timestamp)
			offCPUTimeHistDPs = append(offCPUTimeHistDPs, offCPUHistDP)
		}
	}

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.wall.samples",
		Description: "Number of wall clock samples",
		Unit:        "1",
		Data: metricdata.Sum[int64]{
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
			DataPoints:  sampleDPs,
		},
	})

	metrics = append(metrics, metricdata.Metrics{
		Name:        "profiler.wall.duration_seconds",
		Description: "Distribution of wall clock time per sample",
		Unit:        "s",
		Data: metricdata.Histogram[float64]{
			Temporality: metricdata.CumulativeTemporality,
			DataPoints:  wallTimeHistDPs,
		},
	})

	if len(cpuTimeHistDPs) > 0 {
		metrics = append(metrics, metricdata.Metrics{
			Name:        "profiler.wall.cpu_time_seconds",
			Description: "Distribution of CPU time during wall clock sampling",
			Unit:        "s",
			Data: metricdata.Histogram[float64]{
				Temporality: metricdata.CumulativeTemporality,
				DataPoints:  cpuTimeHistDPs,
			},
		})
	}

	if len(offCPUTimeHistDPs) > 0 {
		metrics = append(metrics, metricdata.Metrics{
			Name:        "profiler.wall.offcpu_time_seconds",
			Description: "Distribution of off-CPU time during wall clock sampling",
			Unit:        "s",
			Data: metricdata.Histogram[float64]{
				Temporality: metricdata.CumulativeTemporality,
				DataPoints:  offCPUTimeHistDPs,
			},
		})
	}

	return metrics
}

// buildAggregationKey builds a unique key for aggregating samples with similar attributes
func (e *MetricsExporter) buildAggregationKey(sample StackSample, profileType ProfileType) string {
	// Key format: profile_type|app_name|pid|comm|container_id|function|class|type_specific
	key := string(profileType)

	// Add app.name - critical for UI correlation with logs
	// Use shared resolver to ensure identical app name derivation with LogExporter
	// Pass empty string for serviceName to auto-detect from profiled process (jar name, binary, etc.)
	// e.config.ServiceName is the TELEGEN AGENT's identity, not the profiled app's name
	appName := e.metadataResolver.ResolveAppName(sample.PID, sample.Comm, "")
	key += "|" + appName

	// Always add process attribute placeholders to maintain consistent key format
	// This ensures parseAggregationKey can correctly parse at fixed positions
	if e.config.IncludeProcessAttributes {
		key += fmt.Sprintf("|%d|%s", sample.PID, sample.Comm)

		// Add container ID if available
		if cInfo, err := container.InfoForPID(sample.PID); err == nil && cInfo.ContainerID != "" {
			key += "|" + cInfo.ContainerID[:12] // Use short container ID
		} else {
			key += "|"
		}
	} else {
		// Add empty placeholders to maintain position alignment
		key += "|||"
	}

	if e.config.IncludeStackAttributes && len(sample.Frames) > 0 {
		topFrame := sample.Frames[0]
		key += "|" + topFrame.Function
		if topFrame.Class != "" {
			key += "|" + topFrame.Class
		} else {
			key += "|"
		}
	} else {
		key += "||"
	}

	// Add profile-type-specific attributes
	switch profileType {
	case ProfileTypeOffCPU:
		key += "|" + sample.BlockReason.String()
	case ProfileTypeMemory, ProfileTypeHeap, ProfileTypeAllocs, ProfileTypeAllocBytes, ProfileTypeAllocCount:
		key += "|" + allocTypeToString(sample.AllocType)
	default:
		key += "|"
	}

	return key
}

// parseAggregationKey parses an aggregation key back to attributes
func (e *MetricsExporter) parseAggregationKey(key string, profileType ProfileType) attribute.Set {
	attrs := []attribute.KeyValue{
		attribute.String("profile.type", string(profileType)),
	}

	// Parse key: profile_type|app_name|pid|comm|container_id|function|class|type_specific
	parts := splitKey(key)

	// app.name is always at index 1 (critical for UI correlation)
	if len(parts) > 1 && parts[1] != "" {
		attrs = append(attrs, attribute.String("app.name", parts[1]))
	}

	if e.config.IncludeProcessAttributes && len(parts) > 3 {
		if parts[2] != "" {
			// Parse PID
			var pid int64
			fmt.Sscanf(parts[2], "%d", &pid)
			if pid > 0 {
				attrs = append(attrs, attribute.Int64("process.pid", pid))
			}
		}
		if parts[3] != "" {
			attrs = append(attrs, attribute.String("process.executable.name", parts[3]))
		}
		if len(parts) > 4 && parts[4] != "" {
			attrs = append(attrs, attribute.String("container.id", parts[4]))
		}
	}

	if e.config.IncludeStackAttributes {
		idx := 5 // Start after container_id
		if len(parts) > idx && parts[idx] != "" {
			attrs = append(attrs, attribute.String("code.function", parts[idx]))
		}
		idx++
		if len(parts) > idx && parts[idx] != "" {
			attrs = append(attrs, attribute.String("code.class", parts[idx]))
		}
	}

	// Profile-type-specific attributes
	lastIdx := len(parts) - 1
	if lastIdx >= 0 && parts[lastIdx] != "" {
		switch profileType {
		case ProfileTypeOffCPU:
			attrs = append(attrs, attribute.String("block.reason", parts[lastIdx]))
		case ProfileTypeMemory, ProfileTypeHeap, ProfileTypeAllocs, ProfileTypeAllocBytes, ProfileTypeAllocCount:
			attrs = append(attrs, attribute.String("allocation.type", parts[lastIdx]))
		}
	}

	return attribute.NewSet(attrs...)
}

// splitKey splits an aggregation key by | delimiter
func splitKey(key string) []string {
	result := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			result = append(result, key[start:i])
			start = i + 1
		}
	}
	result = append(result, key[start:])
	return result
}

// buildHistogramDataPoint builds a histogram datapoint from values
func (e *MetricsExporter) buildHistogramDataPoint(
	values []float64,
	buckets []float64,
	attrs attribute.Set,
	timestamp time.Time,
) metricdata.HistogramDataPoint[float64] {
	if len(values) == 0 {
		return metricdata.HistogramDataPoint[float64]{
			Attributes:   attrs,
			Time:         timestamp,
			Count:        0,
			Bounds:       buckets,
			BucketCounts: make([]uint64, len(buckets)+1),
		}
	}

	// Calculate histogram bucket counts
	bucketCounts := make([]uint64, len(buckets)+1)
	var sum float64
	var min, max float64 = values[0], values[0]

	for _, v := range values {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}

		// Find bucket
		placed := false
		for i, bound := range buckets {
			if v <= bound {
				bucketCounts[i]++
				placed = true
				break
			}
		}
		if !placed {
			bucketCounts[len(buckets)]++ // Overflow bucket
		}
	}

	return metricdata.HistogramDataPoint[float64]{
		Attributes:   attrs,
		Time:         timestamp,
		Count:        uint64(len(values)),
		Sum:          sum,
		Min:          metricdata.NewExtrema(min),
		Max:          metricdata.NewExtrema(max),
		Bounds:       buckets,
		BucketCounts: bucketCounts,
	}
}

// Flush is a no-op for the metrics exporter (immediate export)
func (e *MetricsExporter) Flush(ctx context.Context) error {
	return nil
}

// Close shuts down the exporter if we own it
func (e *MetricsExporter) Close() error {
	if e.ownsExporter && e.exporter != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return e.exporter.Shutdown(ctx)
	}
	return nil
}
