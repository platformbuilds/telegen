package unified

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// OTelExporter exports cloud metrics and resources to OpenTelemetry.
type OTelExporter struct {
	meterProvider *sdkmetric.MeterProvider
	meter         metric.Meter
	gauges        map[string]metric.Float64Gauge
	counters      map[string]metric.Float64Counter
	histograms    map[string]metric.Float64Histogram
	mu            sync.RWMutex
}

// NewOTelExporter creates a new OpenTelemetry exporter.
func NewOTelExporter(meterProvider *sdkmetric.MeterProvider) *OTelExporter {
	return &OTelExporter{
		meterProvider: meterProvider,
		meter:         meterProvider.Meter("cloud.unified"),
		gauges:        make(map[string]metric.Float64Gauge),
		counters:      make(map[string]metric.Float64Counter),
		histograms:    make(map[string]metric.Float64Histogram),
	}
}

// ExportMetrics exports metrics to OpenTelemetry.
func (e *OTelExporter) ExportMetrics(ctx context.Context, metrics []Metric) error {
	for _, m := range metrics {
		if err := e.recordMetric(ctx, m); err != nil {
			// Log error but continue
			continue
		}
	}
	return nil
}

// recordMetric records a single metric.
func (e *OTelExporter) recordMetric(ctx context.Context, m Metric) error {
	attrs := e.labelsToAttributes(m.Labels)

	switch m.Type {
	case MetricTypeGauge:
		gauge, err := e.getOrCreateGauge(m.Name, m.Description, string(m.Unit))
		if err != nil {
			return err
		}
		gauge.Record(ctx, m.Value, metric.WithAttributes(attrs...))

	case MetricTypeCounter:
		counter, err := e.getOrCreateCounter(m.Name, m.Description, string(m.Unit))
		if err != nil {
			return err
		}
		counter.Add(ctx, m.Value, metric.WithAttributes(attrs...))

	case MetricTypeHistogram:
		histogram, err := e.getOrCreateHistogram(m.Name, m.Description, string(m.Unit))
		if err != nil {
			return err
		}
		histogram.Record(ctx, m.Value, metric.WithAttributes(attrs...))
	}

	return nil
}

// getOrCreateGauge gets or creates a gauge instrument.
func (e *OTelExporter) getOrCreateGauge(name, description, unit string) (metric.Float64Gauge, error) {
	e.mu.RLock()
	if gauge, ok := e.gauges[name]; ok {
		e.mu.RUnlock()
		return gauge, nil
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check
	if gauge, ok := e.gauges[name]; ok {
		return gauge, nil
	}

	gauge, err := e.meter.Float64Gauge(name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, err
	}

	e.gauges[name] = gauge
	return gauge, nil
}

// getOrCreateCounter gets or creates a counter instrument.
func (e *OTelExporter) getOrCreateCounter(name, description, unit string) (metric.Float64Counter, error) {
	e.mu.RLock()
	if counter, ok := e.counters[name]; ok {
		e.mu.RUnlock()
		return counter, nil
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	if counter, ok := e.counters[name]; ok {
		return counter, nil
	}

	counter, err := e.meter.Float64Counter(name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, err
	}

	e.counters[name] = counter
	return counter, nil
}

// getOrCreateHistogram gets or creates a histogram instrument.
func (e *OTelExporter) getOrCreateHistogram(name, description, unit string) (metric.Float64Histogram, error) {
	e.mu.RLock()
	if histogram, ok := e.histograms[name]; ok {
		e.mu.RUnlock()
		return histogram, nil
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	if histogram, ok := e.histograms[name]; ok {
		return histogram, nil
	}

	histogram, err := e.meter.Float64Histogram(name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, err
	}

	e.histograms[name] = histogram
	return histogram, nil
}

// labelsToAttributes converts labels to OTel attributes.
func (e *OTelExporter) labelsToAttributes(labels map[string]string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(labels))
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	return attrs
}

// CreateResource creates an OTel resource from cloud metadata.
func CreateResource(metadata *CloudMetadata) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("telegen-agent"),
	}

	// Cloud attributes
	if metadata.Provider != "" {
		attrs = append(attrs, semconv.CloudProviderKey.String(metadata.Provider))
	}
	if metadata.Region != "" {
		attrs = append(attrs, semconv.CloudRegionKey.String(metadata.Region))
	}
	if metadata.Zone != "" {
		attrs = append(attrs, semconv.CloudAvailabilityZoneKey.String(metadata.Zone))
	}
	if metadata.AccountID != "" {
		attrs = append(attrs, semconv.CloudAccountIDKey.String(metadata.AccountID))
	}
	if metadata.Platform != "" {
		attrs = append(attrs, semconv.CloudPlatformKey.String(metadata.Platform))
	}

	// Host attributes
	if metadata.InstanceID != "" {
		attrs = append(attrs, semconv.HostIDKey.String(metadata.InstanceID))
	}
	if metadata.InstanceName != "" {
		attrs = append(attrs, semconv.HostNameKey.String(metadata.InstanceName))
	}
	if metadata.InstanceType != "" {
		attrs = append(attrs, semconv.HostTypeKey.String(metadata.InstanceType))
	}
	if metadata.Architecture != "" {
		attrs = append(attrs, semconv.HostArchKey.String(metadata.Architecture))
	}
	if metadata.ImageID != "" {
		attrs = append(attrs, semconv.HostImageIDKey.String(metadata.ImageID))
	}

	// Custom attributes for private cloud
	if metadata.Datacenter != "" {
		attrs = append(attrs, attribute.String("cloud.datacenter", metadata.Datacenter))
	}
	if metadata.Cluster != "" {
		attrs = append(attrs, attribute.String("cloud.cluster.name", metadata.Cluster))
	}
	if metadata.Hypervisor != "" {
		attrs = append(attrs, attribute.String("virtualization.hypervisor", metadata.Hypervisor))
	}
	if metadata.HostName != "" {
		attrs = append(attrs, attribute.String("cloud.host.name", metadata.HostName))
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attrs...), nil
}

// ResourceExporter exports resource information.
type ResourceExporter struct {
	manager *CloudManager
}

// NewResourceExporter creates a new resource exporter.
func NewResourceExporter(manager *CloudManager) *ResourceExporter {
	return &ResourceExporter{
		manager: manager,
	}
}

// ExportResources exports resources with their relationships.
func (e *ResourceExporter) ExportResources(ctx context.Context) ([]ResourceWithRelations, error) {
	resources, err := e.manager.DiscoverResources(ctx)
	if err != nil {
		return nil, err
	}

	// Build resource graph
	graph := NewResourceGraph()
	for _, res := range resources {
		graph.AddResource(res)
	}

	// Convert to resources with relations
	result := make([]ResourceWithRelations, 0, len(resources))
	for _, res := range resources {
		rwr := ResourceWithRelations{
			Resource: res,
			Parents:  make([]ResourceRef, 0),
			Children: make([]ResourceRef, 0),
			Related:  make([]ResourceRef, 0),
		}

		// Get relations from graph
		edges := graph.GetEdges(res.ID)
		for _, edge := range edges {
			ref := ResourceRef{
				ID:   edge.TargetID,
				Type: edge.TargetType,
			}

			switch edge.Relation {
			case "parent":
				rwr.Parents = append(rwr.Parents, ref)
			case "child":
				rwr.Children = append(rwr.Children, ref)
			default:
				rwr.Related = append(rwr.Related, ref)
			}
		}

		result = append(result, rwr)
	}

	return result, nil
}

// ResourceWithRelations represents a resource with its relationships.
type ResourceWithRelations struct {
	Resource Resource      `json:"resource"`
	Parents  []ResourceRef `json:"parents,omitempty"`
	Children []ResourceRef `json:"children,omitempty"`
	Related  []ResourceRef `json:"related,omitempty"`
}

// HealthReporter reports health status of cloud providers.
type HealthReporter struct {
	manager *CloudManager
}

// NewHealthReporter creates a new health reporter.
func NewHealthReporter(manager *CloudManager) *HealthReporter {
	return &HealthReporter{
		manager: manager,
	}
}

// GetHealthStatus returns the health status of all providers.
func (r *HealthReporter) GetHealthStatus(ctx context.Context) (*HealthStatus, error) {
	status := &HealthStatus{
		Timestamp:      time.Now(),
		ProviderStatus: make(map[string]ProviderHealth),
	}

	provider := r.manager.GetActiveProvider()
	if provider == nil {
		status.Overall = "unknown"
		status.Message = "No active cloud provider"
		return status, nil
	}

	health := provider.HealthCheck(ctx)

	providerHealth := ProviderHealth{
		Name:      provider.Name(),
		Type:      string(provider.Type()),
		Healthy:   health.Healthy,
		Message:   health.Message,
		Latency:   health.Latency,
		LastCheck: health.LastCheck,
	}

	status.ProviderStatus[provider.Name()] = providerHealth

	if health.Healthy {
		status.Overall = "healthy"
		status.Message = fmt.Sprintf("Provider %s is healthy", provider.Name())
	} else {
		status.Overall = "unhealthy"
		status.Message = health.Message
	}

	return status, nil
}

// HealthStatus represents overall health status.
type HealthStatus struct {
	Overall        string                    `json:"overall"`
	Message        string                    `json:"message"`
	Timestamp      time.Time                 `json:"timestamp"`
	ProviderStatus map[string]ProviderHealth `json:"providers"`
}

// ProviderHealth represents health of a single provider.
type ProviderHealth struct {
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	Healthy   bool          `json:"healthy"`
	Message   string        `json:"message,omitempty"`
	Latency   time.Duration `json:"latency"`
	LastCheck time.Time     `json:"last_check"`
}

// MetricsAggregator aggregates metrics across providers.
type MetricsAggregator struct {
	metrics []Metric
	mu      sync.Mutex
}

// NewMetricsAggregator creates a new metrics aggregator.
func NewMetricsAggregator() *MetricsAggregator {
	return &MetricsAggregator{
		metrics: make([]Metric, 0),
	}
}

// Add adds metrics to the aggregator.
func (a *MetricsAggregator) Add(metrics []Metric) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.metrics = append(a.metrics, metrics...)
}

// Get returns all aggregated metrics and clears the buffer.
func (a *MetricsAggregator) Get() []Metric {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := a.metrics
	a.metrics = make([]Metric, 0)
	return result
}

// NormalizeMetrics normalizes metrics to a common format.
func NormalizeMetrics(metrics []Metric, provider string) []Metric {
	normalized := make([]Metric, 0, len(metrics))

	for _, m := range metrics {
		// Add provider label if not present
		if m.Labels == nil {
			m.Labels = make(map[string]string)
		}
		if _, ok := m.Labels["provider"]; !ok {
			m.Labels["provider"] = provider
		}

		// Normalize metric name to standard format
		m.Name = normalizeMetricName(m.Name, provider)

		normalized = append(normalized, m)
	}

	return normalized
}

// normalizeMetricName normalizes metric names to standard format.
func normalizeMetricName(name, provider string) string {
	// Map provider-specific metric names to standard names
	mappings := map[string]map[string]string{
		"aws": {
			"CPUUtilization":    "cloud.vm.cpu.utilization",
			"MemoryUtilization": "cloud.vm.memory.utilization",
			"DiskReadOps":       "cloud.vm.disk.read_ops",
			"DiskWriteOps":      "cloud.vm.disk.write_ops",
			"NetworkIn":         "cloud.vm.network.in_bytes",
			"NetworkOut":        "cloud.vm.network.out_bytes",
		},
		"gcp": {
			"compute.googleapis.com/instance/cpu/utilization":         "cloud.vm.cpu.utilization",
			"compute.googleapis.com/instance/memory/balloon/ram_used": "cloud.vm.memory.used",
			"compute.googleapis.com/instance/disk/read_ops_count":     "cloud.vm.disk.read_ops",
			"compute.googleapis.com/instance/disk/write_ops_count":    "cloud.vm.disk.write_ops",
		},
		"azure": {
			"Percentage CPU":            "cloud.vm.cpu.utilization",
			"Available Memory Bytes":    "cloud.vm.memory.available",
			"Disk Read Operations/Sec":  "cloud.vm.disk.read_ops",
			"Disk Write Operations/Sec": "cloud.vm.disk.write_ops",
		},
	}

	if providerMappings, ok := mappings[provider]; ok {
		if standardName, ok := providerMappings[name]; ok {
			return standardName
		}
	}

	return name
}
