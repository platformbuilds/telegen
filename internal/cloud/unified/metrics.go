package unified

import (
	"context"
	"time"
)

// MetricType defines the type of metric.
type MetricType string

const (
	// MetricTypeGauge represents a point-in-time value.
	MetricTypeGauge MetricType = "gauge"

	// MetricTypeCounter represents a monotonically increasing value.
	MetricTypeCounter MetricType = "counter"

	// MetricTypeHistogram represents a distribution of values.
	MetricTypeHistogram MetricType = "histogram"

	// MetricTypeSummary represents a summary with quantiles.
	MetricTypeSummary MetricType = "summary"
)

// MetricUnit defines standard units for metrics.
type MetricUnit string

const (
	MetricUnitNone        MetricUnit = ""
	MetricUnitPercent     MetricUnit = "percent"
	MetricUnitBytes       MetricUnit = "bytes"
	MetricUnitKilobytes   MetricUnit = "KB"
	MetricUnitMegabytes   MetricUnit = "MB"
	MetricUnitGigabytes   MetricUnit = "GB"
	MetricUnitTerabytes   MetricUnit = "TB"
	MetricUnitSeconds     MetricUnit = "seconds"
	MetricUnitMillis      MetricUnit = "milliseconds"
	MetricUnitMicros      MetricUnit = "microseconds"
	MetricUnitNanos       MetricUnit = "nanoseconds"
	MetricUnitCount       MetricUnit = "count"
	MetricUnitCountPerSec MetricUnit = "count/sec"
	MetricUnitBytesPerSec MetricUnit = "bytes/sec"
	MetricUnitIOPS        MetricUnit = "iops"
)

// Metric represents a unified cloud metric.
type Metric struct {
	// Name is the metric name in cloud.* namespace.
	Name string `json:"name"`

	// Value is the metric value.
	Value float64 `json:"value"`

	// Timestamp of the measurement.
	Timestamp time.Time `json:"timestamp"`

	// Labels are metric dimensions/attributes.
	Labels map[string]string `json:"labels,omitempty"`

	// Unit of the metric value.
	Unit MetricUnit `json:"unit,omitempty"`

	// Type of the metric.
	Type MetricType `json:"type"`

	// Description provides human-readable context.
	Description string `json:"description,omitempty"`

	// Provider that produced this metric.
	Provider string `json:"provider,omitempty"`

	// ResourceID links the metric to a specific resource.
	ResourceID string `json:"resource_id,omitempty"`

	// ResourceType indicates the type of resource.
	ResourceType ResourceType `json:"resource_type,omitempty"`
}

// MetricName constants for unified cloud metrics.
// These follow the pattern: cloud.<resource_type>.<metric_name>
const (
	// VM/Instance CPU metrics
	MetricVMCPUUtilization = "cloud.vm.cpu.utilization"
	MetricVMCPUUsed        = "cloud.vm.cpu.used"
	MetricVMCPUReady       = "cloud.vm.cpu.ready"
	MetricVMCPUWait        = "cloud.vm.cpu.wait"

	// VM/Instance Memory metrics
	MetricVMMemoryUtilization = "cloud.vm.memory.utilization"
	MetricVMMemoryUsed        = "cloud.vm.memory.used"
	MetricVMMemoryFree        = "cloud.vm.memory.free"
	MetricVMMemoryTotal       = "cloud.vm.memory.total"
	MetricVMMemorySwapUsed    = "cloud.vm.memory.swap.used"
	MetricVMMemoryBalloon     = "cloud.vm.memory.balloon"

	// VM/Instance Disk metrics
	MetricVMDiskReadBytes   = "cloud.vm.disk.read.bytes"
	MetricVMDiskWriteBytes  = "cloud.vm.disk.write.bytes"
	MetricVMDiskReadOps     = "cloud.vm.disk.read.ops"
	MetricVMDiskWriteOps    = "cloud.vm.disk.write.ops"
	MetricVMDiskLatency     = "cloud.vm.disk.latency"
	MetricVMDiskUtilization = "cloud.vm.disk.utilization"

	// VM/Instance Network metrics
	MetricVMNetworkRxBytes   = "cloud.vm.network.rx.bytes"
	MetricVMNetworkTxBytes   = "cloud.vm.network.tx.bytes"
	MetricVMNetworkRxPackets = "cloud.vm.network.rx.packets"
	MetricVMNetworkTxPackets = "cloud.vm.network.tx.packets"
	MetricVMNetworkRxDropped = "cloud.vm.network.rx.dropped"
	MetricVMNetworkTxDropped = "cloud.vm.network.tx.dropped"
	MetricVMNetworkRxErrors  = "cloud.vm.network.rx.errors"
	MetricVMNetworkTxErrors  = "cloud.vm.network.tx.errors"

	// Host/Hypervisor CPU metrics
	MetricHostCPUUtilization = "cloud.host.cpu.utilization"
	MetricHostCPUCores       = "cloud.host.cpu.cores"
	MetricHostCPUUsed        = "cloud.host.cpu.used"

	// Host/Hypervisor Memory metrics
	MetricHostMemoryUtilization = "cloud.host.memory.utilization"
	MetricHostMemoryUsed        = "cloud.host.memory.used"
	MetricHostMemoryFree        = "cloud.host.memory.free"
	MetricHostMemoryTotal       = "cloud.host.memory.total"

	// Host VM count
	MetricHostVMsRunning    = "cloud.host.vms.running"
	MetricHostVMsTotal      = "cloud.host.vms.total"
	MetricHostVMsPoweredOff = "cloud.host.vms.powered_off"

	// Datastore/Storage metrics
	MetricDatastoreCapacity    = "cloud.datastore.capacity"
	MetricDatastoreFree        = "cloud.datastore.free"
	MetricDatastoreUsed        = "cloud.datastore.used"
	MetricDatastoreProvisioned = "cloud.datastore.provisioned"
	MetricDatastoreUtilization = "cloud.datastore.utilization"

	// Cluster metrics
	MetricClusterCPUUtilization    = "cloud.cluster.cpu.utilization"
	MetricClusterMemoryUtilization = "cloud.cluster.memory.utilization"
	MetricClusterHostsTotal        = "cloud.cluster.hosts.total"
	MetricClusterHostsHealthy      = "cloud.cluster.hosts.healthy"
	MetricClusterVMsTotal          = "cloud.cluster.vms.total"

	// Volume metrics
	MetricVolumeSize       = "cloud.volume.size"
	MetricVolumeIOPS       = "cloud.volume.iops"
	MetricVolumeThroughput = "cloud.volume.throughput"

	// Network metrics
	MetricNetworkBandwidth  = "cloud.network.bandwidth"
	MetricNetworkPacketsIn  = "cloud.network.packets.in"
	MetricNetworkPacketsOut = "cloud.network.packets.out"
)

// UnifiedMetricMapping maps provider-specific metric names to unified names.
type UnifiedMetricMapping struct {
	AWS       string
	GCP       string
	Azure     string
	OpenStack string
	VMware    string
	Nutanix   string
}

// MetricMappings provides mappings from provider-specific to unified metric names.
var MetricMappings = map[string]UnifiedMetricMapping{
	MetricVMCPUUtilization: {
		AWS:       "CPUUtilization",
		GCP:       "compute.googleapis.com/instance/cpu/utilization",
		Azure:     "Percentage CPU",
		OpenStack: "cpu_util",
		VMware:    "cpu.usage.average",
		Nutanix:   "hypervisor_cpu_usage_ppm",
	},
	MetricVMMemoryUtilization: {
		AWS:       "mem_used_percent",
		GCP:       "compute.googleapis.com/instance/memory/balloon/ram_used",
		Azure:     "Available Memory Bytes",
		OpenStack: "memory.usage",
		VMware:    "mem.usage.average",
		Nutanix:   "hypervisor_memory_usage_ppm",
	},
	MetricVMDiskReadBytes: {
		AWS:       "DiskReadBytes",
		GCP:       "compute.googleapis.com/instance/disk/read_bytes_count",
		Azure:     "Disk Read Bytes",
		OpenStack: "disk.read.bytes",
		VMware:    "virtualDisk.read.average",
		Nutanix:   "controller_io_bandwidth_kBps",
	},
	MetricVMDiskWriteBytes: {
		AWS:       "DiskWriteBytes",
		GCP:       "compute.googleapis.com/instance/disk/write_bytes_count",
		Azure:     "Disk Write Bytes",
		OpenStack: "disk.write.bytes",
		VMware:    "virtualDisk.write.average",
		Nutanix:   "controller_io_bandwidth_kBps",
	},
	MetricVMNetworkRxBytes: {
		AWS:       "NetworkIn",
		GCP:       "compute.googleapis.com/instance/network/received_bytes_count",
		Azure:     "Network In Total",
		OpenStack: "network.incoming.bytes",
		VMware:    "net.received.average",
		Nutanix:   "hypervisor_num_received_bytes",
	},
	MetricVMNetworkTxBytes: {
		AWS:       "NetworkOut",
		GCP:       "compute.googleapis.com/instance/network/sent_bytes_count",
		Azure:     "Network Out Total",
		OpenStack: "network.outgoing.bytes",
		VMware:    "net.transmitted.average",
		Nutanix:   "hypervisor_num_transmitted_bytes",
	},
}

// NormalizeMetricName converts a provider-specific metric name to the unified name.
func NormalizeMetricName(providerName, provider string) string {
	for unifiedName, mapping := range MetricMappings {
		var match string
		switch provider {
		case "aws":
			match = mapping.AWS
		case "gcp":
			match = mapping.GCP
		case "azure":
			match = mapping.Azure
		case "openstack":
			match = mapping.OpenStack
		case "vmware":
			match = mapping.VMware
		case "nutanix":
			match = mapping.Nutanix
		}
		if match == providerName {
			return unifiedName
		}
	}
	// Return original name with cloud. prefix if no mapping found
	return "cloud.custom." + providerName
}

// NewMetric creates a new Metric with the current timestamp.
func NewMetric(name string, value float64, metricType MetricType) Metric {
	return Metric{
		Name:      name,
		Value:     value,
		Timestamp: time.Now(),
		Type:      metricType,
	}
}

// NewGaugeMetric creates a gauge metric.
func NewGaugeMetric(name string, value float64) Metric {
	return NewMetric(name, value, MetricTypeGauge)
}

// NewCounterMetric creates a counter metric.
func NewCounterMetric(name string, value float64) Metric {
	return NewMetric(name, value, MetricTypeCounter)
}

// WithLabels adds labels to the metric and returns it.
func (m Metric) WithLabels(labels map[string]string) Metric {
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	}
	for k, v := range labels {
		m.Labels[k] = v
	}
	return m
}

// WithUnit sets the unit and returns the metric.
func (m Metric) WithUnit(unit MetricUnit) Metric {
	m.Unit = unit
	return m
}

// WithResource sets resource information and returns the metric.
func (m Metric) WithResource(resourceID string, resourceType ResourceType) Metric {
	m.ResourceID = resourceID
	m.ResourceType = resourceType
	return m
}

// WithProvider sets the provider and returns the metric.
func (m Metric) WithProvider(provider string) Metric {
	m.Provider = provider
	return m
}

// MetricsCollector collects and normalizes metrics from any cloud provider.
type MetricsCollector struct {
	manager *CloudManager
}

// NewMetricsCollector creates a new metrics collector.
func NewMetricsCollector(manager *CloudManager) *MetricsCollector {
	return &MetricsCollector{manager: manager}
}

// Collect gathers metrics from the active cloud provider.
func (mc *MetricsCollector) Collect(ctx context.Context) ([]Metric, error) {
	provider := mc.manager.GetActiveProvider()
	if provider == nil {
		return nil, nil
	}
	return provider.CollectMetrics(ctx)
}

// CollectNormalized collects metrics and normalizes names to unified format.
func (mc *MetricsCollector) CollectNormalized(ctx context.Context) ([]Metric, error) {
	metrics, err := mc.Collect(ctx)
	if err != nil {
		return nil, err
	}

	provider := mc.manager.GetActiveProvider()
	if provider == nil {
		return metrics, nil
	}

	providerName := provider.Name()
	normalized := make([]Metric, len(metrics))
	for i, m := range metrics {
		normalized[i] = m
		normalized[i].Name = NormalizeMetricName(m.Name, providerName)
		normalized[i].Provider = providerName
	}

	return normalized, nil
}
