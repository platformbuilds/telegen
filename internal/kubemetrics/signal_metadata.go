// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/platformbuilds/telegen/internal/sigdef"
)

// SignalMetadataDefinitions defines the signal metadata for different kube metric types
var SignalMetadataDefinitions = map[string]*sigdef.SignalMetadata{
	// Kubestate metrics by resource type
	"kube_pod": {
		Category:      "Kubernetes State",
		SubCategory:   "Pod Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Pod state and status metrics from Kubernetes API",
	},
	"kube_deployment": {
		Category:      "Kubernetes State",
		SubCategory:   "Deployment Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Deployment state metrics from Kubernetes API",
	},
	"kube_node": {
		Category:      "Kubernetes State",
		SubCategory:   "Node Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Node state and status metrics from Kubernetes API",
	},
	"kube_statefulset": {
		Category:      "Kubernetes State",
		SubCategory:   "StatefulSet Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "StatefulSet state metrics from Kubernetes API",
	},
	"kube_daemonset": {
		Category:      "Kubernetes State",
		SubCategory:   "DaemonSet Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "DaemonSet state metrics from Kubernetes API",
	},
	"kube_replicaset": {
		Category:      "Kubernetes State",
		SubCategory:   "ReplicaSet Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "ReplicaSet state metrics from Kubernetes API",
	},
	"kube_job": {
		Category:      "Kubernetes State",
		SubCategory:   "Job Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Job state and completion metrics from Kubernetes API",
	},
	"kube_cronjob": {
		Category:      "Kubernetes State",
		SubCategory:   "CronJob Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "CronJob schedule and status metrics from Kubernetes API",
	},
	"kube_service": {
		Category:      "Kubernetes State",
		SubCategory:   "Service Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Service configuration metrics from Kubernetes API",
	},
	"kube_namespace": {
		Category:      "Kubernetes State",
		SubCategory:   "Namespace Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Namespace status and resource quota metrics from Kubernetes API",
	},
	"kube_persistentvolumeclaim": {
		Category:      "Kubernetes State",
		SubCategory:   "Storage Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "PersistentVolumeClaim state metrics from Kubernetes API",
	},
	"kube_persistentvolume": {
		Category:      "Kubernetes State",
		SubCategory:   "Storage Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "PersistentVolume state metrics from Kubernetes API",
	},
	"kube_configmap": {
		Category:      "Kubernetes State",
		SubCategory:   "ConfigMap Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "ConfigMap metadata metrics from Kubernetes API",
	},
	"kube_secret": {
		Category:      "Kubernetes State",
		SubCategory:   "Secret Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Secret metadata metrics from Kubernetes API",
	},
	"kube_hpa": {
		Category:      "Kubernetes State",
		SubCategory:   "HPA Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "HorizontalPodAutoscaler state metrics from Kubernetes API",
	},
	"kube_ingress": {
		Category:      "Kubernetes State",
		SubCategory:   "Ingress Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Ingress configuration metrics from Kubernetes API",
	},
	"kube_endpoints": {
		Category:      "Kubernetes State",
		SubCategory:   "Endpoints Metrics",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubestate",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Endpoints address metrics from Kubernetes API",
	},

	// Container/cAdvisor metrics
	"container_cpu": {
		Category:      "Container Metrics",
		SubCategory:   "CPU Utilization",
		SourceModule:  "github.com/platformbuilds/telegen/internal/cadvisor",
		CollectorType: sigdef.CollectorTypeProcFS,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Container CPU usage metrics from cgroups",
	},
	"container_memory": {
		Category:      "Container Metrics",
		SubCategory:   "Memory Utilization",
		SourceModule:  "github.com/platformbuilds/telegen/internal/cadvisor",
		CollectorType: sigdef.CollectorTypeProcFS,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Container memory usage metrics from cgroups",
	},
	"container_network": {
		Category:      "Container Metrics",
		SubCategory:   "Network Utilization",
		SourceModule:  "github.com/platformbuilds/telegen/internal/cadvisor",
		CollectorType: sigdef.CollectorTypeProcFS,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Container network I/O metrics from cgroups",
	},
	"container_fs": {
		Category:      "Container Metrics",
		SubCategory:   "Disk Utilization",
		SourceModule:  "github.com/platformbuilds/telegen/internal/cadvisor",
		CollectorType: sigdef.CollectorTypeProcFS,
		SignalType:    sigdef.SignalMetrics,
		Description:   "Container disk I/O metrics from cgroups",
	},

	// Kubernetes events as logs
	"kube_event": {
		Category:      "Kubernetes Events",
		SubCategory:   "Cluster Events",
		SourceModule:  "github.com/platformbuilds/telegen/internal/kubemetrics",
		CollectorType: sigdef.CollectorTypeAPI,
		SignalType:    sigdef.SignalLogs,
		Description:   "Kubernetes cluster events as OTLP logs",
	},
}

// MetadataProvider provides signal metadata for kube metrics
type MetadataProvider struct {
	config  sigdef.MetadataFieldsConfig
	enabled bool
}

// NewMetadataProvider creates a new metadata provider
func NewMetadataProvider(config sigdef.MetadataFieldsConfig, enabled bool) *MetadataProvider {
	return &MetadataProvider{
		config:  config,
		enabled: enabled,
	}
}

// GetMetadata returns the metadata for a given metric prefix
func (p *MetadataProvider) GetMetadata(metricPrefix string) *sigdef.SignalMetadata {
	if !p.enabled {
		return nil
	}

	// Try exact match first
	if meta, ok := SignalMetadataDefinitions[metricPrefix]; ok {
		return meta
	}

	// Try prefix match for container metrics
	for prefix, meta := range SignalMetadataDefinitions {
		if len(metricPrefix) >= len(prefix) && metricPrefix[:len(prefix)] == prefix {
			return meta
		}
	}

	return nil
}

// GetAttributes returns OTEL attributes for a given metric prefix
func (p *MetadataProvider) GetAttributes(metricPrefix string) []attribute.KeyValue {
	meta := p.GetMetadata(metricPrefix)
	if meta == nil {
		return nil
	}
	return meta.ToAttributesWithConfig(p.config)
}

// GetPrometheusLabels returns Prometheus labels for a given metric prefix
func (p *MetadataProvider) GetPrometheusLabels(metricPrefix string) map[string]string {
	meta := p.GetMetadata(metricPrefix)
	if meta == nil {
		return nil
	}
	return meta.ToPrometheusLabelsWithConfig(p.config)
}

// DefaultMetadataProvider creates a metadata provider with default config
func DefaultMetadataProvider() *MetadataProvider {
	return NewMetadataProvider(sigdef.DefaultMetadataFieldsConfig(), true)
}

// GetAllMetadataKeys returns all known metric prefixes
func GetAllMetadataKeys() []string {
	keys := make([]string, 0, len(SignalMetadataDefinitions))
	for k := range SignalMetadataDefinitions {
		keys = append(keys, k)
	}
	return keys
}

// GetMetadataBySignalType returns all metadata for a given signal type
func GetMetadataBySignalType(signalType sigdef.SignalType) []*sigdef.SignalMetadata {
	results := make([]*sigdef.SignalMetadata, 0)
	for _, meta := range SignalMetadataDefinitions {
		if meta.SignalType == signalType {
			results = append(results, meta)
		}
	}
	return results
}

// GetMetadataByCategory returns all metadata for a given category
func GetMetadataByCategory(category string) []*sigdef.SignalMetadata {
	results := make([]*sigdef.SignalMetadata, 0)
	for _, meta := range SignalMetadataDefinitions {
		if meta.Category == category {
			results = append(results, meta)
		}
	}
	return results
}
