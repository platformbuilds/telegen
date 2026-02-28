// Package k8s provides Kubernetes environment detection and metadata collection.
package k8s

import (
	"context"
	"os"
	"sync"
	"time"
)

// Environment variables that indicate Kubernetes environment.
const (
	// EnvKubernetesServiceHost is set by Kubernetes in every pod.
	EnvKubernetesServiceHost = "KUBERNETES_SERVICE_HOST"
	// EnvKubernetesServicePort is set by Kubernetes in every pod.
	EnvKubernetesServicePort = "KUBERNETES_SERVICE_PORT"
	// EnvPodName is typically set via downward API.
	EnvPodName = "POD_NAME"
	// EnvPodNamespace is typically set via downward API.
	EnvPodNamespace = "POD_NAMESPACE"
	// EnvNodeName is typically set via downward API.
	EnvNodeName = "NODE_NAME"
	// EnvPodIP is typically set via downward API.
	EnvPodIP = "POD_IP"
	// EnvPodServiceAccount is typically set via downward API.
	EnvPodServiceAccount = "POD_SERVICE_ACCOUNT"
)

// Detector provides Kubernetes environment detection.
type Detector struct {
	mu       sync.RWMutex
	detected bool
	metadata *Metadata
}

// Metadata contains Kubernetes pod metadata.
type Metadata struct {
	// InKubernetes indicates whether running in a Kubernetes cluster.
	InKubernetes bool `json:"in_kubernetes"`

	// ServiceHost is the Kubernetes API server host.
	ServiceHost string `json:"service_host,omitempty"`
	// ServicePort is the Kubernetes API server port.
	ServicePort string `json:"service_port,omitempty"`

	// PodName is the name of the pod (from downward API).
	PodName string `json:"pod_name,omitempty"`
	// PodNamespace is the namespace of the pod (from downward API).
	PodNamespace string `json:"pod_namespace,omitempty"`
	// NodeName is the name of the node (from downward API).
	NodeName string `json:"node_name,omitempty"`
	// PodIP is the IP address of the pod (from downward API).
	PodIP string `json:"pod_ip,omitempty"`
	// ServiceAccount is the service account name (from downward API).
	ServiceAccount string `json:"service_account,omitempty"`

	// DetectedAt is the timestamp when detection was performed.
	DetectedAt time.Time `json:"detected_at"`
}

// NewDetector creates a new Kubernetes detector.
func NewDetector() *Detector {
	return &Detector{}
}

// IsRunningInKubernetes returns true if running inside a Kubernetes cluster.
// This is a quick check that doesn't cache results.
func IsRunningInKubernetes() bool {
	_, exists := os.LookupEnv(EnvKubernetesServiceHost)
	return exists
}

// Detect performs Kubernetes environment detection and caches the result.
func (d *Detector) Detect(ctx context.Context) *Metadata {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Return cached result if available.
	if d.detected && d.metadata != nil {
		return d.metadata
	}

	d.metadata = d.detect()
	d.detected = true
	return d.metadata
}

// GetMetadata returns cached metadata, or performs detection if not cached.
func (d *Detector) GetMetadata(ctx context.Context) *Metadata {
	d.mu.RLock()
	if d.detected && d.metadata != nil {
		meta := d.metadata
		d.mu.RUnlock()
		return meta
	}
	d.mu.RUnlock()

	return d.Detect(ctx)
}

// Reset clears the cached detection result.
func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.detected = false
	d.metadata = nil
}

// detect performs the actual detection.
func (d *Detector) detect() *Metadata {
	serviceHost, inK8s := os.LookupEnv(EnvKubernetesServiceHost)

	meta := &Metadata{
		InKubernetes: inK8s,
		DetectedAt:   time.Now(),
	}

	if !inK8s {
		return meta
	}

	meta.ServiceHost = serviceHost
	meta.ServicePort = os.Getenv(EnvKubernetesServicePort)
	meta.PodName = os.Getenv(EnvPodName)
	meta.PodNamespace = os.Getenv(EnvPodNamespace)
	meta.NodeName = os.Getenv(EnvNodeName)
	meta.PodIP = os.Getenv(EnvPodIP)
	meta.ServiceAccount = os.Getenv(EnvPodServiceAccount)

	return meta
}

// ResourceAttributes returns the metadata as OTLP resource attributes.
func (m *Metadata) ResourceAttributes() map[string]string {
	if m == nil || !m.InKubernetes {
		return nil
	}

	attrs := make(map[string]string)

	// Use OpenTelemetry semantic conventions for Kubernetes.
	// https://opentelemetry.io/docs/specs/semconv/resource/k8s/
	if m.PodName != "" {
		attrs["k8s.pod.name"] = m.PodName
	}
	if m.PodNamespace != "" {
		attrs["k8s.namespace.name"] = m.PodNamespace
	}
	if m.NodeName != "" {
		attrs["k8s.node.name"] = m.NodeName
	}
	if m.PodIP != "" {
		attrs["k8s.pod.ip"] = m.PodIP
	}
	if m.ServiceAccount != "" {
		attrs["k8s.pod.service_account.name"] = m.ServiceAccount
	}

	return attrs
}
