package enrichment

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// K8sEnricher enriches signals with Kubernetes metadata.
type K8sEnricher struct {
	config   K8sEnricherConfig
	logger   *slog.Logger
	metadata *K8sMetadata
	mu       sync.RWMutex
	running  bool
}

// K8sMetadata holds Kubernetes metadata.
type K8sMetadata struct {
	// Cluster info.
	ClusterName string `json:"cluster_name"`
	ClusterUID  string `json:"cluster_uid"`

	// Node info.
	NodeName string `json:"node_name"`
	NodeIP   string `json:"node_ip"`

	// Pod info (from downward API).
	PodName      string            `json:"pod_name"`
	PodNamespace string            `json:"pod_namespace"`
	PodUID       string            `json:"pod_uid"`
	PodIP        string            `json:"pod_ip"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`

	// Workload info.
	OwnerKind string `json:"owner_kind"`
	OwnerName string `json:"owner_name"`

	// Service account.
	ServiceAccount string `json:"service_account"`

	// Container info.
	ContainerName string `json:"container_name"`

	FetchedAt time.Time `json:"fetched_at"`
}

// NewK8sEnricher creates a new Kubernetes enricher.
func NewK8sEnricher(config K8sEnricherConfig, logger *slog.Logger) *K8sEnricher {
	if logger == nil {
		logger = slog.Default()
	}
	return &K8sEnricher{
		config: config,
		logger: logger,
	}
}

func (k *K8sEnricher) Name() string { return "kubernetes" }

func (k *K8sEnricher) Start(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.running {
		return nil
	}

	// Check if running in K8s.
	if !k.isRunningInK8s() {
		k.logger.Debug("not running in Kubernetes, enricher disabled")
		k.running = true
		return nil
	}

	// Fetch K8s metadata from downward API and environment.
	metadata := k.fetchMetadata()
	k.metadata = metadata

	k.logger.Info("detected Kubernetes environment",
		"node", metadata.NodeName,
		"namespace", metadata.PodNamespace,
		"pod", metadata.PodName)

	k.running = true
	return nil
}

func (k *K8sEnricher) Stop() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.running = false
	return nil
}

func (k *K8sEnricher) Enrich(ctx context.Context, resource pcommon.Resource) error {
	k.mu.RLock()
	metadata := k.metadata
	k.mu.RUnlock()

	if metadata == nil {
		return nil
	}

	attrs := resource.Attributes()

	// Set K8s semantic conventions.
	if metadata.ClusterName != "" {
		attrs.PutStr("k8s.cluster.name", metadata.ClusterName)
	}
	if metadata.ClusterUID != "" {
		attrs.PutStr("k8s.cluster.uid", metadata.ClusterUID)
	}
	if metadata.NodeName != "" {
		attrs.PutStr("k8s.node.name", metadata.NodeName)
	}
	if metadata.PodName != "" {
		attrs.PutStr("k8s.pod.name", metadata.PodName)
	}
	if metadata.PodNamespace != "" {
		attrs.PutStr("k8s.namespace.name", metadata.PodNamespace)
	}
	if metadata.PodUID != "" {
		attrs.PutStr("k8s.pod.uid", metadata.PodUID)
	}
	if metadata.PodIP != "" {
		attrs.PutStr("k8s.pod.ip", metadata.PodIP)
	}
	if metadata.ContainerName != "" {
		attrs.PutStr("k8s.container.name", metadata.ContainerName)
	}

	// Workload info.
	if metadata.OwnerKind != "" && metadata.OwnerName != "" {
		switch strings.ToLower(metadata.OwnerKind) {
		case "deployment":
			attrs.PutStr("k8s.deployment.name", metadata.OwnerName)
		case "daemonset":
			attrs.PutStr("k8s.daemonset.name", metadata.OwnerName)
		case "statefulset":
			attrs.PutStr("k8s.statefulset.name", metadata.OwnerName)
		case "replicaset":
			attrs.PutStr("k8s.replicaset.name", metadata.OwnerName)
		case "job":
			attrs.PutStr("k8s.job.name", metadata.OwnerName)
		case "cronjob":
			attrs.PutStr("k8s.cronjob.name", metadata.OwnerName)
		}
	}

	// Add selected labels.
	for key, value := range metadata.Labels {
		// Convert k8s label to attribute key.
		attrKey := "k8s.pod.label." + strings.ReplaceAll(key, "/", "_")
		attrs.PutStr(attrKey, value)
	}

	return nil
}

func (k *K8sEnricher) isRunningInK8s() bool {
	// Check for K8s service account token.
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	// Check for KUBERNETES_SERVICE_HOST environment variable.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	return false
}

func (k *K8sEnricher) fetchMetadata() *K8sMetadata {
	metadata := &K8sMetadata{
		FetchedAt: time.Now(),
		Labels:    make(map[string]string),
	}

	// From environment variables (downward API).
	metadata.PodName = os.Getenv("POD_NAME")
	metadata.PodNamespace = os.Getenv("POD_NAMESPACE")
	metadata.PodUID = os.Getenv("POD_UID")
	metadata.PodIP = os.Getenv("POD_IP")
	metadata.NodeName = os.Getenv("NODE_NAME")
	metadata.NodeIP = os.Getenv("NODE_IP")
	metadata.ServiceAccount = os.Getenv("SERVICE_ACCOUNT")
	metadata.ContainerName = os.Getenv("CONTAINER_NAME")

	// Cluster info.
	metadata.ClusterName = os.Getenv("CLUSTER_NAME")
	if metadata.ClusterName == "" {
		metadata.ClusterName = os.Getenv("K8S_CLUSTER_NAME")
	}

	// Owner info.
	metadata.OwnerKind = os.Getenv("OWNER_KIND")
	metadata.OwnerName = os.Getenv("OWNER_NAME")

	// Try to get from hostname if POD_NAME not set.
	if metadata.PodName == "" {
		metadata.PodName, _ = os.Hostname()
	}

	// Read labels from file if available (downward API).
	if labelsData, err := os.ReadFile("/etc/podinfo/labels"); err == nil {
		metadata.Labels = k.parseLabelsFile(string(labelsData))
	}

	return metadata
}

func (k *K8sEnricher) parseLabelsFile(data string) map[string]string {
	labels := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			labels[key] = value
		}
	}
	return labels
}

// GetMetadata returns the current cached metadata.
func (k *K8sEnricher) GetMetadata() *K8sMetadata {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.metadata
}

// IsKubernetes returns true if running in Kubernetes.
func (k *K8sEnricher) IsKubernetes() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.metadata != nil && k.metadata.PodName != ""
}
