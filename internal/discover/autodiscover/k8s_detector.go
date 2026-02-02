package autodiscover

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// K8sDetector detects Kubernetes environment.
type K8sDetector struct{}

// NewK8sDetector creates a new Kubernetes detector.
func NewK8sDetector() *K8sDetector {
	return &K8sDetector{}
}

// Name returns the detector name.
func (d *K8sDetector) Name() string {
	return "kubernetes"
}

// Priority returns the detection priority.
func (d *K8sDetector) Priority() int {
	return 3
}

// Dependencies returns detector dependencies.
func (d *K8sDetector) Dependencies() []string {
	return []string{"container"}
}

// Detect runs Kubernetes detection.
func (d *K8sDetector) Detect(ctx context.Context) (any, error) {
	info := &K8sInfo{
		Detected: false,
	}

	// Check for KUBERNETES_SERVICE_HOST environment variable
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		info.Detected = true
		info.Method = "env"
		info.APIServerHost = host
		info.APIServerPort = os.Getenv("KUBERNETES_SERVICE_PORT")
	}

	if !info.Detected {
		return info, nil
	}

	// Get pod information from environment and downward API
	d.enrichFromEnv(info)
	d.enrichFromDownwardAPI(info)
	d.enrichFromServiceAccount(info)

	return info, nil
}

// enrichFromEnv adds information from environment variables.
func (d *K8sDetector) enrichFromEnv(info *K8sInfo) {
	// Common environment variables set by Kubernetes
	if podName := os.Getenv("HOSTNAME"); podName != "" && info.PodName == "" {
		info.PodName = podName
	}

	// Some deployments set these explicitly
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		info.Namespace = ns
	}
	if name := os.Getenv("POD_NAME"); name != "" {
		info.PodName = name
	}
	if ip := os.Getenv("POD_IP"); ip != "" {
		info.PodIP = ip
	}
	if node := os.Getenv("NODE_NAME"); node != "" {
		info.NodeName = node
	}
	if nodeIP := os.Getenv("NODE_IP"); nodeIP != "" {
		info.NodeIP = nodeIP
	}

	// Check for common naming conventions
	if cluster := os.Getenv("CLUSTER_NAME"); cluster != "" {
		info.ClusterName = cluster
	}
}

// enrichFromDownwardAPI adds information from the Kubernetes downward API.
func (d *K8sDetector) enrichFromDownwardAPI(info *K8sInfo) {
	// Standard downward API paths
	downwardAPIPath := "/etc/podinfo"

	// Try to read namespace
	if data, err := os.ReadFile(filepath.Join(downwardAPIPath, "namespace")); err == nil {
		info.Namespace = strings.TrimSpace(string(data))
		info.Method = "downward_api"
	}

	// Try to read pod name
	if data, err := os.ReadFile(filepath.Join(downwardAPIPath, "name")); err == nil {
		info.PodName = strings.TrimSpace(string(data))
	}

	// Try to read pod UID
	if data, err := os.ReadFile(filepath.Join(downwardAPIPath, "uid")); err == nil {
		info.PodUID = strings.TrimSpace(string(data))
	}

	// Try to read labels
	if data, err := os.ReadFile(filepath.Join(downwardAPIPath, "labels")); err == nil {
		info.Labels = parseKeyValueFile(string(data))
	}

	// Try to read annotations
	if data, err := os.ReadFile(filepath.Join(downwardAPIPath, "annotations")); err == nil {
		info.Annotations = parseKeyValueFile(string(data))
	}

	// Alternative path used by some setups
	if info.Namespace == "" {
		if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			info.Namespace = strings.TrimSpace(string(data))
		}
	}
}

// enrichFromServiceAccount reads service account information.
func (d *K8sDetector) enrichFromServiceAccount(info *K8sInfo) {
	saPath := "/var/run/secrets/kubernetes.io/serviceaccount"

	// Check if service account directory exists
	if _, err := os.Stat(saPath); os.IsNotExist(err) {
		return
	}

	// Read namespace (most reliable source)
	if data, err := os.ReadFile(filepath.Join(saPath, "namespace")); err == nil {
		info.Namespace = strings.TrimSpace(string(data))
	}

	// Check for token presence (indicates we can potentially call the API)
	if _, err := os.Stat(filepath.Join(saPath, "token")); err == nil { //nolint:staticcheck // SA9003: reserved for API auth
		// Token exists, we could authenticate with the API server
	}
}

// parseKeyValueFile parses a file with key="value" format (one per line).
func parseKeyValueFile(content string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		result[key] = value
	}

	return result
}

// DeriveOwnerFromPodName tries to derive the owner (Deployment, StatefulSet, etc.) from the pod name.
func DeriveOwnerFromPodName(podName string) (kind, name string) {
	// Pod naming conventions:
	// Deployment:   <deployment-name>-<replicaset-hash>-<pod-hash>
	// StatefulSet:  <statefulset-name>-<ordinal>
	// DaemonSet:    <daemonset-name>-<node-specific-hash>
	// Job:          <job-name>-<random-suffix>

	parts := strings.Split(podName, "-")
	if len(parts) < 2 {
		return "", podName
	}

	// Check for StatefulSet (ends with ordinal number)
	lastPart := parts[len(parts)-1]
	if isNumeric(lastPart) {
		// Likely a StatefulSet
		name = strings.Join(parts[:len(parts)-1], "-")
		return "StatefulSet", name
	}

	// Deployment pods have two hash suffixes
	if len(parts) >= 3 {
		// Check if last two parts look like hashes
		if looksLikeHash(parts[len(parts)-1]) && looksLikeHash(parts[len(parts)-2]) {
			name = strings.Join(parts[:len(parts)-2], "-")
			return "Deployment", name
		}
	}

	// DaemonSet or Job (single hash suffix)
	if looksLikeHash(lastPart) {
		name = strings.Join(parts[:len(parts)-1], "-")
		// Can't distinguish between DaemonSet and Job from name alone
		return "Unknown", name
	}

	return "", podName
}

// isNumeric checks if a string is a number.
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// looksLikeHash checks if a string looks like a Kubernetes hash.
func looksLikeHash(s string) bool {
	// K8s hashes are typically 5-10 alphanumeric characters
	if len(s) < 5 || len(s) > 10 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
