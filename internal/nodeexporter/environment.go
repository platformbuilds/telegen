// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package nodeexporter

import (
	"os"
	"path/filepath"
	"strings"
)

// DetectedEnvironment holds information about the detected deployment environment.
type DetectedEnvironment struct {
	// Type is the detected environment type
	Type EnvironmentType

	// IsVirtualized indicates if running in a virtualized environment
	IsVirtualized bool

	// VirtualizationType is the type of virtualization (if detected)
	// e.g., "kvm", "vmware", "xen", "hyperv", "docker", "lxc"
	VirtualizationType string

	// Kubernetes holds K8s-specific information (if running in K8s)
	Kubernetes *K8sEnvironment

	// Labels holds environment-specific labels to add to metrics
	Labels map[string]string
}

// K8sEnvironment holds Kubernetes environment information.
type K8sEnvironment struct {
	// Detected indicates if K8s environment was detected
	Detected bool

	// NodeName is the Kubernetes node name
	NodeName string

	// Namespace is the pod namespace
	Namespace string

	// PodName is the pod name
	PodName string

	// PodIP is the pod IP address
	PodIP string

	// ClusterName is the cluster name
	ClusterName string

	// APIServerHost is the K8s API server host
	APIServerHost string

	// APIServerPort is the K8s API server port
	APIServerPort string
}

// DetectEnvironment detects the current deployment environment.
func DetectEnvironment(cfg EnvironmentConfig) *DetectedEnvironment {
	env := &DetectedEnvironment{
		Type:   EnvironmentType(cfg.Type),
		Labels: make(map[string]string),
	}

	// If not auto-detect, use configured type
	if !cfg.AutoDetect && cfg.Type != "auto" {
		env.Type = EnvironmentType(cfg.Type)
		// Copy configured labels
		for k, v := range cfg.Labels {
			env.Labels[k] = v
		}
		return env
	}

	// Auto-detect environment
	env.detectKubernetes(&cfg)
	env.detectVirtualization()
	env.detectContainerRuntime()

	// Determine final environment type
	if env.Kubernetes != nil && env.Kubernetes.Detected {
		env.Type = EnvironmentKubernetes
		env.Labels["kubernetes_node"] = env.Kubernetes.NodeName
		if env.Kubernetes.Namespace != "" {
			env.Labels["kubernetes_namespace"] = env.Kubernetes.Namespace
		}
		if env.Kubernetes.ClusterName != "" {
			env.Labels["kubernetes_cluster"] = env.Kubernetes.ClusterName
		}
	} else if env.VirtualizationType == "docker" || env.VirtualizationType == "lxc" || env.VirtualizationType == "containerd" {
		env.Type = EnvironmentContainer
		env.Labels["container_runtime"] = env.VirtualizationType
	} else if env.IsVirtualized {
		env.Type = EnvironmentVirtualMachine
		if env.VirtualizationType != "" {
			env.Labels["virtualization"] = env.VirtualizationType
		}
	} else {
		env.Type = EnvironmentBareMetal
	}

	// Copy additional configured labels
	for k, v := range cfg.Labels {
		env.Labels[k] = v
	}

	return env
}

// detectKubernetes detects Kubernetes environment.
func (e *DetectedEnvironment) detectKubernetes(cfg *EnvironmentConfig) {
	k8s := &K8sEnvironment{}

	// Check for KUBERNETES_SERVICE_HOST environment variable
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		k8s.Detected = true
		k8s.APIServerHost = host
		k8s.APIServerPort = os.Getenv("KUBERNETES_SERVICE_PORT")
	}

	// Get pod/node information from environment
	if nodeName := getEnvWithFallback("NODE_NAME", cfg.Kubernetes.NodeName); nodeName != "" {
		k8s.NodeName = nodeName
	}
	if namespace := getEnvWithFallback("POD_NAMESPACE", cfg.Kubernetes.Namespace); namespace != "" {
		k8s.Namespace = namespace
	}
	if podName := getEnvWithFallback("POD_NAME", cfg.Kubernetes.PodName); podName != "" {
		k8s.PodName = podName
	} else if hostname := os.Getenv("HOSTNAME"); hostname != "" && k8s.Detected {
		k8s.PodName = hostname
	}
	if podIP := os.Getenv("POD_IP"); podIP != "" {
		k8s.PodIP = podIP
	}
	if clusterName := getEnvWithFallback("CLUSTER_NAME", cfg.Kubernetes.ClusterName); clusterName != "" {
		k8s.ClusterName = clusterName
	}

	// Try to read from downward API
	if k8s.Detected {
		e.enrichFromDownwardAPI(k8s)
	}

	// Check for service account token as additional K8s indicator
	if !k8s.Detected {
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
			k8s.Detected = true
		}
	}

	if k8s.Detected {
		e.Kubernetes = k8s
	}
}

// enrichFromDownwardAPI reads K8s metadata from downward API files.
func (e *DetectedEnvironment) enrichFromDownwardAPI(k8s *K8sEnvironment) {
	downwardAPIPath := "/etc/podinfo"

	// Try to read namespace
	if k8s.Namespace == "" {
		if data, err := os.ReadFile(filepath.Join(downwardAPIPath, "namespace")); err == nil {
			k8s.Namespace = strings.TrimSpace(string(data))
		}
	}

	// Try to read pod name
	if k8s.PodName == "" {
		if data, err := os.ReadFile(filepath.Join(downwardAPIPath, "name")); err == nil {
			k8s.PodName = strings.TrimSpace(string(data))
		}
	}

	// Try to read labels
	if data, err := os.ReadFile(filepath.Join(downwardAPIPath, "labels")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				if key != "" && value != "" {
					e.Labels["k8s_label_"+sanitizeLabelName(key)] = value
				}
			}
		}
	}
}

// detectVirtualization detects virtualization technology.
func (e *DetectedEnvironment) detectVirtualization() {
	// Check /sys/class/dmi/id/product_name
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.ToLower(strings.TrimSpace(string(data)))
		switch {
		case strings.Contains(product, "vmware"):
			e.IsVirtualized = true
			e.VirtualizationType = "vmware"
		case strings.Contains(product, "virtualbox"):
			e.IsVirtualized = true
			e.VirtualizationType = "virtualbox"
		case strings.Contains(product, "kvm"):
			e.IsVirtualized = true
			e.VirtualizationType = "kvm"
		case strings.Contains(product, "xen"):
			e.IsVirtualized = true
			e.VirtualizationType = "xen"
		case strings.Contains(product, "virtual machine"):
			e.IsVirtualized = true
			e.VirtualizationType = "hyperv"
		case strings.Contains(product, "qemu"):
			e.IsVirtualized = true
			e.VirtualizationType = "qemu"
		}
	}

	// Check /sys/hypervisor/type
	if !e.IsVirtualized {
		if data, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
			hypervisor := strings.ToLower(strings.TrimSpace(string(data)))
			if hypervisor != "" {
				e.IsVirtualized = true
				e.VirtualizationType = hypervisor
			}
		}
	}

	// Check cpuinfo for hypervisor flag
	if !e.IsVirtualized {
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			if strings.Contains(string(data), "hypervisor") {
				e.IsVirtualized = true
				e.VirtualizationType = "unknown"
			}
		}
	}
}

// detectContainerRuntime detects container runtime.
func (e *DetectedEnvironment) detectContainerRuntime() {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		e.VirtualizationType = "docker"
		return
	}

	// Check cgroup for container runtime
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		switch {
		case strings.Contains(content, "docker"):
			e.VirtualizationType = "docker"
		case strings.Contains(content, "kubepods"):
			e.VirtualizationType = "containerd"
		case strings.Contains(content, "lxc"):
			e.VirtualizationType = "lxc"
		case strings.Contains(content, "containerd"):
			e.VirtualizationType = "containerd"
		case strings.Contains(content, "crio"):
			e.VirtualizationType = "crio"
		}
	}

	// Check for containerd socket
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		if e.VirtualizationType == "" {
			e.VirtualizationType = "containerd"
		}
	}
}

// getEnvWithFallback returns the environment variable value or fallback.
func getEnvWithFallback(envVar, fallback string) string {
	if val := os.Getenv(envVar); val != "" {
		return val
	}
	return fallback
}

// sanitizeLabelName converts a label name to Prometheus-compatible format.
func sanitizeLabelName(name string) string {
	// Replace non-alphanumeric chars with underscore
	result := strings.Builder{}
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			result.WriteRune(c)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}

// String returns a string representation of the environment type.
func (e EnvironmentType) String() string {
	return string(e)
}
