// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"bufio"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Enricher enriches security events with container and Kubernetes metadata
// Task: SEC-018
type Enricher struct {
	config Config
	logger *slog.Logger

	// Cache for container metadata
	containerCache map[uint32]*ContainerInfo
	cacheMu        sync.RWMutex

	// Kubernetes client (if available)
	k8sEnabled bool
}

// ContainerInfo holds container metadata
type ContainerInfo struct {
	ContainerID   string
	ContainerName string
	ImageName     string
	ImageTag      string
	Runtime       string // docker, containerd, cri-o
	PodName       string
	PodNamespace  string
	PodUID        string
	NodeName      string
	Labels        map[string]string
}

// NewEnricher creates a new enricher
func NewEnricher(cfg Config, logger *slog.Logger) *Enricher {
	if logger == nil {
		logger = slog.Default()
	}

	e := &Enricher{
		config:         cfg,
		logger:         logger,
		containerCache: make(map[uint32]*ContainerInfo),
	}

	// Try to detect if we're in a Kubernetes environment
	if _, err := os.Stat("/var/run/secrets/kubernetes.io"); err == nil {
		e.k8sEnabled = true
		logger.Info("Kubernetes environment detected, enabling K8s metadata enrichment")
	}

	return e
}

// EnrichSyscall enriches a syscall event with metadata
func (e *Enricher) EnrichSyscall(event *SyscallEvent) {
	e.enrichBase(&event.SecurityEvent)
}

// EnrichExecve enriches an execve event with metadata
func (e *Enricher) EnrichExecve(event *ExecveEvent) {
	e.enrichBase(&event.SecurityEvent)
}

// EnrichFile enriches a file event with metadata
func (e *Enricher) EnrichFile(event *FileEvent) {
	e.enrichBase(&event.SecurityEvent)
}

// EnrichEscape enriches an escape event with metadata
func (e *Enricher) EnrichEscape(event *EscapeEvent) {
	e.enrichBase(&event.SecurityEvent)
}

func (e *Enricher) enrichBase(event *SecurityEvent) {
	// Try to get container info from cache
	e.cacheMu.RLock()
	info, exists := e.containerCache[event.PID]
	e.cacheMu.RUnlock()

	if !exists {
		// Lookup container info
		info = e.lookupContainerInfo(event.PID)
		if info != nil {
			e.cacheMu.Lock()
			e.containerCache[event.PID] = info
			e.cacheMu.Unlock()
		}
	}

	if info != nil {
		event.ContainerID = info.ContainerID
		event.ContainerName = info.ContainerName
		event.PodName = info.PodName
		event.PodNamespace = info.PodNamespace
		event.NodeName = info.NodeName
		event.InContainer = true
	}
}

// lookupContainerInfo looks up container information for a PID
func (e *Enricher) lookupContainerInfo(pid uint32) *ContainerInfo {
	// Read cgroup to get container ID
	containerID := e.getContainerIDFromCgroup(pid)
	if containerID == "" {
		return nil
	}

	info := &ContainerInfo{
		ContainerID: containerID,
	}

	// Detect container runtime
	info.Runtime = e.detectRuntime(containerID)

	// If K8s enabled, try to get pod info
	if e.k8sEnabled {
		e.enrichK8sMetadata(info, pid)
	}

	return info
}

// getContainerIDFromCgroup extracts container ID from cgroup
func (e *Enricher) getContainerIDFromCgroup(pid uint32) string {
	// Use proper integer formatting
	cgroupPath := "/proc/" + itoa(pid) + "/cgroup"

	file, err := os.Open(cgroupPath)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Docker format: 0::/docker/<container_id>
		// Containerd format: 0::/system.slice/containerd.service/kubepods/.../<container_id>
		// CRI-O format: 0::/crio-<container_id>.scope

		if idx := strings.LastIndex(line, "/docker/"); idx != -1 {
			return line[idx+8:]
		}

		if idx := strings.LastIndex(line, "/cri-containerd-"); idx != -1 {
			end := strings.Index(line[idx+16:], ".")
			if end > 0 {
				return line[idx+16 : idx+16+end]
			}
			return line[idx+16:]
		}

		if idx := strings.Index(line, "/crio-"); idx != -1 {
			rest := line[idx+6:]
			if end := strings.Index(rest, "."); end > 0 {
				return rest[:end]
			}
		}

		// Kubernetes pod container format
		if strings.Contains(line, "kubepods") {
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				last := parts[len(parts)-1]
				// Remove scope suffix if present
				if idx := strings.Index(last, ".scope"); idx > 0 {
					last = last[:idx]
				}
				// Remove crio- or containerd- prefix
				last = strings.TrimPrefix(last, "crio-")
				last = strings.TrimPrefix(last, "cri-containerd-")
				if len(last) >= 12 {
					return last
				}
			}
		}
	}

	return ""
}

// detectRuntime detects the container runtime from the container ID format
func (e *Enricher) detectRuntime(containerID string) string {
	// Check for runtime-specific files
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return "docker"
	}
	if _, err := os.Stat("/var/run/containerd/containerd.sock"); err == nil {
		return "containerd"
	}
	if _, err := os.Stat("/var/run/crio/crio.sock"); err == nil {
		return "cri-o"
	}
	return "unknown"
}

// enrichK8sMetadata enriches container info with Kubernetes metadata
func (e *Enricher) enrichK8sMetadata(info *ContainerInfo, pid uint32) {
	// Read environment variables to get pod info
	environPath := "/proc/" + itoa(pid) + "/environ"

	data, err := os.ReadFile(environPath)
	if err != nil {
		return
	}

	// Parse null-separated environment variables
	envVars := strings.Split(string(data), "\x00")
	for _, env := range envVars {
		if strings.HasPrefix(env, "KUBERNETES_POD_NAME=") {
			info.PodName = strings.TrimPrefix(env, "KUBERNETES_POD_NAME=")
		}
		if strings.HasPrefix(env, "KUBERNETES_POD_NAMESPACE=") {
			info.PodNamespace = strings.TrimPrefix(env, "KUBERNETES_POD_NAMESPACE=")
		}
		if strings.HasPrefix(env, "KUBERNETES_NODE_NAME=") {
			info.NodeName = strings.TrimPrefix(env, "KUBERNETES_NODE_NAME=")
		}
		// Downward API environment variables
		if strings.HasPrefix(env, "MY_POD_NAME=") {
			info.PodName = strings.TrimPrefix(env, "MY_POD_NAME=")
		}
		if strings.HasPrefix(env, "MY_POD_NAMESPACE=") {
			info.PodNamespace = strings.TrimPrefix(env, "MY_POD_NAMESPACE=")
		}
		if strings.HasPrefix(env, "MY_NODE_NAME=") {
			info.NodeName = strings.TrimPrefix(env, "MY_NODE_NAME=")
		}
	}

	// If still no pod name, try to get from hostname
	if info.PodName == "" {
		hostname, _ := os.ReadFile("/proc/" + itoa(pid) + "/hostname")
		info.PodName = strings.TrimSpace(string(hostname))
	}
}

// ClearCache clears the container info cache
func (e *Enricher) ClearCache() {
	e.cacheMu.Lock()
	e.containerCache = make(map[uint32]*ContainerInfo)
	e.cacheMu.Unlock()
}

// RemoveFromCache removes a PID from the cache (e.g., on process exit)
func (e *Enricher) RemoveFromCache(pid uint32) {
	e.cacheMu.Lock()
	delete(e.containerCache, pid)
	e.cacheMu.Unlock()
}

// itoa converts uint32 to string without importing strconv
func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}

	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
