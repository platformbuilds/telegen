// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/mirastacklabs-ai/telegen/internal/helpers/container"
	"github.com/mirastacklabs-ai/telegen/internal/kube"
)

// ProcessFilter determines which processes should be profiled based on configuration
type ProcessFilter struct {
	config RunnerConfig
	log    *slog.Logger

	// Kubernetes store for pod/namespace metadata
	kubeStore *kube.Store

	// Caches for process metadata
	mu            sync.RWMutex
	processInfo   map[uint32]*ProcessMetadata
	containerInfo map[string]*ContainerMetadata
}

// ProcessMetadata holds metadata about a process
type ProcessMetadata struct {
	PID         uint32
	Name        string // Process name (e.g., "java")
	Executable  string // Full path (e.g., "/usr/bin/java")
	ContainerID string
	Namespace   string // K8s namespace
	PodName     string
	OwnerKind   string // Deployment, DaemonSet, StatefulSet, etc.
	OwnerName   string
	Labels      map[string]string
}

// ContainerMetadata holds Kubernetes metadata for a container
type ContainerMetadata struct {
	ContainerID string
	Namespace   string
	PodName     string
	OwnerKind   string
	OwnerName   string
	Labels      map[string]string
}

// NewProcessFilter creates a new process filter
func NewProcessFilter(config RunnerConfig, log *slog.Logger, kubeStore *kube.Store) *ProcessFilter {
	return &ProcessFilter{
		config:        config,
		log:           log,
		kubeStore:     kubeStore,
		processInfo:   make(map[uint32]*ProcessMetadata),
		containerInfo: make(map[string]*ContainerMetadata),
	}
}

// ShouldProfile returns true if the given PID should be profiled
func (pf *ProcessFilter) ShouldProfile(pid uint32) bool {
	// If no filters are configured, profile all processes
	if !pf.hasFilters() {
		return true
	}

	// Check PID-based filters first (fastest)
	if pf.config.TargetPID != 0 && pid == pf.config.TargetPID {
		pf.log.Debug("process matched target PID", "pid", pid)
		return true
	}
	for _, targetPID := range pf.config.TargetPIDs {
		if pid == targetPID {
			pf.log.Debug("process matched target PIDs list", "pid", pid)
			return true
		}
	}

	// Get or fetch process metadata
	meta := pf.getProcessMetadata(pid)
	if meta == nil {
		pf.log.Debug("could not fetch process metadata", "pid", pid)
		return false
	}

	// Check exclude filters first
	if pf.isExcluded(meta) {
		pf.log.Debug("process excluded by filter",
			"pid", pid,
			"name", meta.Name,
			"namespace", meta.Namespace)
		return false
	}

	// Check include filters
	included := pf.isIncluded(meta)
	if included {
		pf.log.Debug("process included by filter",
			"pid", pid,
			"name", meta.Name,
			"namespace", meta.Namespace,
			"owner", meta.OwnerName)
	} else {
		pf.log.Debug("process did not match include filters",
			"pid", pid,
			"name", meta.Name,
			"namespace", meta.Namespace)
	}
	return included
}

// hasFilters returns true if any filters are configured
func (pf *ProcessFilter) hasFilters() bool {
	return pf.config.TargetPID != 0 ||
		len(pf.config.TargetPIDs) > 0 ||
		len(pf.config.TargetContainerIDs) > 0 ||
		len(pf.config.TargetProcessNames) > 0 ||
		len(pf.config.TargetExecutables) > 0 ||
		len(pf.config.TargetNamespaces) > 0 ||
		len(pf.config.TargetDeployments) > 0 ||
		len(pf.config.TargetDaemonSets) > 0 ||
		len(pf.config.TargetStatefulSets) > 0 ||
		len(pf.config.TargetLabels) > 0
}

// isExcluded checks if the process should be excluded
func (pf *ProcessFilter) isExcluded(meta *ProcessMetadata) bool {
	// Check namespace exclusions (supports wildcards with *)
	for _, pattern := range pf.config.ExcludeNamespaces {
		if pf.matchPattern(meta.Namespace, pattern) {
			return true
		}
	}
	return false
}

// matchPattern matches a string against a pattern with wildcard support.
// Supports * as a wildcard character:
//   - "java"          → exact match only
//   - "java*"         → prefix match (e.g. "javac", "java-app")
//   - "*java"         → suffix match (e.g. "openjava")
//   - "*java*"        → substring/contains match (e.g. "my-java-app")
//   - "kube-*-lease"  → prefix + suffix match
func (pf *ProcessFilter) matchPattern(s, pattern string) bool {
	// Exact match
	if s == pattern {
		return true
	}

	// No wildcard → exact match only (already checked above)
	if !strings.Contains(pattern, "*") {
		return false
	}

	// Single "*" matches everything
	if pattern == "*" {
		return true
	}

	// *text* → contains (must check before prefix/suffix-only cases)
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		middle := pattern[1 : len(pattern)-1]
		return strings.Contains(s, middle)
	}

	// prefix* → starts with
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(s, prefix)
	}

	// *suffix → ends with
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(s, suffix)
	}

	// prefix*suffix → starts with prefix AND ends with suffix (e.g. "kube-*-lease")
	parts := strings.SplitN(pattern, "*", 2)
	if len(parts) == 2 {
		return strings.HasPrefix(s, parts[0]) && strings.HasSuffix(s, parts[1]) &&
			len(s) >= len(parts[0])+len(parts[1])
	}

	return false
}

// isIncluded checks if the process matches all configured include filters (AND logic)
// When multiple filter types are configured, ALL must match
func (pf *ProcessFilter) isIncluded(meta *ProcessMetadata) bool {
	// Track which filter types are configured and whether they matched
	numFilterTypes := 0
	numMatched := 0

	// Container ID filter
	if len(pf.config.TargetContainerIDs) > 0 {
		numFilterTypes++
		for _, cid := range pf.config.TargetContainerIDs {
			if meta.ContainerID == cid {
				numMatched++
				break
			}
		}
	}

	// Process name filter — supports wildcards: "java", "*java*", "java*", "*java"
	if len(pf.config.TargetProcessNames) > 0 {
		numFilterTypes++
		for _, name := range pf.config.TargetProcessNames {
			if pf.matchPattern(meta.Name, name) {
				numMatched++
				break
			}
		}
	}

	// Executable path filter — supports wildcards: "/usr/bin/java", "*java*", "*/bin/python*"
	if len(pf.config.TargetExecutables) > 0 {
		numFilterTypes++
		for _, exe := range pf.config.TargetExecutables {
			if pf.matchPattern(meta.Executable, exe) {
				numMatched++
				break
			}
		}
	}

	// Kubernetes namespace filter
	if len(pf.config.TargetNamespaces) > 0 {
		numFilterTypes++
		for _, ns := range pf.config.TargetNamespaces {
			if meta.Namespace == ns {
				numMatched++
				break
			}
		}
	}

	// Kubernetes deployment filter
	if len(pf.config.TargetDeployments) > 0 {
		numFilterTypes++
		if meta.OwnerKind == "Deployment" {
			for _, deployment := range pf.config.TargetDeployments {
				if meta.OwnerName == deployment {
					numMatched++
					break
				}
			}
		}
	}

	// Kubernetes daemonset filter
	if len(pf.config.TargetDaemonSets) > 0 {
		numFilterTypes++
		if meta.OwnerKind == "DaemonSet" {
			for _, daemonset := range pf.config.TargetDaemonSets {
				if meta.OwnerName == daemonset {
					numMatched++
					break
				}
			}
		}
	}

	// Kubernetes statefulset filter
	if len(pf.config.TargetStatefulSets) > 0 {
		numFilterTypes++
		if meta.OwnerKind == "StatefulSet" {
			for _, statefulset := range pf.config.TargetStatefulSets {
				if meta.OwnerName == statefulset {
					numMatched++
					break
				}
			}
		}
	}

	// Kubernetes label filter (all labels must match)
	if len(pf.config.TargetLabels) > 0 {
		numFilterTypes++
		if pf.labelsMatch(meta.Labels, pf.config.TargetLabels) {
			numMatched++
		}
	}

	// All configured filter types must match (AND logic)
	// Example: if both process_names and namespaces are configured,
	// a process must match both to be profiled
	result := numFilterTypes > 0 && numMatched == numFilterTypes

	if !result && numFilterTypes > 0 {
		pf.log.Debug("process failed AND filter logic",
			"pid", meta.PID,
			"name", meta.Name,
			"namespace", meta.Namespace,
			"filter_types_configured", numFilterTypes,
			"filter_types_matched", numMatched)
	}

	return result
}

// labelsMatch checks if all target labels match the process labels
func (pf *ProcessFilter) labelsMatch(processLabels, targetLabels map[string]string) bool {
	if len(targetLabels) == 0 {
		return false
	}
	for key, value := range targetLabels {
		if processLabels[key] != value {
			return false
		}
	}
	return true
}

// getProcessMetadata fetches or returns cached metadata for a process
func (pf *ProcessFilter) getProcessMetadata(pid uint32) *ProcessMetadata {
	pf.mu.RLock()
	if meta, ok := pf.processInfo[pid]; ok {
		pf.mu.RUnlock()
		return meta
	}
	pf.mu.RUnlock()

	// Fetch metadata
	meta := pf.fetchProcessMetadata(pid)
	if meta != nil {
		pf.mu.Lock()
		pf.processInfo[pid] = meta
		pf.mu.Unlock()
	}

	return meta
}

// fetchProcessMetadata reads process information from /proc
func (pf *ProcessFilter) fetchProcessMetadata(pid uint32) *ProcessMetadata {
	meta := &ProcessMetadata{
		PID:    pid,
		Labels: make(map[string]string),
	}

	// Read process name from /proc/[pid]/comm
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	if data, err := os.ReadFile(commPath); err == nil {
		meta.Name = strings.TrimSpace(string(data))
	}

	// Read executable path from /proc/[pid]/exe
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	if exe, err := os.Readlink(exePath); err == nil {
		meta.Executable = exe
	}

	// Try to get container information
	if info, err := container.InfoForPID(pid); err == nil {
		meta.ContainerID = info.ContainerID
		pf.log.Debug("found container for process",
			"pid", pid,
			"containerID", info.ContainerID,
			"pidNamespace", info.PIDNamespace)

		// Store meta early so resolveK8sMetadataFromProc can find it by PID
		pf.mu.Lock()
		pf.processInfo[pid] = meta
		pf.mu.Unlock()

		// Try to get Kubernetes metadata from container
		if containerMeta := pf.getContainerMetadata(info.ContainerID); containerMeta != nil {
			meta.Namespace = containerMeta.Namespace
			meta.PodName = containerMeta.PodName
			meta.OwnerKind = containerMeta.OwnerKind
			meta.OwnerName = containerMeta.OwnerName
			meta.Labels = containerMeta.Labels
		}
	} else {
		pf.log.Debug("no container info for process (may be host process)",
			"pid", pid,
			"error", err)
	}

	// If no container info, try to read from environment variables
	// (some systems expose K8s metadata via env vars)
	if meta.Namespace == "" {
		meta.Namespace = pf.readEnvVar(pid, "POD_NAMESPACE")
		meta.PodName = pf.readEnvVar(pid, "POD_NAME")
	}

	return meta
}

// getContainerMetadata fetches Kubernetes metadata for a container
// Uses kube.Store (Kubernetes API) if available, otherwise falls back to filesystem reads
func (pf *ProcessFilter) getContainerMetadata(containerID string) *ContainerMetadata {
	if containerID == "" {
		return nil
	}

	pf.mu.RLock()
	if meta, ok := pf.containerInfo[containerID]; ok {
		pf.mu.RUnlock()
		return meta
	}
	pf.mu.RUnlock()

	// Method 1 (PREFERRED): Use kube.Store if available - same as eBPF discovery
	// This is the reliable method that works with hostPID=true
	if pf.kubeStore != nil {
		cached := pf.kubeStore.PodByContainerID(containerID)
		if cached == nil || cached.Meta == nil {
			pf.log.Debug("kubeStore.PodByContainerID returned nil - pod not yet indexed or container ID mismatch",
				"containerID", containerID)
		}
		if cached != nil && cached.Meta != nil {
			pod := cached.Meta
			meta := &ContainerMetadata{
				ContainerID: containerID,
				Namespace:   pod.Namespace,
				PodName:     pod.Name,
				Labels:      make(map[string]string),
			}
			// Extract owner info
			if pod.Pod != nil && len(pod.Pod.Owners) > 0 {
				// Get the top-level owner (e.g., Deployment)
				for i := len(pod.Pod.Owners) - 1; i >= 0; i-- {
					owner := pod.Pod.Owners[i]
					meta.OwnerKind = owner.Kind
					meta.OwnerName = owner.Name
					if owner.Kind == "Deployment" || owner.Kind == "StatefulSet" || owner.Kind == "DaemonSet" {
						break // Found a workload controller
					}
				}
			}
			if pod.Labels != nil {
				meta.Labels = pod.Labels
			}
			pf.mu.Lock()
			pf.containerInfo[containerID] = meta
			pf.mu.Unlock()
			pf.log.Debug("resolved namespace from kube.Store",
				"container", containerID,
				"namespace", meta.Namespace,
				"pod", meta.PodName,
				"owner", meta.OwnerName)
			return meta
		}
	}

	// Method 2 (FALLBACK): Try to extract namespace from filesystem
	// This may not work with hostPID=true but kept for non-k8s environments
	meta := pf.resolveK8sMetadataFromProc(containerID)
	if meta != nil {
		pf.mu.Lock()
		pf.containerInfo[containerID] = meta
		pf.mu.Unlock()
	}

	return meta
}

// resolveK8sMetadataFromProc tries to resolve Kubernetes metadata by:
// 1. Reading /proc/<pid>/cgroup to find pod UID
// 2. Looking for pod metadata in standard K8s paths
func (pf *ProcessFilter) resolveK8sMetadataFromProc(containerID string) *ContainerMetadata {
	// Try to find which PID has this container ID and read its cgroup
	// Walk through known PIDs to find the one with matching container ID
	pf.mu.RLock()
	var matchingPID uint32
	for pid, meta := range pf.processInfo {
		if meta.ContainerID == containerID {
			matchingPID = pid
			break
		}
	}
	pf.mu.RUnlock()

	if matchingPID == 0 {
		return nil
	}

	// Read cgroup to extract pod UID
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", matchingPID)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return nil
	}

	cgroupStr := string(data)

	// Extract namespace from cgroup path
	// Format: /kubepods/burstable/pod<uid>/... or /kubepods.slice/.../kubepods-...-pod<uid>.slice/...
	namespace := pf.extractNamespaceFromCgroup(matchingPID, cgroupStr)

	if namespace != "" {
		return &ContainerMetadata{
			ContainerID: containerID,
			Namespace:   namespace,
			Labels:      make(map[string]string),
		}
	}

	return nil
}

// extractNamespaceFromCgroup tries to determine the K8s namespace for a process.
// Since the namespace is not directly in the cgroup path, we use the Kubernetes
// downward API: read /proc/<pid>/root/var/run/secrets/kubernetes.io/serviceaccount/namespace
// which K8s mounts into every pod.
func (pf *ProcessFilter) extractNamespaceFromCgroup(pid uint32, _ string) string {
	// Method 1: Read the namespace from the mounted K8s service account
	// Every pod gets this file mounted by kubelet
	nsPath := fmt.Sprintf("/proc/%d/root/var/run/secrets/kubernetes.io/serviceaccount/namespace", pid)
	if data, err := os.ReadFile(nsPath); err == nil {
		ns := strings.TrimSpace(string(data))
		if ns != "" {
			return ns
		}
	}

	// Method 2: Read from host-level proc (when running with hostPID)
	nsPathAlt := fmt.Sprintf("/host/proc/%d/root/var/run/secrets/kubernetes.io/serviceaccount/namespace", pid)
	if data, err := os.ReadFile(nsPathAlt); err == nil {
		ns := strings.TrimSpace(string(data))
		if ns != "" {
			return ns
		}
	}

	// Method 3: Fallback to reading POD_NAMESPACE env var
	return pf.readEnvVar(pid, "POD_NAMESPACE")
}

// readEnvVar reads an environment variable from a process
func (pf *ProcessFilter) readEnvVar(pid uint32, key string) string {
	envPath := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := os.ReadFile(envPath)
	if err != nil {
		return ""
	}

	// Environment variables are null-terminated
	vars := strings.Split(string(data), "\x00")
	prefix := key + "="
	for _, v := range vars {
		if strings.HasPrefix(v, prefix) {
			return strings.TrimPrefix(v, prefix)
		}
	}
	return ""
}

// ClearCache clears the metadata cache for a process
func (pf *ProcessFilter) ClearCache(pid uint32) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	delete(pf.processInfo, pid)
}

// ClearAllCaches clears all metadata caches
func (pf *ProcessFilter) ClearAllCaches() {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.processInfo = make(map[uint32]*ProcessMetadata)
	pf.containerInfo = make(map[string]*ContainerMetadata)
}

// GetFilteredProcesses scans /proc and returns PIDs that match the filter
func (pf *ProcessFilter) GetFilteredProcesses() ([]uint32, error) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc: %w", err)
	}
	defer func() {
		if closeErr := procDir.Close(); closeErr != nil {
			pf.log.Warn("failed to close /proc directory", "error", closeErr)
		}
	}()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	var pids []uint32
	var matchedProcesses []string // Track process details for logging

	for _, entry := range entries {
		// Check if this is a PID directory
		var pid uint32
		if _, err := fmt.Sscanf(entry, "%d", &pid); err != nil {
			continue
		}

		// Apply filter
		if pf.ShouldProfile(pid) {
			pids = append(pids, pid)

			// Get process metadata for logging
			meta := pf.getProcessMetadata(pid)
			if meta != nil {
				processDesc := fmt.Sprintf("%s[%d]", meta.Name, pid)
				if meta.Namespace != "" {
					processDesc += fmt.Sprintf(" (ns:%s", meta.Namespace)
					if meta.OwnerName != "" {
						processDesc += fmt.Sprintf("/%s", meta.OwnerName)
					}
					processDesc += ")"
				}
				matchedProcesses = append(matchedProcesses, processDesc)
			}
		}
	}

	pf.log.Info("filtered processes for profiling",
		"total_scanned", len(entries),
		"matched", len(pids),
		"has_filters", pf.hasFilters())

	// Log detailed list of matched processes
	if len(matchedProcesses) > 0 {
		pf.log.Info("profiling started for processes",
			"count", len(matchedProcesses),
			"processes", strings.Join(matchedProcesses, ", "))
	} else if pf.hasFilters() {
		pf.log.Warn("no processes matched the configured filters - nothing will be profiled")
	}

	return pids, nil
}

// GetFilterSummary returns a human-readable summary of active filters
func (pf *ProcessFilter) GetFilterSummary() string {
	if !pf.hasFilters() {
		return "No filters configured - profiling all processes"
	}

	var parts []string
	numFilterTypes := 0

	if pf.config.TargetPID != 0 {
		parts = append(parts, fmt.Sprintf("PID=%d", pf.config.TargetPID))
		numFilterTypes++
	}
	if len(pf.config.TargetPIDs) > 0 {
		parts = append(parts, fmt.Sprintf("PIDs=%v", pf.config.TargetPIDs))
		numFilterTypes++
	}
	if len(pf.config.TargetProcessNames) > 0 {
		parts = append(parts, fmt.Sprintf("ProcessNames=%v", pf.config.TargetProcessNames))
		numFilterTypes++
	}
	if len(pf.config.TargetExecutables) > 0 {
		parts = append(parts, fmt.Sprintf("Executables=%v", pf.config.TargetExecutables))
		numFilterTypes++
	}
	if len(pf.config.TargetNamespaces) > 0 {
		parts = append(parts, fmt.Sprintf("Namespaces=%v", pf.config.TargetNamespaces))
		numFilterTypes++
	}
	if len(pf.config.TargetDeployments) > 0 {
		parts = append(parts, fmt.Sprintf("Deployments=%v", pf.config.TargetDeployments))
		numFilterTypes++
	}
	if len(pf.config.TargetDaemonSets) > 0 {
		parts = append(parts, fmt.Sprintf("DaemonSets=%v", pf.config.TargetDaemonSets))
		numFilterTypes++
	}
	if len(pf.config.TargetStatefulSets) > 0 {
		parts = append(parts, fmt.Sprintf("StatefulSets=%v", pf.config.TargetStatefulSets))
		numFilterTypes++
	}
	if len(pf.config.TargetLabels) > 0 {
		parts = append(parts, fmt.Sprintf("Labels=%v", pf.config.TargetLabels))
		numFilterTypes++
	}
	if len(pf.config.ExcludeNamespaces) > 0 {
		parts = append(parts, fmt.Sprintf("ExcludeNamespaces=%v", pf.config.ExcludeNamespaces))
	}

	logic := ""
	if numFilterTypes > 1 {
		logic = " (AND logic - all must match)"
	}

	return "Active filters" + logic + ": " + strings.Join(parts, ", ")
}
