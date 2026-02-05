package parsers

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// K8sPathEnricher extracts Kubernetes metadata from container log file paths
// Supports paths like:
//   - /var/log/pods/{namespace}_{pod}_{uid}/{container}/{restart}.log
//   - /var/log/containers/{pod}_{namespace}_{container}-{container_id}.log
type K8sPathEnricher struct {
	// /var/log/pods/{namespace}_{pod}_{uid}/{container}/{restart}.log
	podsPathRegex *regexp.Regexp

	// /var/log/containers/{pod}_{namespace}_{container}-{container_id}.log
	containersPathRegex *regexp.Regexp
}

// NewK8sPathEnricher creates a new K8s path enricher
func NewK8sPathEnricher() *K8sPathEnricher {
	return &K8sPathEnricher{
		// Matches: /var/log/pods/namespace_podname_uid/containername/0.log
		podsPathRegex: regexp.MustCompile(
			`^.*/var/log/pods/([^_]+)_([^_]+)_([a-f0-9-]+)/([^/]+)/(\d+)\.log$`,
		),
		// Matches: /var/log/containers/podname_namespace_containername-containerid.log
		containersPathRegex: regexp.MustCompile(
			`^.*/var/log/containers/([^_]+)_([^_]+)_([^-]+)-([a-f0-9]+)\.log$`,
		),
	}
}

// Name returns the enricher name
func (e *K8sPathEnricher) Name() string {
	return "k8s_path"
}

// Enrich adds Kubernetes metadata extracted from the file path
func (e *K8sPathEnricher) Enrich(log *ParsedLog, filePath string) {
	if filePath == "" {
		return
	}

	// Store the file path
	log.FilePath = filePath

	// Try /var/log/pods format first (most common in modern K8s)
	if matches := e.podsPathRegex.FindStringSubmatch(filePath); matches != nil {
		log.ResourceAttributes["k8s.namespace.name"] = matches[1]
		log.ResourceAttributes["k8s.pod.name"] = matches[2]
		log.ResourceAttributes["k8s.pod.uid"] = matches[3]
		log.ResourceAttributes["k8s.container.name"] = matches[4]
		log.ResourceAttributes["k8s.container.restart_count"] = matches[5]

		// Try to resolve container ID for trace correlation
		// This looks up the symlink in /var/log/containers/
		info := &K8sLogPathInfo{
			Namespace:     matches[1],
			PodName:       matches[2],
			PodUID:        matches[3],
			ContainerName: matches[4],
			RestartCount:  matches[5],
			IsPodsPath:    true,
		}
		if containerID := ResolveContainerID(info); containerID != "" {
			log.ResourceAttributes["k8s.container.id"] = containerID
		}
		return
	}

	// Try /var/log/containers format (symlinks, older format)
	if matches := e.containersPathRegex.FindStringSubmatch(filePath); matches != nil {
		log.ResourceAttributes["k8s.pod.name"] = matches[1]
		log.ResourceAttributes["k8s.namespace.name"] = matches[2]
		log.ResourceAttributes["k8s.container.name"] = matches[3]
		// Store container ID for trace correlation (used by TraceContextEnricher)
		log.ResourceAttributes["k8s.container.id"] = matches[4]
		return
	}

	// Not a K8s log path - just store the file path
}

// IsK8sLogPath checks if a path looks like a Kubernetes container log path
func IsK8sLogPath(path string) bool {
	return strings.Contains(path, "/var/log/pods/") ||
		strings.Contains(path, "/var/log/containers/")
}

// ExtractK8sMetadataFromPath extracts K8s metadata from a file path
// Returns a map of attribute key to value
func ExtractK8sMetadataFromPath(filePath string) map[string]string {
	enricher := NewK8sPathEnricher()
	log := NewParsedLog()
	enricher.Enrich(log, filePath)
	return log.ResourceAttributes
}

// K8sLogPathInfo contains parsed Kubernetes log path information
type K8sLogPathInfo struct {
	Namespace     string
	PodName       string
	PodUID        string
	ContainerName string
	ContainerID   string
	RestartCount  string
	IsPodsPath    bool // true if /var/log/pods, false if /var/log/containers
}

// ParseK8sLogPath parses a K8s log path and returns structured info
func ParseK8sLogPath(filePath string) *K8sLogPathInfo {
	enricher := NewK8sPathEnricher()

	// Try /var/log/pods format
	if matches := enricher.podsPathRegex.FindStringSubmatch(filePath); matches != nil {
		return &K8sLogPathInfo{
			Namespace:     matches[1],
			PodName:       matches[2],
			PodUID:        matches[3],
			ContainerName: matches[4],
			RestartCount:  matches[5],
			IsPodsPath:    true,
		}
	}

	// Try /var/log/containers format
	if matches := enricher.containersPathRegex.FindStringSubmatch(filePath); matches != nil {
		return &K8sLogPathInfo{
			PodName:       matches[1],
			Namespace:     matches[2],
			ContainerName: matches[3],
			ContainerID:   matches[4],
			IsPodsPath:    false,
		}
	}

	return nil
}

// containerIDCache caches container ID lookups to avoid repeated filesystem access
var containerIDCache = make(map[string]string)
var containerIDCacheMu sync.RWMutex

// ResolveContainerID attempts to resolve the container ID for a /var/log/pods/ path
// by finding the matching symlink in /var/log/containers/
func ResolveContainerID(info *K8sLogPathInfo) string {
	if info == nil {
		return ""
	}

	// If we already have container ID (from /var/log/containers/ format), return it
	if info.ContainerID != "" {
		return info.ContainerID
	}

	// For /var/log/pods/ format, try to find matching container ID
	// Construct cache key from pod/namespace/container
	cacheKey := info.Namespace + "/" + info.PodName + "/" + info.ContainerName

	// Check cache first
	containerIDCacheMu.RLock()
	if id, ok := containerIDCache[cacheKey]; ok {
		containerIDCacheMu.RUnlock()
		return id
	}
	containerIDCacheMu.RUnlock()

	// Try to find container ID from /var/log/containers/ symlinks
	// Pattern: /var/log/containers/{pod}_{namespace}_{container}-{containerID}.log
	pattern := fmt.Sprintf("/var/log/containers/%s_%s_%s-*.log",
		info.PodName, info.Namespace, info.ContainerName)

	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}

	// Parse container ID from the matched path
	containerIDRegex := regexp.MustCompile(`-([a-f0-9]+)\.log$`)
	for _, match := range matches {
		if submatches := containerIDRegex.FindStringSubmatch(match); submatches != nil {
			containerID := submatches[1]

			// Cache the result
			containerIDCacheMu.Lock()
			containerIDCache[cacheKey] = containerID
			containerIDCacheMu.Unlock()

			return containerID
		}
	}

	return ""
}
