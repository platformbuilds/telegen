// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package filetailer

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/platformbuilds/telegen/internal/config"
	"github.com/platformbuilds/telegen/internal/kube/kubecache/informer"
	ikube "github.com/platformbuilds/telegen/internal/kubei"
)

// K8sLogStore is the subset of kube.Store that the discoverer needs.
// Using an interface avoids a hard dependency on the full Store implementation
// and makes testing straightforward.
type K8sLogStore interface {
	// Subscribe registers an observer that receives pod lifecycle events.
	Subscribe(observer K8sLogObserver)
}

// K8sLogObserver is the callback interface the kube.Store calls on each event.
// It is a subset of meta.Observer — we only need On and ID.
type K8sLogObserver interface {
	ID() string
	On(event *informer.Event) error
}

// K8sLogDiscoverer watches a kube.Store for pods matching the configured
// criteria and dynamically resolves their log file paths on the node.
//
// It implements the K8sLogObserver interface so it can be passed to
// kube.Store.Subscribe(). Internally it keeps a live set of glob patterns
// (e.g. /var/log/pods/prod_payment-abc_uid123/app/*.log) that the Tailer
// merges with its static Include globs on every poll tick.
type K8sLogDiscoverer struct {
	cfg      *config.K8sLogDiscovery
	basePath string // default: /var/log/pods
	logger   *slog.Logger

	mu       sync.RWMutex
	logPaths map[string]struct{} // set of discovered log glob patterns
}

// NewK8sLogDiscoverer creates a discoverer and subscribes it to the store.
// The store delivers a "welcome message" of all existing pods on Subscribe,
// so the discovered set is immediately populated.
func NewK8sLogDiscoverer(store K8sLogStore, cfg *config.K8sLogDiscovery, logger *slog.Logger) *K8sLogDiscoverer {
	base := cfg.LogPath
	if base == "" {
		base = "/var/log/pods"
	}
	if logger == nil {
		logger = slog.Default()
	}

	d := &K8sLogDiscoverer{
		cfg:      cfg,
		basePath: base,
		logger:   logger.With("component", "k8s_log_discovery"),
		logPaths: make(map[string]struct{}),
	}

	// Subscribe to pod events from the store. The store sends existing pods
	// as EventType_CREATED on subscribe (same pattern as watcherKubeEnricher).
	store.Subscribe(d)

	return d
}

// ID satisfies the meta.Observer / K8sLogObserver interface.
func (d *K8sLogDiscoverer) ID() string { return "k8s-log-discoverer" }

// On is called by kube.Store when pods are created/updated/deleted.
// Same pattern as discover.watcherKubeEnricher.On in discover/watcher_kube.go.
func (d *K8sLogDiscoverer) On(event *informer.Event) error {
	if event.Resource == nil || event.Resource.Pod == nil {
		return nil
	}
	om := event.Resource
	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		if d.matchesCriteria(om) {
			d.addPodLogPaths(om)
		} else {
			d.removePodLogPaths(om)
		}
	case informer.EventType_DELETED:
		d.removePodLogPaths(om)
	}
	return nil
}

// DiscoveredPaths returns the currently discovered log file glob patterns.
// Called by the Tailer on each poll cycle.
func (d *K8sLogDiscoverer) DiscoveredPaths() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	paths := make([]string, 0, len(d.logPaths))
	for p := range d.logPaths {
		paths = append(paths, p)
	}
	return paths
}

// matchesCriteria checks if a pod matches the configured K8s discovery criteria.
// Empty criteria sections are treated as "match all" for that axis.
// When multiple axes are specified, ALL must match (AND logic across sections).
func (d *K8sLogDiscoverer) matchesCriteria(om *informer.ObjectMeta) bool {
	// 1. Namespace inclusion
	if len(d.cfg.Namespaces) > 0 {
		if !matchesAnyGlob(om.Namespace, d.cfg.Namespaces) {
			return false
		}
	}

	// 2. Namespace exclusion (always applied)
	if matchesAnyGlob(om.Namespace, d.cfg.ExcludeNamespaces) {
		return false
	}

	// 3. Owner-based matching (deployments / daemonsets / statefulsets)
	hasOwnerCriteria := len(d.cfg.Deployments) > 0 ||
		len(d.cfg.DaemonSets) > 0 ||
		len(d.cfg.StatefulSets) > 0
	if hasOwnerCriteria {
		owner := ikube.TopOwner(om.Pod)
		matched := false
		if owner != nil {
			switch owner.Kind {
			case "Deployment", "ReplicaSet":
				// ReplicaSet is included because TopOwner may return the
				// immediate owner when the chain is only one level deep.
				matched = matchesAnyGlob(owner.Name, d.cfg.Deployments)
			case "DaemonSet":
				matched = matchesAnyGlob(owner.Name, d.cfg.DaemonSets)
			case "StatefulSet":
				matched = matchesAnyGlob(owner.Name, d.cfg.StatefulSets)
			}
		}
		if !matched {
			return false
		}
	}

	// 4. app.kubernetes.io/name label
	if len(d.cfg.AppNames) > 0 {
		appLabel := om.Labels["app.kubernetes.io/name"]
		if !matchesAnyGlob(appLabel, d.cfg.AppNames) {
			return false
		}
	}

	// 5. Pod labels (AND logic — every entry must match)
	for key, pattern := range d.cfg.PodLabels {
		val, ok := om.Labels[key]
		if !ok || !globMatch(pattern, val) {
			return false
		}
	}

	// 6. Pod annotations (AND logic)
	for key, pattern := range d.cfg.PodAnnotations {
		val, ok := om.Annotations[key]
		if !ok || !globMatch(pattern, val) {
			return false
		}
	}

	return true
}

// addPodLogPaths constructs /var/log/pods/{ns}_{pod}_{uid}/{container}/*.log
// glob patterns for all (or filtered) containers of the matched pod.
func (d *K8sLogDiscoverer) addPodLogPaths(om *informer.ObjectMeta) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, c := range om.Pod.Containers {
		if len(d.cfg.ContainerNames) > 0 && !matchesAnyGlob(c.Name, d.cfg.ContainerNames) {
			continue
		}
		// Construct: /var/log/pods/{namespace}_{podname}_{uid}/{container}/*.log
		pattern := fmt.Sprintf("%s/%s_%s_%s/%s/*.log",
			d.basePath, om.Namespace, om.Name, om.Pod.Uid, c.Name)
		if _, exists := d.logPaths[pattern]; !exists {
			d.logPaths[pattern] = struct{}{}
			d.logger.Debug("discovered pod log path",
				"namespace", om.Namespace,
				"pod", om.Name,
				"container", c.Name,
				"pattern", pattern)
		}
	}
}

// removePodLogPaths removes all log paths associated with a pod.
func (d *K8sLogDiscoverer) removePodLogPaths(om *informer.ObjectMeta) {
	d.mu.Lock()
	defer d.mu.Unlock()

	prefix := fmt.Sprintf("%s/%s_%s_%s/",
		d.basePath, om.Namespace, om.Name, om.Pod.Uid)

	for p := range d.logPaths {
		if len(p) >= len(prefix) && p[:len(prefix)] == prefix {
			delete(d.logPaths, p)
			d.logger.Debug("removed pod log path", "pattern", p)
		}
	}
}

// matchesAnyGlob returns true if value matches any of the glob patterns.
// An empty patterns slice returns false (no patterns = no match).
func matchesAnyGlob(value string, patterns []string) bool {
	for _, p := range patterns {
		if globMatch(p, value) {
			return true
		}
	}
	return false
}

// globMatch uses filepath.Match for glob pattern matching.
// It treats match errors (bad pattern) as non-matching.
func globMatch(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		return false
	}
	return matched
}
