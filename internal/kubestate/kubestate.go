// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/kubestate/sharding"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeState is the main orchestrator for Kubernetes state metrics
type KubeState struct {
	config    *Config
	clientset kubernetes.Interface
	sharder   *sharding.Sharder

	stores    []*MetricsStore
	informers []cache.SharedInformer

	mu      sync.RWMutex
	started bool
	cancel  context.CancelFunc
	logger  *slog.Logger
}

// New creates a new KubeState instance
func New(cfg *Config, logger *slog.Logger) (*KubeState, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	clientset, err := createClientset(cfg.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	sharder := sharding.NewSharder(cfg.Shard, cfg.TotalShards)

	return &KubeState{
		config:    cfg,
		clientset: clientset,
		sharder:   sharder,
		stores:    make([]*MetricsStore, 0),
		informers: make([]cache.SharedInformer, 0),
		logger:    logger,
	}, nil
}

// NewWithClientset creates a new KubeState with an existing clientset
func NewWithClientset(cfg *Config, clientset kubernetes.Interface, logger *slog.Logger) (*KubeState, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	sharder := sharding.NewSharder(cfg.Shard, cfg.TotalShards)

	return &KubeState{
		config:    cfg,
		clientset: clientset,
		sharder:   sharder,
		stores:    make([]*MetricsStore, 0),
		informers: make([]cache.SharedInformer, 0),
		logger:    logger,
	}, nil
}

// createClientset creates a Kubernetes clientset
func createClientset(kubeconfig string) (kubernetes.Interface, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, err
	}

	// Set reasonable defaults
	config.QPS = 50
	config.Burst = 100

	return kubernetes.NewForConfig(config)
}

// Start begins collecting metrics from Kubernetes
func (k *KubeState) Start(ctx context.Context) error {
	k.mu.Lock()
	if k.started {
		k.mu.Unlock()
		return fmt.Errorf("kubestate already started")
	}
	k.started = true
	ctx, k.cancel = context.WithCancel(ctx)
	k.mu.Unlock()

	k.logger.Info("starting kubestate metrics collector",
		"resources", k.config.Resources,
		"namespaces", k.config.Namespaces,
		"shard", k.config.Shard,
		"totalShards", k.config.TotalShards,
	)

	// Build collectors based on enabled resources
	if err := k.buildCollectors(ctx); err != nil {
		return fmt.Errorf("failed to build collectors: %w", err)
	}

	// Start all informers
	for _, informer := range k.informers {
		go informer.Run(ctx.Done())
	}

	// Wait for caches to sync
	k.logger.Info("waiting for informer caches to sync")
	syncCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	for _, informer := range k.informers {
		if !cache.WaitForCacheSync(syncCtx.Done(), informer.HasSynced) {
			return fmt.Errorf("timed out waiting for caches to sync")
		}
	}

	k.logger.Info("kubestate metrics collector started",
		"storeCount", len(k.stores),
	)

	return nil
}

// Stop stops the metrics collector
func (k *KubeState) Stop() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.cancel != nil {
		k.cancel()
	}
	k.started = false
	k.logger.Info("kubestate metrics collector stopped")
}

// buildCollectors builds the metric collectors based on configuration
func (k *KubeState) buildCollectors(ctx context.Context) error {
	resources := k.config.GetEnabledResources()

	for _, resource := range resources {
		if err := k.buildCollector(ctx, resource); err != nil {
			k.logger.Error("failed to build collector",
				"resource", resource,
				"error", err,
			)
			// Continue with other collectors
		}
	}

	return nil
}

// buildCollector builds a collector for a specific resource type
func (k *KubeState) buildCollector(ctx context.Context, resource string) error {
	switch resource {
	case "pods":
		return k.buildPodCollector(ctx)
	case "deployments":
		return k.buildDeploymentCollector(ctx)
	case "statefulsets":
		return k.buildStatefulSetCollector(ctx)
	case "daemonsets":
		return k.buildDaemonSetCollector(ctx)
	case "replicasets":
		return k.buildReplicaSetCollector(ctx)
	case "nodes":
		return k.buildNodeCollector(ctx)
	case "namespaces":
		return k.buildNamespaceCollector(ctx)
	case "services":
		return k.buildServiceCollector(ctx)
	case "endpoints":
		return k.buildEndpointsCollector(ctx)
	case "persistentvolumeclaims":
		return k.buildPVCCollector(ctx)
	case "persistentvolumes":
		return k.buildPVCollector(ctx)
	case "configmaps":
		return k.buildConfigMapCollector(ctx)
	case "secrets":
		return k.buildSecretCollector(ctx)
	case "jobs":
		return k.buildJobCollector(ctx)
	case "cronjobs":
		return k.buildCronJobCollector(ctx)
	case "horizontalpodautoscalers":
		return k.buildHPACollector(ctx)
	case "ingresses":
		return k.buildIngressCollector(ctx)
	default:
		k.logger.Warn("unknown resource type", "resource", resource)
		return nil
	}
}

// ServeHTTP implements http.Handler for Prometheus scraping
func (k *KubeState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	buf := &bytes.Buffer{}
	for _, store := range k.stores {
		if err := store.WriteAll(buf); err != nil {
			k.logger.Error("failed to write metrics", "error", err)
			http.Error(w, "failed to write metrics", http.StatusInternalServerError)
			return
		}
	}

	if _, err := io.Copy(w, buf); err != nil {
		k.logger.Error("failed to send metrics", "error", err)
	}
}

// WriteMetrics writes all metrics to the provided writer
func (k *KubeState) WriteMetrics(w io.Writer) error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	for _, store := range k.stores {
		if err := store.WriteAll(w); err != nil {
			return err
		}
	}
	return nil
}

// GetMetricsBytes returns all metrics as bytes
func (k *KubeState) GetMetricsBytes() ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := k.WriteMetrics(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// IsHealthy returns true if the collector is healthy
func (k *KubeState) IsHealthy() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.started {
		return false
	}

	for _, informer := range k.informers {
		if !informer.HasSynced() {
			return false
		}
	}
	return true
}

// Size returns the total number of tracked objects
func (k *KubeState) Size() int {
	k.mu.RLock()
	defer k.mu.RUnlock()

	total := 0
	for _, store := range k.stores {
		total += store.Size()
	}
	return total
}

// Stats returns collector statistics
func (k *KubeState) Stats() map[string]interface{} {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return map[string]interface{}{
		"started":        k.started,
		"store_count":    len(k.stores),
		"informer_count": len(k.informers),
		"total_objects":  k.Size(),
		"shard":          k.config.Shard,
		"total_shards":   k.config.TotalShards,
	}
}

// IsMine checks if an object belongs to this shard
func (k *KubeState) IsMine(uid string) bool {
	return k.sharder.IsMine(uid)
}

// GetClient returns the Kubernetes clientset
func (k *KubeState) GetClient() kubernetes.Interface {
	return k.clientset
}
