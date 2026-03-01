// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package dell provides collectors for Dell storage arrays.
package dell

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// PowerStoreCollector collects metrics from Dell PowerStore arrays via REST API
type PowerStoreCollector struct {
	config    storagedef.DellConfig
	client    *storagedef.HTTPClient
	log       *slog.Logger
	authToken string

	mu      sync.RWMutex
	running bool
	health  *storagedef.CollectorHealth
}

// Cluster represents a PowerStore cluster
type Cluster struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	State              string  `json:"state"`
	PhysicalCapacity   int64   `json:"physical_capacity"`
	PhysicalUsed       int64   `json:"physical_used"`
	LogicalCapacity    int64   `json:"logical_capacity"`
	LogicalUsed        int64   `json:"logical_used"`
	DataReductionRatio float64 `json:"data_reduction_ratio"`
}

// Volume represents a PowerStore volume
type Volume struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	Size               int64   `json:"size"`
	LogicalUsed        int64   `json:"logical_used"`
	DataReductionRatio float64 `json:"data_reduction_ratio"`
	State              string  `json:"state"`
	ProtectionPolicyID string  `json:"protection_policy_id"`
	Type               string  `json:"type"`
	WWN                string  `json:"wwn"`
}

// VolumePerformance represents volume performance metrics
type VolumePerformance struct {
	VolumeID       string  `json:"volume_id"`
	ReadIOPS       float64 `json:"read_iops"`
	WriteIOPS      float64 `json:"write_iops"`
	ReadBandwidth  float64 `json:"read_bandwidth"`
	WriteBandwidth float64 `json:"write_bandwidth"`
	ReadLatency    float64 `json:"read_latency_us"`
	WriteLatency   float64 `json:"write_latency_us"`
	AvgIOSize      float64 `json:"avg_io_size"`
}

// Host represents a connected host
type Host struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	OSType        string `json:"os_type"`
	Type          string `json:"type"`
	Initiators    int    `json:"num_of_initiators"`
	MappedVolumes int    `json:"num_of_mapped_volumes"`
}

// HostPerformance represents host I/O performance
type HostPerformance struct {
	HostID         string  `json:"host_id"`
	ReadIOPS       float64 `json:"read_iops"`
	WriteIOPS      float64 `json:"write_iops"`
	ReadBandwidth  float64 `json:"read_bandwidth"`
	WriteBandwidth float64 `json:"write_bandwidth"`
}

// NewPowerStoreCollector creates a new Dell PowerStore collector
func NewPowerStoreCollector(cfg storagedef.DellConfig, log *slog.Logger) (*PowerStoreCollector, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "dell-powerstore", "name", cfg.Name)

	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	httpClient, err := storagedef.NewHTTPClient(storagedef.HTTPClientConfig{
		BaseURL:   cfg.Address,
		Timeout:   cfg.Timeout,
		VerifySSL: cfg.VerifySSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	collector := &PowerStoreCollector{
		config: cfg,
		client: httpClient,
		log:    log,
		health: &storagedef.CollectorHealth{
			Status: storagedef.HealthStatusUnknown,
		},
	}

	// Set up basic auth
	httpClient.SetAuthHook(collector.addAuth)

	return collector, nil
}

// Name returns the collector name
func (c *PowerStoreCollector) Name() string {
	return c.config.Name
}

// Vendor returns the vendor type
func (c *PowerStoreCollector) Vendor() storagedef.VendorType {
	return storagedef.VendorDell
}

// Start initializes the collector
func (c *PowerStoreCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.log.Info("starting Dell PowerStore collector",
		"address", c.config.Address,
	)

	// Test connectivity
	if err := c.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	c.running = true
	return nil
}

// Stop shuts down the collector
func (c *PowerStoreCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.log.Info("stopping Dell PowerStore collector")
	c.running = false
	return nil
}

// Health returns the collector health status
func (c *PowerStoreCollector) Health(ctx context.Context) (*storagedef.CollectorHealth, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.health, nil
}

// authenticate performs basic authentication
func (c *PowerStoreCollector) authenticate(ctx context.Context) error {
	// PowerStore uses Basic auth with username:password
	auth := base64.StdEncoding.EncodeToString(
		[]byte(c.config.Username + ":" + c.config.Password),
	)
	c.authToken = auth

	// Test the connection by getting cluster info
	var cluster Cluster
	if err := c.client.Get(ctx, "/api/rest/cluster", &cluster); err != nil {
		return fmt.Errorf("failed to verify connection: %w", err)
	}

	c.log.Debug("authenticated successfully", "cluster", cluster.Name)
	return nil
}

// addAuth adds authentication to requests
func (c *PowerStoreCollector) addAuth(req *http.Request) error {
	if c.authToken != "" {
		req.Header.Set("Authorization", "Basic "+c.authToken)
	}
	return nil
}

// CollectMetrics collects all metrics from the PowerStore array
func (c *PowerStoreCollector) CollectMetrics(ctx context.Context) ([]storagedef.Metric, error) {
	c.mu.RLock()
	if !c.running {
		c.mu.RUnlock()
		return nil, fmt.Errorf("collector not running")
	}
	c.mu.RUnlock()

	var allMetrics []storagedef.Metric
	now := time.Now()

	// Determine what to collect based on configuration
	collectAll := len(c.config.Collect) == 0
	shouldCollect := func(item string) bool {
		if collectAll {
			return true
		}
		for _, c := range c.config.Collect {
			if c == item {
				return true
			}
		}
		return false
	}

	// Collect cluster metrics
	if shouldCollect("capacity") || shouldCollect("cluster") {
		metrics, err := c.collectClusterMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect cluster metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect volume metrics
	if shouldCollect("volumes") || shouldCollect("performance") {
		metrics, err := c.collectVolumeMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect volume metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect host metrics
	if shouldCollect("hosts") {
		metrics, err := c.collectHostMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect host metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Add common labels to all metrics
	for i := range allMetrics {
		if allMetrics[i].Labels == nil {
			allMetrics[i].Labels = make(map[string]string)
		}
		allMetrics[i].Labels["array_name"] = c.config.Name
		allMetrics[i].Labels["vendor"] = "dell"
		allMetrics[i].Labels["product"] = "powerstore"

		// Add any configured labels
		for k, v := range c.config.Labels {
			allMetrics[i].Labels[k] = v
		}
	}

	return allMetrics, nil
}

// collectClusterMetrics collects cluster-level metrics
func (c *PowerStoreCollector) collectClusterMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var cluster Cluster
	if err := c.client.Get(ctx, "/api/rest/cluster", &cluster); err != nil {
		return nil, fmt.Errorf("failed to get cluster info: %w", err)
	}

	labels := map[string]string{
		"cluster_id":   cluster.ID,
		"cluster_name": cluster.Name,
	}

	metrics := []storagedef.Metric{
		{
			Name:      "dell_powerstore_cluster_physical_capacity_bytes",
			Help:      "Physical storage capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.PhysicalCapacity),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "dell_powerstore_cluster_physical_used_bytes",
			Help:      "Physical storage used in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.PhysicalUsed),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "dell_powerstore_cluster_logical_capacity_bytes",
			Help:      "Logical storage capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.LogicalCapacity),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "dell_powerstore_cluster_logical_used_bytes",
			Help:      "Logical storage used in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.LogicalUsed),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "dell_powerstore_cluster_data_reduction_ratio",
			Help:      "Data reduction ratio",
			Type:      storagedef.MetricTypeGauge,
			Value:     cluster.DataReductionRatio,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "dell_powerstore_cluster_state",
			Help:      "Cluster state (1=healthy, 0=other)",
			Type:      storagedef.MetricTypeGauge,
			Value:     stateToValue(cluster.State),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
	}

	return metrics, nil
}

// collectVolumeMetrics collects volume-level metrics
func (c *PowerStoreCollector) collectVolumeMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var volumes []Volume
	if err := c.client.Get(ctx, "/api/rest/volume", &volumes); err != nil {
		return nil, fmt.Errorf("failed to get volumes: %w", err)
	}

	var metrics []storagedef.Metric

	for _, vol := range volumes {
		labels := map[string]string{
			"volume_id":   vol.ID,
			"volume_name": vol.Name,
			"volume_type": vol.Type,
			"wwn":         vol.WWN,
		}

		// Capacity metrics
		metrics = append(metrics,
			storagedef.Metric{
				Name:      "dell_powerstore_volume_size_bytes",
				Help:      "Volume size in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Size),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_volume_used_bytes",
				Help:      "Volume logical used in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.LogicalUsed),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_volume_data_reduction_ratio",
				Help:      "Volume data reduction ratio",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.DataReductionRatio,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_volume_state",
				Help:      "Volume state (1=healthy, 0=other)",
				Type:      storagedef.MetricTypeGauge,
				Value:     stateToValue(vol.State),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)

		// Get performance metrics for this volume
		perf, err := c.getVolumePerformance(ctx, vol.ID)
		if err != nil {
			c.log.Debug("failed to get volume performance", "volume", vol.Name, "error", err)
			continue
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "dell_powerstore_volume_read_iops",
				Help:      "Volume read IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.ReadIOPS,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_volume_write_iops",
				Help:      "Volume write IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.WriteIOPS,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_volume_read_bandwidth_bytes",
				Help:      "Volume read bandwidth in bytes/sec",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.ReadBandwidth,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_volume_write_bandwidth_bytes",
				Help:      "Volume write bandwidth in bytes/sec",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.WriteBandwidth,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_volume_read_latency_us",
				Help:      "Volume read latency in microseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.ReadLatency,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_volume_write_latency_us",
				Help:      "Volume write latency in microseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.WriteLatency,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// getVolumePerformance gets performance metrics for a volume
func (c *PowerStoreCollector) getVolumePerformance(ctx context.Context, volumeID string) (*VolumePerformance, error) {
	var perf VolumePerformance
	path := fmt.Sprintf("/api/rest/metrics/volume/%s", volumeID)
	if err := c.client.Get(ctx, path, &perf); err != nil {
		return nil, err
	}
	return &perf, nil
}

// collectHostMetrics collects host-level metrics
func (c *PowerStoreCollector) collectHostMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var hosts []Host
	if err := c.client.Get(ctx, "/api/rest/host", &hosts); err != nil {
		return nil, fmt.Errorf("failed to get hosts: %w", err)
	}

	var metrics []storagedef.Metric

	for _, host := range hosts {
		labels := map[string]string{
			"host_id":   host.ID,
			"host_name": host.Name,
			"os_type":   host.OSType,
			"host_type": host.Type,
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "dell_powerstore_host_initiators",
				Help:      "Number of initiators for host",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(host.Initiators),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_host_mapped_volumes",
				Help:      "Number of volumes mapped to host",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(host.MappedVolumes),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)

		// Get host performance metrics
		perf, err := c.getHostPerformance(ctx, host.ID)
		if err != nil {
			c.log.Debug("failed to get host performance", "host", host.Name, "error", err)
			continue
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "dell_powerstore_host_read_iops",
				Help:      "Host read IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.ReadIOPS,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_host_write_iops",
				Help:      "Host write IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.WriteIOPS,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_host_read_bandwidth_bytes",
				Help:      "Host read bandwidth in bytes/sec",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.ReadBandwidth,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "dell_powerstore_host_write_bandwidth_bytes",
				Help:      "Host write bandwidth in bytes/sec",
				Type:      storagedef.MetricTypeGauge,
				Value:     perf.WriteBandwidth,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// getHostPerformance gets performance metrics for a host
func (c *PowerStoreCollector) getHostPerformance(ctx context.Context, hostID string) (*HostPerformance, error) {
	var perf HostPerformance
	path := fmt.Sprintf("/api/rest/metrics/host/%s", hostID)
	if err := c.client.Get(ctx, path, &perf); err != nil {
		return nil, err
	}
	return &perf, nil
}

// Helper functions

func copyLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}

func stateToValue(state string) float64 {
	switch state {
	case "Configured", "healthy", "Ready", "online":
		return 1
	default:
		return 0
	}
}
