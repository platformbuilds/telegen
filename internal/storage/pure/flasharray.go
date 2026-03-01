// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package pure provides collectors for Pure Storage arrays.
package pure

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// FlashArrayCollector collects metrics from Pure FlashArray via REST API v2
type FlashArrayCollector struct {
	config      storagedef.PureConfig
	client      *storagedef.HTTPClient
	log         *slog.Logger
	accessToken string
	tokenExpiry time.Time

	mu      sync.RWMutex
	running bool
	health  *storagedef.CollectorHealth
}

// Array represents FlashArray system information
type Array struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	PurityVersion   string `json:"purity_version"`
	Capacity        int64  `json:"capacity"`
	Banner          string `json:"banner"`
	ConsoleLockFlag bool   `json:"console_lock_enabled"`
}

// ArraySpace represents FlashArray space metrics
type ArraySpace struct {
	Space struct {
		DataReduction    float64 `json:"data_reduction"`
		ThinProvisioning float64 `json:"thin_provisioning"`
		TotalReduction   float64 `json:"total_reduction"`
		Shared           int64   `json:"shared"`
		Snapshots        int64   `json:"snapshots"`
		System           int64   `json:"system"`
		TotalPhysical    int64   `json:"total_physical"`
		TotalProvisioned int64   `json:"total_provisioned"`
		Unique           int64   `json:"unique"`
		Virtual          int64   `json:"virtual"`
	} `json:"space"`
	Capacity int64 `json:"capacity"`
}

// ArrayPerformance represents FlashArray performance metrics
type ArrayPerformance struct {
	ReadBytesPerSec       int64   `json:"reads_per_sec"`
	WriteBytesPerSec      int64   `json:"writes_per_sec"`
	ReadOpsPerSec         int64   `json:"read_bytes_per_sec"`
	WriteOpsPerSec        int64   `json:"write_bytes_per_sec"`
	UsecPerReadOp         float64 `json:"usec_per_read_op"`
	UsecPerWriteOp        float64 `json:"usec_per_write_op"`
	InputPerSec           int64   `json:"input_per_sec"`
	OutputPerSec          int64   `json:"output_per_sec"`
	QueueDepth            int64   `json:"queue_depth"`
	SanUsecPerReadOp      float64 `json:"san_usec_per_read_op"`
	SanUsecPerWriteOp     float64 `json:"san_usec_per_write_op"`
	ServiceUsecPerReadOp  float64 `json:"service_usec_per_read_op"`
	ServiceUsecPerWriteOp float64 `json:"service_usec_per_write_op"`
}

// Volume represents a Pure volume
type Volume struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provisioned int64  `json:"provisioned"`
	Serial      string `json:"serial"`
	Created     int64  `json:"created"`
	Source      struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"source"`
	Space struct {
		DataReduction    float64 `json:"data_reduction"`
		TotalReduction   float64 `json:"total_reduction"`
		Snapshots        int64   `json:"snapshots"`
		TotalPhysical    int64   `json:"total_physical"`
		Unique           int64   `json:"unique"`
		Virtual          int64   `json:"virtual"`
		ThinProvisioning float64 `json:"thin_provisioning"`
	} `json:"space"`
	Priority      int   `json:"priority"`
	Destroyed     bool  `json:"destroyed"`
	TimeRemaining int64 `json:"time_remaining"`
}

// VolumePerformance represents volume performance metrics
type VolumePerformance struct {
	Name             string  `json:"name"`
	ReadBytesPerSec  int64   `json:"read_bytes_per_sec"`
	WriteBytesPerSec int64   `json:"write_bytes_per_sec"`
	ReadsPerSec      int64   `json:"reads_per_sec"`
	WritesPerSec     int64   `json:"writes_per_sec"`
	UsecPerReadOp    float64 `json:"usec_per_read_op"`
	UsecPerWriteOp   float64 `json:"usec_per_write_op"`
}

// Host represents a connected host
type Host struct {
	Name        string   `json:"name"`
	WWN         []string `json:"wwn"`
	IQN         []string `json:"iqn"`
	NQN         []string `json:"nqn"`
	Personality string   `json:"personality"`
	HostGroup   struct {
		Name string `json:"name"`
	} `json:"host_group"`
}

// HostGroup represents a host group
type HostGroup struct {
	Name      string `json:"name"`
	HostCount int    `json:"host_count"`
}

// Controller represents a FlashArray controller
type Controller struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"`
	Model   string `json:"model"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

// HardwareComponent represents a hardware component
type Hardware struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Status      string  `json:"status"`
	Index       int     `json:"index"`
	Identify    string  `json:"identify"`
	Slot        int     `json:"slot"`
	Speed       int64   `json:"speed"`
	Temperature int     `json:"temperature"`
	Voltage     float64 `json:"voltage"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// NewFlashArrayCollector creates a new Pure FlashArray collector
func NewFlashArrayCollector(cfg storagedef.PureConfig, log *slog.Logger) (*FlashArrayCollector, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "pure-flasharray", "name", cfg.Name)

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

	collector := &FlashArrayCollector{
		config: cfg,
		client: httpClient,
		log:    log,
		health: &storagedef.CollectorHealth{
			Status: storagedef.HealthStatusUnknown,
		},
	}

	// Set up OAuth token-based auth
	httpClient.SetAuthHook(collector.addAuthToken)

	return collector, nil
}

// Name returns the collector name
func (c *FlashArrayCollector) Name() string {
	return c.config.Name
}

// Vendor returns the vendor type
func (c *FlashArrayCollector) Vendor() storagedef.VendorType {
	return storagedef.VendorPure
}

// Start initializes the collector
func (c *FlashArrayCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.log.Info("starting Pure FlashArray collector",
		"address", c.config.Address,
	)

	// Authenticate with API
	if err := c.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	c.running = true
	return nil
}

// Stop shuts down the collector
func (c *FlashArrayCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.log.Info("stopping Pure FlashArray collector")
	c.running = false
	c.accessToken = ""
	return nil
}

// Health returns the collector health status
func (c *FlashArrayCollector) Health(ctx context.Context) (*storagedef.CollectorHealth, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.health, nil
}

// authenticate gets an OAuth token from the API
func (c *FlashArrayCollector) authenticate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Pure uses API token authentication
	// First, we need to create an access token using the API token
	body := map[string]string{
		"api_token": c.config.APIToken,
	}

	var resp AuthResponse
	if err := c.client.Post(ctx, "/api/2.0/login", body, &resp); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	c.accessToken = resp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	c.log.Debug("authenticated successfully", "expires_in", resp.ExpiresIn)
	return nil
}

// refreshTokenIfNeeded checks and refreshes token if expired
func (c *FlashArrayCollector) refreshTokenIfNeeded(ctx context.Context) error {
	// Check if token is about to expire (within 5 minutes)
	if time.Until(c.tokenExpiry) < 5*time.Minute {
		return c.authenticate(ctx)
	}
	return nil
}

// addAuthToken adds the access token to requests
func (c *FlashArrayCollector) addAuthToken(req *http.Request) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	// Pure FlashArray also uses this header
	req.Header.Set("x-auth-token", c.accessToken)
	return nil
}

// CollectMetrics collects all metrics from the FlashArray
func (c *FlashArrayCollector) CollectMetrics(ctx context.Context) ([]storagedef.Metric, error) {
	c.mu.RLock()
	if !c.running {
		c.mu.RUnlock()
		return nil, fmt.Errorf("collector not running")
	}
	c.mu.RUnlock()

	// Refresh token if needed
	if err := c.refreshTokenIfNeeded(ctx); err != nil {
		c.log.Warn("failed to refresh token", "error", err)
	}

	var allMetrics []storagedef.Metric
	now := time.Now()

	// Determine what to collect
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

	// Collect array metrics
	if shouldCollect("array") || shouldCollect("capacity") {
		metrics, err := c.collectArrayMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect array metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect array performance metrics
	if shouldCollect("performance") {
		metrics, err := c.collectArrayPerformance(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect array performance", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect volume metrics
	if shouldCollect("volumes") {
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

	// Collect hardware metrics
	if shouldCollect("hardware") {
		metrics, err := c.collectHardwareMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect hardware metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Add common labels
	for i := range allMetrics {
		if allMetrics[i].Labels == nil {
			allMetrics[i].Labels = make(map[string]string)
		}
		allMetrics[i].Labels["array_name"] = c.config.Name
		allMetrics[i].Labels["vendor"] = "pure"
		allMetrics[i].Labels["product"] = "flasharray"

		// Add any configured labels
		for k, v := range c.config.Labels {
			allMetrics[i].Labels[k] = v
		}
	}

	return allMetrics, nil
}

// collectArrayMetrics collects array-level metrics
func (c *FlashArrayCollector) collectArrayMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	// Get array info
	var arrays struct {
		Items []Array `json:"items"`
	}
	if err := c.client.Get(ctx, "/api/2.0/arrays", &arrays); err != nil {
		return nil, fmt.Errorf("failed to get array info: %w", err)
	}

	if len(arrays.Items) == 0 {
		return nil, fmt.Errorf("no array info returned")
	}

	array := arrays.Items[0]

	// Get space metrics
	var space struct {
		Items []ArraySpace `json:"items"`
	}
	if err := c.client.Get(ctx, "/api/2.0/arrays/space", &space); err != nil {
		return nil, fmt.Errorf("failed to get space info: %w", err)
	}

	var spaceInfo ArraySpace
	if len(space.Items) > 0 {
		spaceInfo = space.Items[0]
	}

	labels := map[string]string{
		"array_id":   array.ID,
		"name":       array.Name,
		"version":    array.Version,
		"purity_ver": array.PurityVersion,
	}

	metrics := []storagedef.Metric{
		{
			Name:      "pure_flasharray_capacity_bytes",
			Help:      "Total array capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(spaceInfo.Capacity),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_used_bytes",
			Help:      "Total used capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(spaceInfo.Space.TotalPhysical),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_provisioned_bytes",
			Help:      "Total provisioned capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(spaceInfo.Space.TotalProvisioned),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_snapshot_bytes",
			Help:      "Snapshot space used in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(spaceInfo.Space.Snapshots),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_shared_bytes",
			Help:      "Shared space in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(spaceInfo.Space.Shared),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_system_bytes",
			Help:      "System space used in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(spaceInfo.Space.System),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_data_reduction_ratio",
			Help:      "Data reduction ratio",
			Type:      storagedef.MetricTypeGauge,
			Value:     spaceInfo.Space.DataReduction,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_total_reduction_ratio",
			Help:      "Total reduction ratio",
			Type:      storagedef.MetricTypeGauge,
			Value:     spaceInfo.Space.TotalReduction,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_thin_provisioning_ratio",
			Help:      "Thin provisioning savings",
			Type:      storagedef.MetricTypeGauge,
			Value:     spaceInfo.Space.ThinProvisioning,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
	}

	return metrics, nil
}

// collectArrayPerformance collects array performance metrics
func (c *FlashArrayCollector) collectArrayPerformance(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var perf struct {
		Items []ArrayPerformance `json:"items"`
	}
	if err := c.client.Get(ctx, "/api/2.0/arrays/performance", &perf); err != nil {
		return nil, fmt.Errorf("failed to get array performance: %w", err)
	}

	if len(perf.Items) == 0 {
		return nil, fmt.Errorf("no performance data returned")
	}

	p := perf.Items[0]
	labels := make(map[string]string)

	metrics := []storagedef.Metric{
		{
			Name:      "pure_flasharray_read_iops",
			Help:      "Array read IOPS",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(p.ReadOpsPerSec),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_write_iops",
			Help:      "Array write IOPS",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(p.WriteOpsPerSec),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_read_bandwidth_bytes",
			Help:      "Array read bandwidth in bytes/sec",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(p.ReadBytesPerSec),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_write_bandwidth_bytes",
			Help:      "Array write bandwidth in bytes/sec",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(p.WriteBytesPerSec),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_read_latency_usec",
			Help:      "Array read latency in microseconds",
			Type:      storagedef.MetricTypeGauge,
			Value:     p.UsecPerReadOp,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_write_latency_usec",
			Help:      "Array write latency in microseconds",
			Type:      storagedef.MetricTypeGauge,
			Value:     p.UsecPerWriteOp,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_queue_depth",
			Help:      "Array queue depth",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(p.QueueDepth),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_san_read_latency_usec",
			Help:      "SAN read latency in microseconds",
			Type:      storagedef.MetricTypeGauge,
			Value:     p.SanUsecPerReadOp,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "pure_flasharray_san_write_latency_usec",
			Help:      "SAN write latency in microseconds",
			Type:      storagedef.MetricTypeGauge,
			Value:     p.SanUsecPerWriteOp,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
	}

	return metrics, nil
}

// collectVolumeMetrics collects volume-level metrics
func (c *FlashArrayCollector) collectVolumeMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	// Get volumes
	var volumes struct {
		Items []Volume `json:"items"`
	}
	if err := c.client.Get(ctx, "/api/2.0/volumes", &volumes); err != nil {
		return nil, fmt.Errorf("failed to get volumes: %w", err)
	}

	// Get volume performance
	var perf struct {
		Items []VolumePerformance `json:"items"`
	}
	_ = c.client.Get(ctx, "/api/2.0/volumes/performance", &perf)

	// Build performance lookup
	perfMap := make(map[string]VolumePerformance)
	for _, p := range perf.Items {
		perfMap[p.Name] = p
	}

	var metrics []storagedef.Metric

	for _, vol := range volumes.Items {
		if vol.Destroyed {
			continue // Skip destroyed volumes
		}

		labels := map[string]string{
			"volume_id":   vol.ID,
			"volume_name": vol.Name,
			"serial":      vol.Serial,
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "pure_flasharray_volume_provisioned_bytes",
				Help:      "Volume provisioned size in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Provisioned),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "pure_flasharray_volume_used_bytes",
				Help:      "Volume unique space used in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Space.Unique),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "pure_flasharray_volume_physical_bytes",
				Help:      "Volume total physical used in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Space.TotalPhysical),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "pure_flasharray_volume_snapshot_bytes",
				Help:      "Volume snapshot space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Space.Snapshots),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "pure_flasharray_volume_data_reduction_ratio",
				Help:      "Volume data reduction ratio",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.Space.DataReduction,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)

		// Add performance metrics if available
		if p, ok := perfMap[vol.Name]; ok {
			metrics = append(metrics,
				storagedef.Metric{
					Name:      "pure_flasharray_volume_read_iops",
					Help:      "Volume read IOPS",
					Type:      storagedef.MetricTypeGauge,
					Value:     float64(p.ReadsPerSec),
					Labels:    copyLabels(labels),
					Timestamp: timestamp,
				},
				storagedef.Metric{
					Name:      "pure_flasharray_volume_write_iops",
					Help:      "Volume write IOPS",
					Type:      storagedef.MetricTypeGauge,
					Value:     float64(p.WritesPerSec),
					Labels:    copyLabels(labels),
					Timestamp: timestamp,
				},
				storagedef.Metric{
					Name:      "pure_flasharray_volume_read_bandwidth_bytes",
					Help:      "Volume read bandwidth in bytes/sec",
					Type:      storagedef.MetricTypeGauge,
					Value:     float64(p.ReadBytesPerSec),
					Labels:    copyLabels(labels),
					Timestamp: timestamp,
				},
				storagedef.Metric{
					Name:      "pure_flasharray_volume_write_bandwidth_bytes",
					Help:      "Volume write bandwidth in bytes/sec",
					Type:      storagedef.MetricTypeGauge,
					Value:     float64(p.WriteBytesPerSec),
					Labels:    copyLabels(labels),
					Timestamp: timestamp,
				},
				storagedef.Metric{
					Name:      "pure_flasharray_volume_read_latency_usec",
					Help:      "Volume read latency in microseconds",
					Type:      storagedef.MetricTypeGauge,
					Value:     p.UsecPerReadOp,
					Labels:    copyLabels(labels),
					Timestamp: timestamp,
				},
				storagedef.Metric{
					Name:      "pure_flasharray_volume_write_latency_usec",
					Help:      "Volume write latency in microseconds",
					Type:      storagedef.MetricTypeGauge,
					Value:     p.UsecPerWriteOp,
					Labels:    copyLabels(labels),
					Timestamp: timestamp,
				},
			)
		}
	}

	return metrics, nil
}

// collectHostMetrics collects host-level metrics
func (c *FlashArrayCollector) collectHostMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var hosts struct {
		Items []Host `json:"items"`
	}
	if err := c.client.Get(ctx, "/api/2.0/hosts", &hosts); err != nil {
		return nil, fmt.Errorf("failed to get hosts: %w", err)
	}

	var metrics []storagedef.Metric

	for _, host := range hosts.Items {
		labels := map[string]string{
			"host_name":   host.Name,
			"personality": host.Personality,
			"host_group":  host.HostGroup.Name,
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "pure_flasharray_host_wwn_count",
				Help:      "Number of FC WWNs for host",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(len(host.WWN)),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "pure_flasharray_host_iqn_count",
				Help:      "Number of iSCSI IQNs for host",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(len(host.IQN)),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "pure_flasharray_host_nqn_count",
				Help:      "Number of NVMe NQNs for host",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(len(host.NQN)),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectHardwareMetrics collects hardware-level metrics
func (c *FlashArrayCollector) collectHardwareMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	// Get controllers
	var controllers struct {
		Items []Controller `json:"items"`
	}
	if err := c.client.Get(ctx, "/api/2.0/controllers", &controllers); err != nil {
		c.log.Debug("failed to get controllers", "error", err)
	}

	var metrics []storagedef.Metric

	for _, ctrl := range controllers.Items {
		labels := map[string]string{
			"controller_name": ctrl.Name,
			"model":           ctrl.Model,
			"mode":            ctrl.Mode,
		}

		statusVal := 0.0
		if ctrl.Status == "ready" || ctrl.Status == "online" {
			statusVal = 1.0
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "pure_flasharray_controller_status",
				Help:      "Controller status (1=ready/online)",
				Type:      storagedef.MetricTypeGauge,
				Value:     statusVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	// Get hardware components
	var hardware struct {
		Items []Hardware `json:"items"`
	}
	if err := c.client.Get(ctx, "/api/2.0/hardware", &hardware); err != nil {
		c.log.Debug("failed to get hardware", "error", err)
		return metrics, nil
	}

	for _, hw := range hardware.Items {
		labels := map[string]string{
			"component_name": hw.Name,
			"type":           hw.Type,
		}

		statusVal := 0.0
		if hw.Status == "ok" || hw.Status == "healthy" {
			statusVal = 1.0
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "pure_flasharray_hardware_status",
				Help:      "Hardware component status (1=ok/healthy)",
				Type:      storagedef.MetricTypeGauge,
				Value:     statusVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)

		// Add temperature if available
		if hw.Temperature > 0 {
			metrics = append(metrics,
				storagedef.Metric{
					Name:      "pure_flasharray_hardware_temperature_celsius",
					Help:      "Hardware component temperature in Celsius",
					Type:      storagedef.MetricTypeGauge,
					Value:     float64(hw.Temperature),
					Labels:    copyLabels(labels),
					Timestamp: timestamp,
				},
			)
		}
	}

	return metrics, nil
}

// Helper functions

func copyLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}
	return result
}
