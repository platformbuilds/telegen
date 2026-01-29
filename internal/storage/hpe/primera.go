// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package hpe provides collectors for HPE storage arrays.
package hpe

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/storagedef"
)

// PrimeraCollector collects metrics from HPE Primera/3PAR arrays via WSAPI
type PrimeraCollector struct {
	config      storagedef.HPEConfig
	client      *storagedef.HTTPClient
	log         *slog.Logger
	sessionKey  string
	sessionLock sync.Mutex

	mu      sync.RWMutex
	running bool
	health  *storagedef.CollectorHealth
}

// SystemInfo represents HPE system information
type SystemInfo struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	SystemVersion     string `json:"systemVersion"`
	Model             string `json:"model"`
	SerialNumber      string `json:"serialNumber"`
	TotalCapacityMiB  int64  `json:"totalCapacityMiB"`
	AllocatedCapacity int64  `json:"allocatedCapacityMiB"`
	FreeCapacity      int64  `json:"freeCapacityMiB"`
	FailedCapacityMiB int64  `json:"failedCapacityMiB"`
	TotalNodes        int    `json:"totalNodes"`
	OnlineNodes       int    `json:"onlineNodes"`
	ClusterNodes      int    `json:"clusterNodes"`
	ChunkletsizeMiB   int64  `json:"chunkletSizeMiB"`
	OverallState      int    `json:"overallState"`
	ClusterCondition  int    `json:"clusterCondition"`
	IPv4Addr          string `json:"IPv4Addr"`
	CompactModel      string `json:"compactModel"`
	Location          string `json:"location"`
}

// Volume represents an HPE volume
type Volume struct {
	ID               int     `json:"id"`
	Name             string  `json:"name"`
	SizeMiB          int64   `json:"sizeMiB"`
	UsrUsedMiB       int64   `json:"userSpace.usedMiB"`
	SnpUsedMiB       int64   `json:"snpSpace.usedMiB"`
	AdminUsedMiB     int64   `json:"adminSpace.usedMiB"`
	State            int     `json:"state"`
	ProvisioningType int     `json:"provisioningType"`
	BaseId           int     `json:"baseId"`
	WWN              string  `json:"wwn"`
	RdSLat           float64 `json:"rdSLat"`
	WrSLat           float64 `json:"wrSLat"`
	TotalIOPs        float64 `json:"totalIOPs"`
	ReadIOPs         float64 `json:"rdIOPs"`
	WriteIOPs        float64 `json:"wrIOPs"`
	ReadKB           float64 `json:"rdKBytes"`
	WriteKB          float64 `json:"wrKBytes"`
	CompressionRatio float64 `json:"compressionRatio"`
	DedupeRatio      float64 `json:"dedupeRatio"`
	CPG              string  `json:"userCPG"`
}

// CPG represents a Common Provisioning Group
type CPG struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	State       int    `json:"state"`
	NumFPVVs    int    `json:"numFPVVs"`
	NumTPVVs    int    `json:"numTPVVs"`
	NumTDVVs    int    `json:"numTDVVs"`
	UsedMiB     int64  `json:"UsrUsage.usedMiB"`
	TotalMiB    int64  `json:"UsrUsage.totalMiB"`
	RawUsedMiB  int64  `json:"UsrUsage.rawUsedMiB"`
	RawTotalMiB int64  `json:"UsrUsage.rawTotalMiB"`
}

// Port represents a port on the array
type Port struct {
	PortPos struct {
		Node int `json:"node"`
		Slot int `json:"slot"`
		Port int `json:"cardPort"`
	} `json:"portPos"`
	Type      int    `json:"type"`
	Protocol  int    `json:"protocol"`
	Mode      int    `json:"mode"`
	LinkState int    `json:"linkState"`
	WWN       string `json:"portWWN"`
	Label     string `json:"label"`
}

// Host represents a connected host
type Host struct {
	ID         int      `json:"id"`
	Name       string   `json:"name"`
	Persona    int      `json:"persona"`
	FCPaths    []FCPath `json:"FCPaths"`
	ISCSIPaths []string `json:"iSCSIPaths"`
}

// FCPath represents a Fibre Channel path
type FCPath struct {
	WWN     string `json:"wwn"`
	PortPos struct {
		Node int `json:"node"`
		Slot int `json:"slot"`
		Port int `json:"cardPort"`
	} `json:"portPos"`
}

// SessionResponse represents authentication response
type SessionResponse struct {
	Key string `json:"key"`
}

// NewPrimeraCollector creates a new HPE Primera/3PAR collector
func NewPrimeraCollector(cfg storagedef.HPEConfig, log *slog.Logger) (*PrimeraCollector, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "hpe-primera", "name", cfg.Name)

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

	collector := &PrimeraCollector{
		config: cfg,
		client: httpClient,
		log:    log,
		health: &storagedef.CollectorHealth{
			Status: storagedef.HealthStatusUnknown,
		},
	}

	// Set up session-based auth
	httpClient.SetAuthHook(collector.addSessionKey)

	return collector, nil
}

// Name returns the collector name
func (c *PrimeraCollector) Name() string {
	return c.config.Name
}

// Vendor returns the vendor type
func (c *PrimeraCollector) Vendor() storagedef.VendorType {
	return storagedef.VendorHPE
}

// Start initializes the collector
func (c *PrimeraCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.log.Info("starting HPE Primera collector",
		"address", c.config.Address,
	)

	// Authenticate and get session key
	if err := c.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	c.running = true
	return nil
}

// Stop shuts down the collector
func (c *PrimeraCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.log.Info("stopping HPE Primera collector")

	// Logout from session
	if c.sessionKey != "" {
		_ = c.logout(ctx)
	}

	c.running = false
	return nil
}

// Health returns the collector health status
func (c *PrimeraCollector) Health(ctx context.Context) (*storagedef.CollectorHealth, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.health, nil
}

// authenticate creates a session with the WSAPI
func (c *PrimeraCollector) authenticate(ctx context.Context) error {
	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()

	body := map[string]string{
		"user":     c.config.Username,
		"password": c.config.Password,
	}

	var resp SessionResponse
	if err := c.client.Post(ctx, "/api/v1/credentials", body, &resp); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	c.sessionKey = resp.Key
	c.log.Debug("authenticated successfully")
	return nil
}

// logout terminates the session
func (c *PrimeraCollector) logout(ctx context.Context) error {
	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()

	if c.sessionKey == "" {
		return nil
	}

	if err := c.client.Delete(ctx, "/api/v1/credentials/"+c.sessionKey); err != nil {
		return err
	}

	c.sessionKey = ""
	return nil
}

// addSessionKey adds the session key to requests
func (c *PrimeraCollector) addSessionKey(req *http.Request) error {
	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()

	if c.sessionKey != "" {
		req.Header.Set("X-HP3PAR-WSAPI-SessionKey", c.sessionKey)
	}
	return nil
}

// CollectMetrics collects all metrics from the Primera/3PAR array
func (c *PrimeraCollector) CollectMetrics(ctx context.Context) ([]storagedef.Metric, error) {
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

	// Collect system metrics
	if shouldCollect("system") || shouldCollect("capacity") {
		metrics, err := c.collectSystemMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect system metrics", "error", err)
			// Try to re-authenticate
			if authErr := c.authenticate(ctx); authErr == nil {
				metrics, err = c.collectSystemMetrics(ctx, now)
			}
		}
		if err == nil {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect CPG metrics
	if shouldCollect("cpg") || shouldCollect("pools") {
		metrics, err := c.collectCPGMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect CPG metrics", "error", err)
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

	// Collect port metrics
	if shouldCollect("ports") {
		metrics, err := c.collectPortMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect port metrics", "error", err)
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

	// Add common labels
	for i := range allMetrics {
		if allMetrics[i].Labels == nil {
			allMetrics[i].Labels = make(map[string]string)
		}
		allMetrics[i].Labels["array_name"] = c.config.Name
		allMetrics[i].Labels["vendor"] = "hpe"
		allMetrics[i].Labels["product"] = "primera"

		// Add any configured labels
		for k, v := range c.config.Labels {
			allMetrics[i].Labels[k] = v
		}
	}

	return allMetrics, nil
}

// collectSystemMetrics collects system-level metrics
func (c *PrimeraCollector) collectSystemMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var system SystemInfo
	if err := c.client.Get(ctx, "/api/v1/system", &system); err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}

	labels := map[string]string{
		"system_name":   system.Name,
		"model":         system.Model,
		"serial_number": system.SerialNumber,
		"version":       system.SystemVersion,
	}

	metrics := []storagedef.Metric{
		{
			Name:      "hpe_primera_system_total_capacity_bytes",
			Help:      "Total storage capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.TotalCapacityMiB) * 1024 * 1024,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "hpe_primera_system_allocated_capacity_bytes",
			Help:      "Allocated storage capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.AllocatedCapacity) * 1024 * 1024,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "hpe_primera_system_free_capacity_bytes",
			Help:      "Free storage capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.FreeCapacity) * 1024 * 1024,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "hpe_primera_system_failed_capacity_bytes",
			Help:      "Failed storage capacity in bytes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.FailedCapacityMiB) * 1024 * 1024,
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "hpe_primera_system_total_nodes",
			Help:      "Total number of nodes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.TotalNodes),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "hpe_primera_system_online_nodes",
			Help:      "Number of online nodes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.OnlineNodes),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "hpe_primera_system_cluster_nodes",
			Help:      "Number of cluster nodes",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.ClusterNodes),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "hpe_primera_system_state",
			Help:      "System overall state (1=normal)",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.OverallState),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "hpe_primera_system_cluster_condition",
			Help:      "Cluster condition (1=normal)",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(system.ClusterCondition),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
	}

	return metrics, nil
}

// collectCPGMetrics collects CPG-level metrics
func (c *PrimeraCollector) collectCPGMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Members []CPG `json:"members"`
	}
	if err := c.client.Get(ctx, "/api/v1/cpgs", &response); err != nil {
		return nil, fmt.Errorf("failed to get CPGs: %w", err)
	}

	var metrics []storagedef.Metric

	for _, cpg := range response.Members {
		labels := map[string]string{
			"cpg_id":   fmt.Sprintf("%d", cpg.ID),
			"cpg_name": cpg.Name,
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "hpe_primera_cpg_used_bytes",
				Help:      "CPG used capacity in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(cpg.UsedMiB) * 1024 * 1024,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_cpg_total_bytes",
				Help:      "CPG total capacity in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(cpg.TotalMiB) * 1024 * 1024,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_cpg_raw_used_bytes",
				Help:      "CPG raw used capacity in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(cpg.RawUsedMiB) * 1024 * 1024,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_cpg_raw_total_bytes",
				Help:      "CPG raw total capacity in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(cpg.RawTotalMiB) * 1024 * 1024,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_cpg_fpvv_count",
				Help:      "Number of FPVVs in CPG",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(cpg.NumFPVVs),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_cpg_tpvv_count",
				Help:      "Number of TPVVs in CPG",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(cpg.NumTPVVs),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_cpg_state",
				Help:      "CPG state (1=normal)",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(cpg.State),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectVolumeMetrics collects volume-level metrics
func (c *PrimeraCollector) collectVolumeMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Members []Volume `json:"members"`
	}
	if err := c.client.Get(ctx, "/api/v1/volumes", &response); err != nil {
		return nil, fmt.Errorf("failed to get volumes: %w", err)
	}

	var metrics []storagedef.Metric

	for _, vol := range response.Members {
		labels := map[string]string{
			"volume_id":   fmt.Sprintf("%d", vol.ID),
			"volume_name": vol.Name,
			"cpg":         vol.CPG,
			"wwn":         vol.WWN,
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "hpe_primera_volume_size_bytes",
				Help:      "Volume size in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.SizeMiB) * 1024 * 1024,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_used_bytes",
				Help:      "Volume user space used in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.UsrUsedMiB) * 1024 * 1024,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_snapshot_used_bytes",
				Help:      "Volume snapshot space used in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.SnpUsedMiB) * 1024 * 1024,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_state",
				Help:      "Volume state (1=normal)",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.State),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_read_iops",
				Help:      "Volume read IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.ReadIOPs,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_write_iops",
				Help:      "Volume write IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.WriteIOPs,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_total_iops",
				Help:      "Volume total IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.TotalIOPs,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_read_latency_ms",
				Help:      "Volume read latency in milliseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.RdSLat,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_write_latency_ms",
				Help:      "Volume write latency in milliseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.WrSLat,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_read_kbytes",
				Help:      "Volume read throughput in KB/s",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.ReadKB,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_write_kbytes",
				Help:      "Volume write throughput in KB/s",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.WriteKB,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_compression_ratio",
				Help:      "Volume compression ratio",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.CompressionRatio,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_volume_dedupe_ratio",
				Help:      "Volume deduplication ratio",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.DedupeRatio,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectPortMetrics collects port-level metrics
func (c *PrimeraCollector) collectPortMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Members []Port `json:"members"`
	}
	if err := c.client.Get(ctx, "/api/v1/ports", &response); err != nil {
		return nil, fmt.Errorf("failed to get ports: %w", err)
	}

	var metrics []storagedef.Metric

	for _, port := range response.Members {
		labels := map[string]string{
			"port_label": port.Label,
			"port_wwn":   port.WWN,
			"node":       fmt.Sprintf("%d", port.PortPos.Node),
			"slot":       fmt.Sprintf("%d", port.PortPos.Slot),
			"card_port":  fmt.Sprintf("%d", port.PortPos.Port),
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "hpe_primera_port_link_state",
				Help:      "Port link state (4=ready)",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(port.LinkState),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_port_type",
				Help:      "Port type",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(port.Type),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_port_mode",
				Help:      "Port mode",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(port.Mode),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectHostMetrics collects host-level metrics
func (c *PrimeraCollector) collectHostMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Members []Host `json:"members"`
	}
	if err := c.client.Get(ctx, "/api/v1/hosts", &response); err != nil {
		return nil, fmt.Errorf("failed to get hosts: %w", err)
	}

	var metrics []storagedef.Metric

	for _, host := range response.Members {
		labels := map[string]string{
			"host_id":   fmt.Sprintf("%d", host.ID),
			"host_name": host.Name,
			"persona":   fmt.Sprintf("%d", host.Persona),
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "hpe_primera_host_fc_paths",
				Help:      "Number of FC paths for host",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(len(host.FCPaths)),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "hpe_primera_host_iscsi_paths",
				Help:      "Number of iSCSI paths for host",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(len(host.ISCSIPaths)),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
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
