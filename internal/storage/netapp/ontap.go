// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package netapp provides collectors for NetApp storage arrays.
package netapp

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

// ONTAPCollector collects metrics from NetApp ONTAP via REST API
type ONTAPCollector struct {
	config    storagedef.NetAppConfig
	client    *storagedef.HTTPClient
	log       *slog.Logger
	authToken string

	mu      sync.RWMutex
	running bool
	health  *storagedef.CollectorHealth
}

// Cluster represents an ONTAP cluster
type Cluster struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Version struct {
		Full       string `json:"full"`
		Generation int    `json:"generation"`
		Major      int    `json:"major"`
		Minor      int    `json:"minor"`
	} `json:"version"`
	Location   string   `json:"location"`
	Contact    string   `json:"contact"`
	DNSDomains []string `json:"dns_domains"`
	Management struct {
		InterfaceAddress string `json:"interface_address"`
	} `json:"management_interface"`
	MetricStats struct {
		Timestamp  string  `json:"timestamp"`
		IOPS       Metrics `json:"iops"`
		Latency    Metrics `json:"latency"`
		Throughput Metrics `json:"throughput"`
	} `json:"metric"`
}

// Metrics represents ONTAP metric values
type Metrics struct {
	Read  int64 `json:"read"`
	Write int64 `json:"write"`
	Other int64 `json:"other"`
	Total int64 `json:"total"`
}

// Node represents an ONTAP cluster node
type Node struct {
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	Location     string `json:"location"`
	Uptime       int64  `json:"uptime"`
	State        string `json:"state"`
	HAEnabled    bool   `json:"ha_enabled"`
	HAPartner    struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"ha_partner"`
	Controller struct {
		CPU struct {
			Count           int    `json:"count"`
			FirmwareRelease string `json:"firmware_release"`
		} `json:"cpu"`
		FailedFanCount  int  `json:"failed_fan_count"`
		FailedPSUCount  int  `json:"failed_psu_count"`
		OverTemperature bool `json:"over_temperature"`
	} `json:"controller"`
}

// Aggregate represents an ONTAP aggregate
type Aggregate struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	Node struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"node"`
	State string `json:"state"`
	Space struct {
		BlockStorage struct {
			Size                int64 `json:"size"`
			Available           int64 `json:"available"`
			Used                int64 `json:"used"`
			PhysicalUsed        int64 `json:"physical_used"`
			PhysicalUsedPercent int   `json:"physical_used_percent"`
		} `json:"block_storage"`
		CloudStorage struct {
			Used int64 `json:"used"`
		} `json:"cloud_storage"`
		Efficiency struct {
			Savings                int64   `json:"savings"`
			Ratio                  float64 `json:"ratio"`
			LogicalUsed            int64   `json:"logical_used"`
			CrossVolumeDedupeRatio float64 `json:"cross_volume_dedupe_savings"`
		} `json:"efficiency"`
		Footprint int64 `json:"footprint"`
	} `json:"space"`
	Metric struct {
		IOPS       Metrics `json:"iops"`
		Latency    Metrics `json:"latency"`
		Throughput Metrics `json:"throughput"`
	} `json:"metric"`
}

// SVM represents an ONTAP SVM (Storage Virtual Machine)
type SVM struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Subtype string `json:"subtype"`
	Comment string `json:"comment"`
	IPSpace struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"ipspace"`
	Language string `json:"language"`
}

// Volume represents an ONTAP volume
type Volume struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	State string `json:"state"`
	Style string `json:"style"`
	SVM   struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"svm"`
	Aggregates []struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"aggregates"`
	Space struct {
		Size         int64 `json:"size"`
		Available    int64 `json:"available"`
		Used         int64 `json:"used"`
		LogicalSpace struct {
			Enforcement bool  `json:"enforcement"`
			Reporting   bool  `json:"reporting"`
			UsedByAFS   int64 `json:"used_by_afs"`
			Available   int64 `json:"available"`
		} `json:"logical_space"`
		Snapshot struct {
			Used              int64  `json:"used"`
			ReservePercent    int    `json:"reserve_percent"`
			AutoDeleteTrigger string `json:"autodelete_trigger"`
		} `json:"snapshot"`
		PhysicalUsed        int64 `json:"physical_used"`
		PhysicalUsedPercent int   `json:"physical_used_percent"`
	} `json:"space"`
	Metric struct {
		IOPS       Metrics `json:"iops"`
		Latency    Metrics `json:"latency"`
		Throughput Metrics `json:"throughput"`
	} `json:"metric"`
	Efficiency struct {
		Compression           string  `json:"compression"`
		Compaction            string  `json:"compaction"`
		Dedupe                string  `json:"dedupe"`
		CrossVolumeBackground bool    `json:"cross_volume_dedupe"`
		SavingsRatio          float64 `json:"ratio"`
	} `json:"efficiency"`
	Nas struct {
		ExportPolicy struct {
			Name string `json:"name"`
		} `json:"export_policy"`
		JunctionPath  string `json:"junction_path"`
		SecurityStyle string `json:"security_style"`
	} `json:"nas"`
}

// LUN represents an ONTAP LUN
type LUN struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	SVM  struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"svm"`
	Location struct {
		Volume struct {
			Name string `json:"name"`
			UUID string `json:"uuid"`
		} `json:"volume"`
		LogicalUnit string `json:"logical_unit"`
	} `json:"location"`
	Space struct {
		Size          int64 `json:"size"`
		Used          int64 `json:"used"`
		GuaranteeSize int64 `json:"guarantee_size"`
	} `json:"space"`
	Status struct {
		State          string `json:"state"`
		Mapped         bool   `json:"mapped"`
		ReadOnly       bool   `json:"read_only"`
		ContainerState string `json:"container_state"`
	} `json:"status"`
	OSType       string `json:"os_type"`
	SerialNumber string `json:"serial_number"`
	Metric       struct {
		IOPS       Metrics `json:"iops"`
		Latency    Metrics `json:"latency"`
		Throughput Metrics `json:"throughput"`
	} `json:"metric"`
}

// Port represents a network port
type Port struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	Node struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"node"`
	State           string `json:"state"`
	Speed           int64  `json:"speed"`
	Type            string `json:"type"`
	Enabled         bool   `json:"enabled"`
	MTU             int    `json:"mtu"`
	BroadcastDomain struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"broadcast_domain"`
}

// Disk represents a physical disk
type Disk struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
	Node struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"home_node"`
	State           string `json:"state"`
	Type            string `json:"type"`
	Class           string `json:"class"`
	Model           string `json:"model"`
	Vendor          string `json:"vendor"`
	SerialNumber    string `json:"serial_number"`
	FirmwareVersion string `json:"firmware_version"`
	UsableSize      int64  `json:"usable_size"`
	Bay             int    `json:"bay"`
	Shelf           struct {
		UID string `json:"uid"`
	} `json:"shelf"`
	Pool string `json:"pool"`
	RPM  int    `json:"rpm"`
}

// NewONTAPCollector creates a new NetApp ONTAP collector
func NewONTAPCollector(cfg storagedef.NetAppConfig, log *slog.Logger) (*ONTAPCollector, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "netapp-ontap", "name", cfg.Name)

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

	collector := &ONTAPCollector{
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
func (c *ONTAPCollector) Name() string {
	return c.config.Name
}

// Vendor returns the vendor type
func (c *ONTAPCollector) Vendor() storagedef.VendorType {
	return storagedef.VendorNetApp
}

// Start initializes the collector
func (c *ONTAPCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.log.Info("starting NetApp ONTAP collector",
		"address", c.config.Address,
	)

	// Set up authentication
	c.authToken = base64.StdEncoding.EncodeToString(
		[]byte(c.config.Username + ":" + c.config.Password),
	)

	// Test connectivity by getting cluster info
	var cluster Cluster
	if err := c.client.Get(ctx, "/api/cluster", &cluster); err != nil {
		return fmt.Errorf("failed to connect to ONTAP cluster: %w", err)
	}

	c.log.Debug("connected to cluster", "name", cluster.Name, "version", cluster.Version.Full)
	c.running = true
	return nil
}

// Stop shuts down the collector
func (c *ONTAPCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.log.Info("stopping NetApp ONTAP collector")
	c.running = false
	return nil
}

// Health returns the collector health status
func (c *ONTAPCollector) Health(ctx context.Context) (*storagedef.CollectorHealth, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.health, nil
}

// addAuth adds Basic authentication to requests
func (c *ONTAPCollector) addAuth(req *http.Request) error {
	if c.authToken != "" {
		req.Header.Set("Authorization", "Basic "+c.authToken)
	}
	req.Header.Set("Accept", "application/json")
	return nil
}

// CollectMetrics collects all metrics from the ONTAP cluster
func (c *ONTAPCollector) CollectMetrics(ctx context.Context) ([]storagedef.Metric, error) {
	c.mu.RLock()
	if !c.running {
		c.mu.RUnlock()
		return nil, fmt.Errorf("collector not running")
	}
	c.mu.RUnlock()

	var allMetrics []storagedef.Metric
	now := time.Now()

	// Determine what to collect
	collectAll := len(c.config.Collect) == 0
	shouldCollect := func(item string) bool {
		if collectAll {
			return true
		}
		for _, cfg := range c.config.Collect {
			if cfg == item {
				return true
			}
		}
		return false
	}

	// Collect cluster metrics
	if shouldCollect("cluster") {
		metrics, err := c.collectClusterMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect cluster metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect node metrics
	if shouldCollect("nodes") {
		metrics, err := c.collectNodeMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect node metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect aggregate metrics
	if shouldCollect("aggregates") || shouldCollect("capacity") {
		metrics, err := c.collectAggregateMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect aggregate metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect SVM metrics
	if shouldCollect("svms") {
		metrics, err := c.collectSVMMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect SVM metrics", "error", err)
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

	// Collect LUN metrics
	if shouldCollect("luns") {
		metrics, err := c.collectLUNMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect LUN metrics", "error", err)
		} else {
			allMetrics = append(allMetrics, metrics...)
		}
	}

	// Collect disk metrics
	if shouldCollect("disks") || shouldCollect("hardware") {
		metrics, err := c.collectDiskMetrics(ctx, now)
		if err != nil {
			c.log.Warn("failed to collect disk metrics", "error", err)
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
		allMetrics[i].Labels["vendor"] = "netapp"
		allMetrics[i].Labels["product"] = "ontap"

		// Add any configured labels
		for k, v := range c.config.Labels {
			allMetrics[i].Labels[k] = v
		}
	}

	return allMetrics, nil
}

// collectClusterMetrics collects cluster-level metrics
func (c *ONTAPCollector) collectClusterMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var cluster Cluster
	if err := c.client.Get(ctx, "/api/cluster?fields=*", &cluster); err != nil {
		return nil, fmt.Errorf("failed to get cluster info: %w", err)
	}

	labels := map[string]string{
		"cluster_uuid": cluster.UUID,
		"cluster_name": cluster.Name,
		"version":      cluster.Version.Full,
	}

	metrics := []storagedef.Metric{
		{
			Name:      "netapp_ontap_cluster_read_iops",
			Help:      "Cluster read IOPS",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.MetricStats.IOPS.Read),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "netapp_ontap_cluster_write_iops",
			Help:      "Cluster write IOPS",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.MetricStats.IOPS.Write),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "netapp_ontap_cluster_total_iops",
			Help:      "Cluster total IOPS",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.MetricStats.IOPS.Total),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "netapp_ontap_cluster_read_latency_us",
			Help:      "Cluster read latency in microseconds",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.MetricStats.Latency.Read),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "netapp_ontap_cluster_write_latency_us",
			Help:      "Cluster write latency in microseconds",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.MetricStats.Latency.Write),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "netapp_ontap_cluster_read_throughput_bytes",
			Help:      "Cluster read throughput in bytes/sec",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.MetricStats.Throughput.Read),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
		{
			Name:      "netapp_ontap_cluster_write_throughput_bytes",
			Help:      "Cluster write throughput in bytes/sec",
			Type:      storagedef.MetricTypeGauge,
			Value:     float64(cluster.MetricStats.Throughput.Write),
			Labels:    copyLabels(labels),
			Timestamp: timestamp,
		},
	}

	return metrics, nil
}

// collectNodeMetrics collects node-level metrics
func (c *ONTAPCollector) collectNodeMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Records []Node `json:"records"`
	}
	if err := c.client.Get(ctx, "/api/cluster/nodes?fields=*", &response); err != nil {
		return nil, fmt.Errorf("failed to get nodes: %w", err)
	}

	var metrics []storagedef.Metric

	for _, node := range response.Records {
		labels := map[string]string{
			"node_uuid":     node.UUID,
			"node_name":     node.Name,
			"model":         node.Model,
			"serial_number": node.SerialNumber,
		}

		stateVal := 0.0
		if node.State == "up" {
			stateVal = 1.0
		}

		haVal := 0.0
		if node.HAEnabled {
			haVal = 1.0
		}

		overTempVal := 0.0
		if node.Controller.OverTemperature {
			overTempVal = 1.0
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "netapp_ontap_node_state",
				Help:      "Node state (1=up, 0=down)",
				Type:      storagedef.MetricTypeGauge,
				Value:     stateVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_node_uptime_seconds",
				Help:      "Node uptime in seconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(node.Uptime),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_node_ha_enabled",
				Help:      "HA enabled (1=enabled, 0=disabled)",
				Type:      storagedef.MetricTypeGauge,
				Value:     haVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_node_cpu_count",
				Help:      "Number of CPUs",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(node.Controller.CPU.Count),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_node_failed_fans",
				Help:      "Number of failed fans",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(node.Controller.FailedFanCount),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_node_failed_psus",
				Help:      "Number of failed PSUs",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(node.Controller.FailedPSUCount),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_node_over_temperature",
				Help:      "Over temperature (1=yes, 0=no)",
				Type:      storagedef.MetricTypeGauge,
				Value:     overTempVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectAggregateMetrics collects aggregate-level metrics
func (c *ONTAPCollector) collectAggregateMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Records []Aggregate `json:"records"`
	}
	if err := c.client.Get(ctx, "/api/storage/aggregates?fields=*", &response); err != nil {
		return nil, fmt.Errorf("failed to get aggregates: %w", err)
	}

	var metrics []storagedef.Metric

	for _, aggr := range response.Records {
		labels := map[string]string{
			"aggregate_uuid": aggr.UUID,
			"aggregate_name": aggr.Name,
			"node_name":      aggr.Node.Name,
		}

		stateVal := 0.0
		if aggr.State == "online" {
			stateVal = 1.0
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_state",
				Help:      "Aggregate state (1=online)",
				Type:      storagedef.MetricTypeGauge,
				Value:     stateVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_size_bytes",
				Help:      "Aggregate total size in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Space.BlockStorage.Size),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_available_bytes",
				Help:      "Aggregate available space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Space.BlockStorage.Available),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_used_bytes",
				Help:      "Aggregate used space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Space.BlockStorage.Used),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_physical_used_bytes",
				Help:      "Aggregate physical used space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Space.BlockStorage.PhysicalUsed),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_physical_used_percent",
				Help:      "Aggregate physical used percentage",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Space.BlockStorage.PhysicalUsedPercent),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_efficiency_ratio",
				Help:      "Aggregate storage efficiency ratio",
				Type:      storagedef.MetricTypeGauge,
				Value:     aggr.Space.Efficiency.Ratio,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_efficiency_savings_bytes",
				Help:      "Aggregate efficiency savings in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Space.Efficiency.Savings),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			// Performance metrics
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_read_iops",
				Help:      "Aggregate read IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Metric.IOPS.Read),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_write_iops",
				Help:      "Aggregate write IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Metric.IOPS.Write),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_read_latency_us",
				Help:      "Aggregate read latency in microseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Metric.Latency.Read),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_aggregate_write_latency_us",
				Help:      "Aggregate write latency in microseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(aggr.Metric.Latency.Write),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectSVMMetrics collects SVM-level metrics
func (c *ONTAPCollector) collectSVMMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Records []SVM `json:"records"`
	}
	if err := c.client.Get(ctx, "/api/svm/svms?fields=*", &response); err != nil {
		return nil, fmt.Errorf("failed to get SVMs: %w", err)
	}

	var metrics []storagedef.Metric

	for _, svm := range response.Records {
		labels := map[string]string{
			"svm_uuid":    svm.UUID,
			"svm_name":    svm.Name,
			"svm_subtype": svm.Subtype,
			"ipspace":     svm.IPSpace.Name,
		}

		stateVal := 0.0
		if svm.State == "running" {
			stateVal = 1.0
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "netapp_ontap_svm_state",
				Help:      "SVM state (1=running)",
				Type:      storagedef.MetricTypeGauge,
				Value:     stateVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectVolumeMetrics collects volume-level metrics
func (c *ONTAPCollector) collectVolumeMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Records []Volume `json:"records"`
	}
	if err := c.client.Get(ctx, "/api/storage/volumes?fields=*", &response); err != nil {
		return nil, fmt.Errorf("failed to get volumes: %w", err)
	}

	var metrics []storagedef.Metric

	for _, vol := range response.Records {
		labels := map[string]string{
			"volume_uuid":  vol.UUID,
			"volume_name":  vol.Name,
			"volume_type":  vol.Type,
			"volume_style": vol.Style,
			"svm_name":     vol.SVM.Name,
		}

		stateVal := 0.0
		if vol.State == "online" {
			stateVal = 1.0
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "netapp_ontap_volume_state",
				Help:      "Volume state (1=online)",
				Type:      storagedef.MetricTypeGauge,
				Value:     stateVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_size_bytes",
				Help:      "Volume size in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Space.Size),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_available_bytes",
				Help:      "Volume available space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Space.Available),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_used_bytes",
				Help:      "Volume used space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Space.Used),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_physical_used_bytes",
				Help:      "Volume physical used space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Space.PhysicalUsed),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_snapshot_used_bytes",
				Help:      "Volume snapshot used space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Space.Snapshot.Used),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_efficiency_ratio",
				Help:      "Volume storage efficiency ratio",
				Type:      storagedef.MetricTypeGauge,
				Value:     vol.Efficiency.SavingsRatio,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			// Performance metrics
			storagedef.Metric{
				Name:      "netapp_ontap_volume_read_iops",
				Help:      "Volume read IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Metric.IOPS.Read),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_write_iops",
				Help:      "Volume write IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Metric.IOPS.Write),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_total_iops",
				Help:      "Volume total IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Metric.IOPS.Total),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_read_latency_us",
				Help:      "Volume read latency in microseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Metric.Latency.Read),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_write_latency_us",
				Help:      "Volume write latency in microseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Metric.Latency.Write),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_read_throughput_bytes",
				Help:      "Volume read throughput in bytes/sec",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Metric.Throughput.Read),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_volume_write_throughput_bytes",
				Help:      "Volume write throughput in bytes/sec",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(vol.Metric.Throughput.Write),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectLUNMetrics collects LUN-level metrics
func (c *ONTAPCollector) collectLUNMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Records []LUN `json:"records"`
	}
	if err := c.client.Get(ctx, "/api/storage/luns?fields=*", &response); err != nil {
		return nil, fmt.Errorf("failed to get LUNs: %w", err)
	}

	var metrics []storagedef.Metric

	for _, lun := range response.Records {
		labels := map[string]string{
			"lun_uuid":    lun.UUID,
			"lun_name":    lun.Name,
			"svm_name":    lun.SVM.Name,
			"volume_name": lun.Location.Volume.Name,
			"os_type":     lun.OSType,
		}

		stateVal := 0.0
		if lun.Status.State == "online" {
			stateVal = 1.0
		}

		mappedVal := 0.0
		if lun.Status.Mapped {
			mappedVal = 1.0
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "netapp_ontap_lun_state",
				Help:      "LUN state (1=online)",
				Type:      storagedef.MetricTypeGauge,
				Value:     stateVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_lun_mapped",
				Help:      "LUN mapped (1=mapped)",
				Type:      storagedef.MetricTypeGauge,
				Value:     mappedVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_lun_size_bytes",
				Help:      "LUN size in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(lun.Space.Size),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_lun_used_bytes",
				Help:      "LUN used space in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(lun.Space.Used),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			// Performance metrics
			storagedef.Metric{
				Name:      "netapp_ontap_lun_read_iops",
				Help:      "LUN read IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(lun.Metric.IOPS.Read),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_lun_write_iops",
				Help:      "LUN write IOPS",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(lun.Metric.IOPS.Write),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_lun_read_latency_us",
				Help:      "LUN read latency in microseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(lun.Metric.Latency.Read),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_lun_write_latency_us",
				Help:      "LUN write latency in microseconds",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(lun.Metric.Latency.Write),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)
	}

	return metrics, nil
}

// collectDiskMetrics collects disk-level metrics
func (c *ONTAPCollector) collectDiskMetrics(ctx context.Context, timestamp time.Time) ([]storagedef.Metric, error) {
	var response struct {
		Records []Disk `json:"records"`
	}
	if err := c.client.Get(ctx, "/api/storage/disks?fields=*", &response); err != nil {
		return nil, fmt.Errorf("failed to get disks: %w", err)
	}

	var metrics []storagedef.Metric

	for _, disk := range response.Records {
		labels := map[string]string{
			"disk_name":  disk.Name,
			"disk_uid":   disk.UID,
			"node_name":  disk.Node.Name,
			"disk_type":  disk.Type,
			"disk_class": disk.Class,
			"model":      disk.Model,
			"vendor":     disk.Vendor,
		}

		stateVal := 0.0
		if disk.State == "present" || disk.State == "spare" || disk.State == "partner" {
			stateVal = 1.0
		}

		metrics = append(metrics,
			storagedef.Metric{
				Name:      "netapp_ontap_disk_state",
				Help:      "Disk state (1=healthy)",
				Type:      storagedef.MetricTypeGauge,
				Value:     stateVal,
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
			storagedef.Metric{
				Name:      "netapp_ontap_disk_usable_size_bytes",
				Help:      "Disk usable size in bytes",
				Type:      storagedef.MetricTypeGauge,
				Value:     float64(disk.UsableSize),
				Labels:    copyLabels(labels),
				Timestamp: timestamp,
			},
		)

		if disk.RPM > 0 {
			metrics = append(metrics,
				storagedef.Metric{
					Name:      "netapp_ontap_disk_rpm",
					Help:      "Disk RPM (0 for SSD)",
					Type:      storagedef.MetricTypeGauge,
					Value:     float64(disk.RPM),
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
