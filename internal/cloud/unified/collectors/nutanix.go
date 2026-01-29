package collectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/cloud/unified"
)

// NutanixCollector collects metrics and resources from Nutanix Prism.
type NutanixCollector struct {
	config unified.NutanixConfig
	client *http.Client
	baseMu sync.RWMutex
}

// NewNutanixCollector creates a new Nutanix Prism collector.
func NewNutanixCollector(config unified.NutanixConfig) *NutanixCollector {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Insecure,
		},
	}

	return &NutanixCollector{
		config: config,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// CollectMetrics collects metrics from Nutanix Prism.
func (c *NutanixCollector) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	var metrics []unified.Metric
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Collect cluster metrics
	wg.Add(1)
	go func() {
		defer wg.Done()
		if clusterMetrics, err := c.collectClusterMetrics(ctx); err == nil {
			mu.Lock()
			metrics = append(metrics, clusterMetrics...)
			mu.Unlock()
		}
	}()

	// Collect host metrics
	wg.Add(1)
	go func() {
		defer wg.Done()
		if hostMetrics, err := c.collectHostMetrics(ctx); err == nil {
			mu.Lock()
			metrics = append(metrics, hostMetrics...)
			mu.Unlock()
		}
	}()

	// Collect VM metrics
	wg.Add(1)
	go func() {
		defer wg.Done()
		if vmMetrics, err := c.collectVMMetrics(ctx); err == nil {
			mu.Lock()
			metrics = append(metrics, vmMetrics...)
			mu.Unlock()
		}
	}()

	// Collect storage metrics
	wg.Add(1)
	go func() {
		defer wg.Done()
		if storageMetrics, err := c.collectStorageMetrics(ctx); err == nil {
			mu.Lock()
			metrics = append(metrics, storageMetrics...)
			mu.Unlock()
		}
	}()

	wg.Wait()
	return metrics, nil
}

// collectClusterMetrics collects Nutanix cluster metrics.
func (c *NutanixCollector) collectClusterMetrics(ctx context.Context) ([]unified.Metric, error) {
	data, err := c.doRequest(ctx, "/api/nutanix/v3/clusters/list", map[string]any{"kind": "cluster"})
	if err != nil {
		return nil, err
	}

	var resp nutanixListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	now := time.Now()

	for _, entity := range resp.Entities {
		clusterName := entity.Status.Name
		labels := map[string]string{
			"cluster":    clusterName,
			"cluster_id": entity.Metadata.UUID,
		}

		// Get cluster resources
		if entity.Status.Resources.Config != nil {
			config := entity.Status.Resources.Config

			if config.SoftwareMap != nil {
				for name, version := range config.SoftwareMap {
					metrics = append(metrics, unified.Metric{
						Name:      "nutanix.cluster.software_version",
						Type:      unified.MetricTypeGauge,
						Value:     1,
						Unit:      unified.MetricUnitCount,
						Timestamp: now,
						Labels: map[string]string{
							"cluster":  clusterName,
							"software": name,
							"version":  version,
						},
					})
				}
			}
		}

		// Get cluster stats
		if entity.Status.Resources.Stats != nil {
			stats := entity.Status.Resources.Stats

			if stats.HypervisorCPUUsagePPM > 0 {
				cpuPct := float64(stats.HypervisorCPUUsagePPM) / 10000
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.cluster.cpu.usage_percent",
					Type:      unified.MetricTypeGauge,
					Value:     cpuPct,
					Unit:      unified.MetricUnitPercent,
					Timestamp: now,
					Labels:    labels,
				})
			}

			if stats.HypervisorMemoryUsagePPM > 0 {
				memPct := float64(stats.HypervisorMemoryUsagePPM) / 10000
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.cluster.memory.usage_percent",
					Type:      unified.MetricTypeGauge,
					Value:     memPct,
					Unit:      unified.MetricUnitPercent,
					Timestamp: now,
					Labels:    labels,
				})
			}

			if stats.StorageUsageBytes > 0 {
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.cluster.storage.used_bytes",
					Type:      unified.MetricTypeGauge,
					Value:     float64(stats.StorageUsageBytes),
					Unit:      unified.MetricUnitBytes,
					Timestamp: now,
					Labels:    labels,
				})
			}

			if stats.StorageCapacityBytes > 0 {
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.cluster.storage.capacity_bytes",
					Type:      unified.MetricTypeGauge,
					Value:     float64(stats.StorageCapacityBytes),
					Unit:      unified.MetricUnitBytes,
					Timestamp: now,
					Labels:    labels,
				})
			}
		}
	}

	metrics = append(metrics, unified.Metric{
		Name:      "nutanix.cluster.total",
		Type:      unified.MetricTypeGauge,
		Value:     float64(len(resp.Entities)),
		Unit:      unified.MetricUnitCount,
		Timestamp: now,
		Labels:    map[string]string{},
	})

	return metrics, nil
}

// collectHostMetrics collects Nutanix host metrics.
func (c *NutanixCollector) collectHostMetrics(ctx context.Context) ([]unified.Metric, error) {
	data, err := c.doRequest(ctx, "/api/nutanix/v3/hosts/list", map[string]any{"kind": "host"})
	if err != nil {
		return nil, err
	}

	var resp nutanixListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	now := time.Now()

	stateCounts := make(map[string]int)
	var totalCPU, totalMemory int64

	for _, entity := range resp.Entities {
		hostName := entity.Status.Name
		stateCounts[entity.Status.State]++

		labels := map[string]string{
			"host":    hostName,
			"host_id": entity.Metadata.UUID,
		}

		// Get host resources
		if entity.Status.Resources.CPU != nil {
			cpu := entity.Status.Resources.CPU
			totalCPU += int64(cpu.NumSockets * cpu.NumCoresPerSocket)

			metrics = append(metrics,
				unified.Metric{
					Name:      "nutanix.host.cpu.sockets",
					Type:      unified.MetricTypeGauge,
					Value:     float64(cpu.NumSockets),
					Unit:      unified.MetricUnitCount,
					Timestamp: now,
					Labels:    labels,
				},
				unified.Metric{
					Name:      "nutanix.host.cpu.cores_per_socket",
					Type:      unified.MetricTypeGauge,
					Value:     float64(cpu.NumCoresPerSocket),
					Unit:      unified.MetricUnitCount,
					Timestamp: now,
					Labels:    labels,
				},
			)

			if cpu.Frequency > 0 {
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.host.cpu.frequency_hz",
					Type:      unified.MetricTypeGauge,
					Value:     float64(cpu.Frequency),
					Unit:      unified.MetricUnitCount,
					Timestamp: now,
					Labels:    labels,
				})
			}
		}

		if entity.Status.Resources.Memory != nil {
			mem := entity.Status.Resources.Memory
			totalMemory += mem.SizeBytes

			metrics = append(metrics, unified.Metric{
				Name:      "nutanix.host.memory.total_bytes",
				Type:      unified.MetricTypeGauge,
				Value:     float64(mem.SizeBytes),
				Unit:      unified.MetricUnitBytes,
				Timestamp: now,
				Labels:    labels,
			})
		}

		// Host stats
		if entity.Status.Resources.Stats != nil {
			stats := entity.Status.Resources.Stats

			if stats.HypervisorCPUUsagePPM > 0 {
				cpuPct := float64(stats.HypervisorCPUUsagePPM) / 10000
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.host.cpu.usage_percent",
					Type:      unified.MetricTypeGauge,
					Value:     cpuPct,
					Unit:      unified.MetricUnitPercent,
					Timestamp: now,
					Labels:    labels,
				})
			}

			if stats.HypervisorMemoryUsagePPM > 0 {
				memPct := float64(stats.HypervisorMemoryUsagePPM) / 10000
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.host.memory.usage_percent",
					Type:      unified.MetricTypeGauge,
					Value:     memPct,
					Unit:      unified.MetricUnitPercent,
					Timestamp: now,
					Labels:    labels,
				})
			}

			metrics = append(metrics, unified.Metric{
				Name:      "nutanix.host.vms.running",
				Type:      unified.MetricTypeGauge,
				Value:     float64(stats.NumVMs),
				Unit:      unified.MetricUnitCount,
				Timestamp: now,
				Labels:    labels,
			})
		}
	}

	for state, count := range stateCounts {
		metrics = append(metrics, unified.Metric{
			Name:      "nutanix.host.count",
			Type:      unified.MetricTypeGauge,
			Value:     float64(count),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{"state": state},
		})
	}

	metrics = append(metrics,
		unified.Metric{
			Name:      "nutanix.host.total",
			Type:      unified.MetricTypeGauge,
			Value:     float64(len(resp.Entities)),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "nutanix.host.cpu.total_cores",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalCPU),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "nutanix.host.memory.total_bytes",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalMemory),
			Unit:      unified.MetricUnitBytes,
			Timestamp: now,
			Labels:    map[string]string{},
		},
	)

	return metrics, nil
}

// collectVMMetrics collects Nutanix VM metrics.
func (c *NutanixCollector) collectVMMetrics(ctx context.Context) ([]unified.Metric, error) {
	data, err := c.doRequest(ctx, "/api/nutanix/v3/vms/list", map[string]any{"kind": "vm"})
	if err != nil {
		return nil, err
	}

	var resp nutanixListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	now := time.Now()

	stateCounts := make(map[string]int)
	var totalCPU, totalMemory int64

	for _, entity := range resp.Entities {
		stateCounts[entity.Status.State]++

		if entity.Status.Resources.CPU != nil {
			totalCPU += int64(entity.Status.Resources.CPU.NumVCPUs)
		}
		if entity.Status.Resources.Memory != nil {
			totalMemory += entity.Status.Resources.Memory.SizeMiB * 1024 * 1024
		}
	}

	for state, count := range stateCounts {
		metrics = append(metrics, unified.Metric{
			Name:      "nutanix.vm.count",
			Type:      unified.MetricTypeGauge,
			Value:     float64(count),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{"power_state": state},
		})
	}

	metrics = append(metrics,
		unified.Metric{
			Name:      "nutanix.vm.total",
			Type:      unified.MetricTypeGauge,
			Value:     float64(len(resp.Entities)),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "nutanix.vm.cpu.total_vcpus",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalCPU),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "nutanix.vm.memory.total_bytes",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalMemory),
			Unit:      unified.MetricUnitBytes,
			Timestamp: now,
			Labels:    map[string]string{},
		},
	)

	return metrics, nil
}

// collectStorageMetrics collects Nutanix storage container metrics.
func (c *NutanixCollector) collectStorageMetrics(ctx context.Context) ([]unified.Metric, error) {
	data, err := c.doRequest(ctx, "/api/nutanix/v3/storage_containers/list", map[string]any{"kind": "storage_container"})
	if err != nil {
		return nil, err
	}

	var resp nutanixListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	now := time.Now()

	var totalCapacity, totalUsed int64

	for _, entity := range resp.Entities {
		containerName := entity.Status.Name
		labels := map[string]string{
			"container":    containerName,
			"container_id": entity.Metadata.UUID,
		}

		if entity.Status.Resources.Stats != nil {
			stats := entity.Status.Resources.Stats

			if stats.StorageCapacityBytes > 0 {
				totalCapacity += stats.StorageCapacityBytes
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.storage_container.capacity_bytes",
					Type:      unified.MetricTypeGauge,
					Value:     float64(stats.StorageCapacityBytes),
					Unit:      unified.MetricUnitBytes,
					Timestamp: now,
					Labels:    labels,
				})
			}

			if stats.StorageUsageBytes > 0 {
				totalUsed += stats.StorageUsageBytes
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.storage_container.used_bytes",
					Type:      unified.MetricTypeGauge,
					Value:     float64(stats.StorageUsageBytes),
					Unit:      unified.MetricUnitBytes,
					Timestamp: now,
					Labels:    labels,
				})
			}

			if stats.StorageCapacityBytes > 0 && stats.StorageUsageBytes > 0 {
				usedPct := float64(stats.StorageUsageBytes) / float64(stats.StorageCapacityBytes) * 100
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.storage_container.used_percent",
					Type:      unified.MetricTypeGauge,
					Value:     usedPct,
					Unit:      unified.MetricUnitPercent,
					Timestamp: now,
					Labels:    labels,
				})
			}

			if stats.DeduplicationRatio > 0 {
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.storage_container.dedup_ratio",
					Type:      unified.MetricTypeGauge,
					Value:     stats.DeduplicationRatio,
					Unit:      unified.MetricUnitCount,
					Timestamp: now,
					Labels:    labels,
				})
			}

			if stats.CompressionRatio > 0 {
				metrics = append(metrics, unified.Metric{
					Name:      "nutanix.storage_container.compression_ratio",
					Type:      unified.MetricTypeGauge,
					Value:     stats.CompressionRatio,
					Unit:      unified.MetricUnitCount,
					Timestamp: now,
					Labels:    labels,
				})
			}
		}
	}

	metrics = append(metrics,
		unified.Metric{
			Name:      "nutanix.storage_container.total",
			Type:      unified.MetricTypeGauge,
			Value:     float64(len(resp.Entities)),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "nutanix.storage.total_capacity_bytes",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalCapacity),
			Unit:      unified.MetricUnitBytes,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "nutanix.storage.total_used_bytes",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalUsed),
			Unit:      unified.MetricUnitBytes,
			Timestamp: now,
			Labels:    map[string]string{},
		},
	)

	return metrics, nil
}

// DiscoverResources discovers Nutanix resources.
func (c *NutanixCollector) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	var resources []unified.Resource
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Discover VMs
	wg.Add(1)
	go func() {
		defer wg.Done()
		if vms, err := c.discoverVMs(ctx); err == nil {
			mu.Lock()
			resources = append(resources, vms...)
			mu.Unlock()
		}
	}()

	// Discover hosts
	wg.Add(1)
	go func() {
		defer wg.Done()
		if hosts, err := c.discoverHosts(ctx); err == nil {
			mu.Lock()
			resources = append(resources, hosts...)
			mu.Unlock()
		}
	}()

	// Discover storage containers
	wg.Add(1)
	go func() {
		defer wg.Done()
		if containers, err := c.discoverStorageContainers(ctx); err == nil {
			mu.Lock()
			resources = append(resources, containers...)
			mu.Unlock()
		}
	}()

	// Discover networks
	wg.Add(1)
	go func() {
		defer wg.Done()
		if networks, err := c.discoverNetworks(ctx); err == nil {
			mu.Lock()
			resources = append(resources, networks...)
			mu.Unlock()
		}
	}()

	wg.Wait()
	return resources, nil
}

// discoverVMs discovers Nutanix VMs.
func (c *NutanixCollector) discoverVMs(ctx context.Context) ([]unified.Resource, error) {
	data, err := c.doRequest(ctx, "/api/nutanix/v3/vms/list", map[string]any{"kind": "vm"})
	if err != nil {
		return nil, err
	}

	var resp nutanixListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var resources []unified.Resource
	for _, entity := range resp.Entities {
		resource := unified.Resource{
			ID:       entity.Metadata.UUID,
			Name:     entity.Status.Name,
			Type:     unified.ResourceTypeVM,
			Provider: "nutanix",
			Status:   entity.Status.State,
			Properties: map[string]any{
				"cluster_reference": entity.Status.ClusterReference,
				"host_reference":    entity.Status.HostReference,
			},
		}

		if entity.Status.Resources.CPU != nil {
			resource.Properties["num_vcpus"] = entity.Status.Resources.CPU.NumVCPUs
			resource.Properties["num_cores_per_vcpu"] = entity.Status.Resources.CPU.NumCoresPerVCPU
		}

		if entity.Status.Resources.Memory != nil {
			resource.Properties["memory_size_mib"] = entity.Status.Resources.Memory.SizeMiB
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// discoverHosts discovers Nutanix hosts.
func (c *NutanixCollector) discoverHosts(ctx context.Context) ([]unified.Resource, error) {
	data, err := c.doRequest(ctx, "/api/nutanix/v3/hosts/list", map[string]any{"kind": "host"})
	if err != nil {
		return nil, err
	}

	var resp nutanixListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var resources []unified.Resource
	for _, entity := range resp.Entities {
		resource := unified.Resource{
			ID:       entity.Metadata.UUID,
			Name:     entity.Status.Name,
			Type:     unified.ResourceTypeHost,
			Provider: "nutanix",
			Status:   entity.Status.State,
			Properties: map[string]any{
				"cluster_reference": entity.Status.ClusterReference,
				"hypervisor_type":   entity.Status.Resources.HypervisorType,
			},
		}

		if entity.Status.Resources.CPU != nil {
			resource.Properties["num_sockets"] = entity.Status.Resources.CPU.NumSockets
			resource.Properties["num_cores_per_socket"] = entity.Status.Resources.CPU.NumCoresPerSocket
		}

		if entity.Status.Resources.Memory != nil {
			resource.Properties["memory_size_bytes"] = entity.Status.Resources.Memory.SizeBytes
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// discoverStorageContainers discovers Nutanix storage containers.
func (c *NutanixCollector) discoverStorageContainers(ctx context.Context) ([]unified.Resource, error) {
	data, err := c.doRequest(ctx, "/api/nutanix/v3/storage_containers/list", map[string]any{"kind": "storage_container"})
	if err != nil {
		return nil, err
	}

	var resp nutanixListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var resources []unified.Resource
	for _, entity := range resp.Entities {
		resource := unified.Resource{
			ID:       entity.Metadata.UUID,
			Name:     entity.Status.Name,
			Type:     unified.ResourceTypeDatastore,
			Provider: "nutanix",
			Status:   entity.Status.State,
			Properties: map[string]any{
				"cluster_reference": entity.Status.ClusterReference,
			},
		}

		if entity.Status.Resources.Stats != nil {
			resource.Properties["capacity_bytes"] = entity.Status.Resources.Stats.StorageCapacityBytes
			resource.Properties["used_bytes"] = entity.Status.Resources.Stats.StorageUsageBytes
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// discoverNetworks discovers Nutanix networks.
func (c *NutanixCollector) discoverNetworks(ctx context.Context) ([]unified.Resource, error) {
	data, err := c.doRequest(ctx, "/api/nutanix/v3/subnets/list", map[string]any{"kind": "subnet"})
	if err != nil {
		return nil, err
	}

	var resp nutanixListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var resources []unified.Resource
	for _, entity := range resp.Entities {
		resource := unified.Resource{
			ID:       entity.Metadata.UUID,
			Name:     entity.Status.Name,
			Type:     unified.ResourceTypeNetwork,
			Provider: "nutanix",
			Status:   entity.Status.State,
			Properties: map[string]any{
				"cluster_reference": entity.Status.ClusterReference,
				"subnet_type":       entity.Status.Resources.SubnetType,
			},
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

// doRequest performs an authenticated request to Nutanix Prism.
func (c *NutanixCollector) doRequest(ctx context.Context, path string, body map[string]any) ([]byte, error) {
	url := fmt.Sprintf("https://%s:%d%s", c.config.PrismURL, c.config.Port, path)

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = &bytesReader{data: bodyBytes}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.config.Username, c.config.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %s - %s", resp.Status, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// Nutanix API response structures.
type nutanixListResponse struct {
	Entities []nutanixEntity `json:"entities"`
	Metadata nutanixMetadata `json:"metadata"`
}

type nutanixEntity struct {
	Metadata nutanixEntityMetadata `json:"metadata"`
	Status   nutanixEntityStatus   `json:"status"`
}

type nutanixEntityMetadata struct {
	UUID           string            `json:"uuid"`
	Kind           string            `json:"kind"`
	Categories     map[string]string `json:"categories,omitempty"`
	CreationTime   string            `json:"creation_time,omitempty"`
	LastUpdateTime string            `json:"last_update_time,omitempty"`
}

type nutanixEntityStatus struct {
	Name             string                 `json:"name"`
	State            string                 `json:"state"`
	ClusterReference *nutanixReference      `json:"cluster_reference,omitempty"`
	HostReference    *nutanixReference      `json:"host_reference,omitempty"`
	Resources        nutanixEntityResources `json:"resources"`
}

type nutanixReference struct {
	UUID string `json:"uuid"`
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

type nutanixEntityResources struct {
	// Cluster config
	Config *nutanixClusterConfig `json:"config,omitempty"`

	// CPU resources
	CPU *nutanixCPU `json:"cpu,omitempty"`

	// Memory resources
	Memory *nutanixMemory `json:"memory,omitempty"`

	// Stats
	Stats *nutanixStats `json:"stats,omitempty"`

	// Host-specific
	HypervisorType string `json:"hypervisor_type,omitempty"`

	// VM-specific
	NumVCPUs        int `json:"num_vcpus_per_socket,omitempty"`
	NumCoresPerVCPU int `json:"num_cores_per_vcpu,omitempty"`

	// Network-specific
	SubnetType string `json:"subnet_type,omitempty"`
}

type nutanixClusterConfig struct {
	SoftwareMap map[string]string `json:"software_map,omitempty"`
}

type nutanixCPU struct {
	NumSockets        int   `json:"num_sockets,omitempty"`
	NumCoresPerSocket int   `json:"num_cores_per_socket,omitempty"`
	NumVCPUs          int   `json:"num_vcpus,omitempty"`
	NumCoresPerVCPU   int   `json:"num_cores_per_vcpu,omitempty"`
	Frequency         int64 `json:"frequency_hz,omitempty"`
}

type nutanixMemory struct {
	SizeBytes int64 `json:"size_bytes,omitempty"`
	SizeMiB   int64 `json:"size_mib,omitempty"`
}

type nutanixStats struct {
	HypervisorCPUUsagePPM    int64   `json:"hypervisor_cpu_usage_ppm,omitempty"`
	HypervisorMemoryUsagePPM int64   `json:"hypervisor_memory_usage_ppm,omitempty"`
	StorageUsageBytes        int64   `json:"storage_user_bytes,omitempty"`
	StorageCapacityBytes     int64   `json:"storage_capacity_bytes,omitempty"`
	NumVMs                   int     `json:"num_vms,omitempty"`
	DeduplicationRatio       float64 `json:"dedup_ratio,omitempty"`
	CompressionRatio         float64 `json:"compression_ratio,omitempty"`
}

type nutanixMetadata struct {
	TotalMatches int `json:"total_matches"`
	Length       int `json:"length"`
	Offset       int `json:"offset"`
}
