package collectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/cloud/unified"
)

// VMwareCollector collects metrics and resources from VMware vSphere.
type VMwareCollector struct {
	config    unified.VMwareConfig
	client    *http.Client
	sessionID string
	sessionMu sync.RWMutex
}

// NewVMwareCollector creates a new VMware vSphere collector.
func NewVMwareCollector(config unified.VMwareConfig) *VMwareCollector {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Insecure,
		},
	}

	return &VMwareCollector{
		config: config,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// Authenticate authenticates with vCenter.
func (c *VMwareCollector) Authenticate(ctx context.Context) error {
	loginURL := fmt.Sprintf("https://%s/api/session", c.config.Address)

	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	req.SetBasicAuth(c.config.Username, c.config.Password)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed: %s - %s", resp.Status, string(body))
	}

	// Read session ID from response body (vSphere 7.0+ REST API)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read session response: %w", err)
	}

	sessionID := strings.Trim(string(body), "\"")

	c.sessionMu.Lock()
	c.sessionID = sessionID
	c.sessionMu.Unlock()

	return nil
}

// ensureAuthenticated ensures we have a valid session.
func (c *VMwareCollector) ensureAuthenticated(ctx context.Context) error {
	c.sessionMu.RLock()
	hasSession := c.sessionID != ""
	c.sessionMu.RUnlock()

	if hasSession {
		// Verify session is still valid
		if c.checkSession(ctx) {
			return nil
		}
	}

	return c.Authenticate(ctx)
}

// checkSession verifies the session is still valid.
func (c *VMwareCollector) checkSession(ctx context.Context) bool {
	sessionURL := fmt.Sprintf("https://%s/api/session", c.config.Address)

	req, err := http.NewRequestWithContext(ctx, "GET", sessionURL, nil)
	if err != nil {
		return false
	}

	c.sessionMu.RLock()
	req.Header.Set("vmware-api-session-id", c.sessionID)
	c.sessionMu.RUnlock()

	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// CollectMetrics collects metrics from vSphere.
func (c *VMwareCollector) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	var mu sync.Mutex
	var wg sync.WaitGroup

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

	// Collect datastore metrics
	wg.Add(1)
	go func() {
		defer wg.Done()
		if dsMetrics, err := c.collectDatastoreMetrics(ctx); err == nil {
			mu.Lock()
			metrics = append(metrics, dsMetrics...)
			mu.Unlock()
		}
	}()

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

	wg.Wait()
	return metrics, nil
}

// collectHostMetrics collects ESXi host metrics.
func (c *VMwareCollector) collectHostMetrics(ctx context.Context) ([]unified.Metric, error) {
	hosts, err := c.doRequest(ctx, "/api/vcenter/host")
	if err != nil {
		return nil, err
	}

	var hostList []vsphereHost
	if err := json.Unmarshal(hosts, &hostList); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	now := time.Now()

	// Count hosts by state
	stateCounts := make(map[string]int)
	connectionCounts := make(map[string]int)

	for _, host := range hostList {
		stateCounts[host.PowerState]++
		connectionCounts[host.ConnectionState]++
	}

	for state, count := range stateCounts {
		metrics = append(metrics, unified.Metric{
			Name:      "vmware.host.count",
			Type:      unified.MetricTypeGauge,
			Value:     float64(count),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{"power_state": state},
		})
	}

	for state, count := range connectionCounts {
		metrics = append(metrics, unified.Metric{
			Name:      "vmware.host.connection_state",
			Type:      unified.MetricTypeGauge,
			Value:     float64(count),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{"state": state},
		})
	}

	// Get detailed host information
	for _, host := range hostList {
		if host.ConnectionState != "CONNECTED" {
			continue
		}

		// Get host summary
		hostSummary, err := c.doRequest(ctx, fmt.Sprintf("/api/vcenter/host/%s", host.Host))
		if err != nil {
			continue
		}

		var summary vsphereHostSummary
		if err := json.Unmarshal(hostSummary, &summary); err != nil {
			continue
		}

		labels := map[string]string{
			"host":    host.Name,
			"host_id": host.Host,
		}

		// CPU metrics
		if summary.CPU.Cores > 0 {
			metrics = append(metrics,
				unified.Metric{
					Name:      "vmware.host.cpu.cores",
					Type:      unified.MetricTypeGauge,
					Value:     float64(summary.CPU.Cores),
					Unit:      unified.MetricUnitCount,
					Timestamp: now,
					Labels:    labels,
				},
				unified.Metric{
					Name:      "vmware.host.cpu.threads",
					Type:      unified.MetricTypeGauge,
					Value:     float64(summary.CPU.Threads),
					Unit:      unified.MetricUnitCount,
					Timestamp: now,
					Labels:    labels,
				},
			)
		}

		// Memory metrics
		if summary.Memory > 0 {
			metrics = append(metrics, unified.Metric{
				Name:      "vmware.host.memory.total_bytes",
				Type:      unified.MetricTypeGauge,
				Value:     float64(summary.Memory),
				Unit:      unified.MetricUnitBytes,
				Timestamp: now,
				Labels:    labels,
			})
		}
	}

	metrics = append(metrics, unified.Metric{
		Name:      "vmware.host.total",
		Type:      unified.MetricTypeGauge,
		Value:     float64(len(hostList)),
		Unit:      unified.MetricUnitCount,
		Timestamp: now,
		Labels:    map[string]string{},
	})

	return metrics, nil
}

// collectVMMetrics collects virtual machine metrics.
func (c *VMwareCollector) collectVMMetrics(ctx context.Context) ([]unified.Metric, error) {
	vms, err := c.doRequest(ctx, "/api/vcenter/vm")
	if err != nil {
		return nil, err
	}

	var vmList []vsphereVM
	if err := json.Unmarshal(vms, &vmList); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	now := time.Now()

	// Count VMs by power state
	stateCounts := make(map[string]int)
	var totalCPU, totalMemoryMB int

	for _, vm := range vmList {
		stateCounts[vm.PowerState]++
		totalCPU += vm.CPUCount
		totalMemoryMB += vm.MemorySizeMiB
	}

	for state, count := range stateCounts {
		metrics = append(metrics, unified.Metric{
			Name:      "vmware.vm.count",
			Type:      unified.MetricTypeGauge,
			Value:     float64(count),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{"power_state": state},
		})
	}

	metrics = append(metrics,
		unified.Metric{
			Name:      "vmware.vm.total",
			Type:      unified.MetricTypeGauge,
			Value:     float64(len(vmList)),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "vmware.vm.cpu.total_allocated",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalCPU),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "vmware.vm.memory.total_allocated_mb",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalMemoryMB),
			Unit:      unified.MetricUnitMegabytes,
			Timestamp: now,
			Labels:    map[string]string{},
		},
	)

	return metrics, nil
}

// collectDatastoreMetrics collects datastore metrics.
func (c *VMwareCollector) collectDatastoreMetrics(ctx context.Context) ([]unified.Metric, error) {
	datastores, err := c.doRequest(ctx, "/api/vcenter/datastore")
	if err != nil {
		return nil, err
	}

	var dsList []vsphereDatastore
	if err := json.Unmarshal(datastores, &dsList); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	now := time.Now()

	var totalCapacity, totalFree int64
	typeCounts := make(map[string]int)

	for _, ds := range dsList {
		typeCounts[ds.Type]++
		totalCapacity += ds.Capacity
		totalFree += ds.FreeSpace

		labels := map[string]string{
			"datastore": ds.Name,
			"type":      ds.Type,
		}

		metrics = append(metrics,
			unified.Metric{
				Name:      "vmware.datastore.capacity_bytes",
				Type:      unified.MetricTypeGauge,
				Value:     float64(ds.Capacity),
				Unit:      unified.MetricUnitBytes,
				Timestamp: now,
				Labels:    labels,
			},
			unified.Metric{
				Name:      "vmware.datastore.free_bytes",
				Type:      unified.MetricTypeGauge,
				Value:     float64(ds.FreeSpace),
				Unit:      unified.MetricUnitBytes,
				Timestamp: now,
				Labels:    labels,
			},
		)

		if ds.Capacity > 0 {
			usedPct := float64(ds.Capacity-ds.FreeSpace) / float64(ds.Capacity) * 100
			metrics = append(metrics, unified.Metric{
				Name:      "vmware.datastore.used_percent",
				Type:      unified.MetricTypeGauge,
				Value:     usedPct,
				Unit:      unified.MetricUnitPercent,
				Timestamp: now,
				Labels:    labels,
			})
		}
	}

	for dsType, count := range typeCounts {
		metrics = append(metrics, unified.Metric{
			Name:      "vmware.datastore.count",
			Type:      unified.MetricTypeGauge,
			Value:     float64(count),
			Unit:      unified.MetricUnitCount,
			Timestamp: now,
			Labels:    map[string]string{"type": dsType},
		})
	}

	metrics = append(metrics,
		unified.Metric{
			Name:      "vmware.datastore.total_capacity_bytes",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalCapacity),
			Unit:      unified.MetricUnitBytes,
			Timestamp: now,
			Labels:    map[string]string{},
		},
		unified.Metric{
			Name:      "vmware.datastore.total_free_bytes",
			Type:      unified.MetricTypeGauge,
			Value:     float64(totalFree),
			Unit:      unified.MetricUnitBytes,
			Timestamp: now,
			Labels:    map[string]string{},
		},
	)

	return metrics, nil
}

// collectClusterMetrics collects cluster metrics.
func (c *VMwareCollector) collectClusterMetrics(ctx context.Context) ([]unified.Metric, error) {
	clusters, err := c.doRequest(ctx, "/api/vcenter/cluster")
	if err != nil {
		return nil, err
	}

	var clusterList []vsphereCluster
	if err := json.Unmarshal(clusters, &clusterList); err != nil {
		return nil, err
	}

	var metrics []unified.Metric
	now := time.Now()

	for _, cluster := range clusterList {
		labels := map[string]string{
			"cluster": cluster.Name,
		}

		haEnabled := 0
		if cluster.HAEnabled {
			haEnabled = 1
		}

		drsEnabled := 0
		if cluster.DRSEnabled {
			drsEnabled = 1
		}

		metrics = append(metrics,
			unified.Metric{
				Name:      "vmware.cluster.ha_enabled",
				Type:      unified.MetricTypeGauge,
				Value:     float64(haEnabled),
				Unit:      unified.MetricUnitCount,
				Timestamp: now,
				Labels:    labels,
			},
			unified.Metric{
				Name:      "vmware.cluster.drs_enabled",
				Type:      unified.MetricTypeGauge,
				Value:     float64(drsEnabled),
				Unit:      unified.MetricUnitCount,
				Timestamp: now,
				Labels:    labels,
			},
		)
	}

	metrics = append(metrics, unified.Metric{
		Name:      "vmware.cluster.total",
		Type:      unified.MetricTypeGauge,
		Value:     float64(len(clusterList)),
		Unit:      unified.MetricUnitCount,
		Timestamp: now,
		Labels:    map[string]string{},
	})

	return metrics, nil
}

// DiscoverResources discovers VMware resources.
func (c *VMwareCollector) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, err
	}

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

	// Discover datastores
	wg.Add(1)
	go func() {
		defer wg.Done()
		if datastores, err := c.discoverDatastores(ctx); err == nil {
			mu.Lock()
			resources = append(resources, datastores...)
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

// discoverVMs discovers virtual machines.
func (c *VMwareCollector) discoverVMs(ctx context.Context) ([]unified.Resource, error) {
	data, err := c.doRequest(ctx, "/api/vcenter/vm")
	if err != nil {
		return nil, err
	}

	var vmList []vsphereVM
	if err := json.Unmarshal(data, &vmList); err != nil {
		return nil, err
	}

	var resources []unified.Resource
	for _, vm := range vmList {
		resource := unified.Resource{
			ID:       vm.VM,
			Name:     vm.Name,
			Type:     unified.ResourceTypeVM,
			Provider: "vmware",
			Status:   vm.PowerState,
			Attributes: map[string]any{
				"cpu_count":       vm.CPUCount,
				"memory_size_mib": vm.MemorySizeMiB,
				"power_state":     vm.PowerState,
			},
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

// discoverHosts discovers ESXi hosts.
func (c *VMwareCollector) discoverHosts(ctx context.Context) ([]unified.Resource, error) {
	data, err := c.doRequest(ctx, "/api/vcenter/host")
	if err != nil {
		return nil, err
	}

	var hostList []vsphereHost
	if err := json.Unmarshal(data, &hostList); err != nil {
		return nil, err
	}

	var resources []unified.Resource
	for _, host := range hostList {
		resource := unified.Resource{
			ID:       host.Host,
			Name:     host.Name,
			Type:     unified.ResourceTypeHost,
			Provider: "vmware",
			Status:   host.ConnectionState,
			Attributes: map[string]any{
				"power_state":      host.PowerState,
				"connection_state": host.ConnectionState,
			},
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

// discoverDatastores discovers datastores.
func (c *VMwareCollector) discoverDatastores(ctx context.Context) ([]unified.Resource, error) {
	data, err := c.doRequest(ctx, "/api/vcenter/datastore")
	if err != nil {
		return nil, err
	}

	var dsList []vsphereDatastore
	if err := json.Unmarshal(data, &dsList); err != nil {
		return nil, err
	}

	var resources []unified.Resource
	for _, ds := range dsList {
		resource := unified.Resource{
			ID:       ds.Datastore,
			Name:     ds.Name,
			Type:     unified.ResourceTypeDatastore,
			Provider: "vmware",
			Attributes: map[string]any{
				"type":       ds.Type,
				"capacity":   ds.Capacity,
				"free_space": ds.FreeSpace,
			},
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

// discoverNetworks discovers networks.
func (c *VMwareCollector) discoverNetworks(ctx context.Context) ([]unified.Resource, error) {
	data, err := c.doRequest(ctx, "/api/vcenter/network")
	if err != nil {
		return nil, err
	}

	var networkList []vsphereNetwork
	if err := json.Unmarshal(data, &networkList); err != nil {
		return nil, err
	}

	var resources []unified.Resource
	for _, net := range networkList {
		resource := unified.Resource{
			ID:       net.Network,
			Name:     net.Name,
			Type:     unified.ResourceTypeNetwork,
			Provider: "vmware",
			Attributes: map[string]any{
				"type": net.Type,
			},
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

// doRequest performs an authenticated request to vCenter.
func (c *VMwareCollector) doRequest(ctx context.Context, path string) ([]byte, error) {
	baseURL := fmt.Sprintf("https://%s", c.config.Address)
	reqURL, err := url.Parse(baseURL + path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	if err != nil {
		return nil, err
	}

	c.sessionMu.RLock()
	req.Header.Set("vmware-api-session-id", c.sessionID)
	c.sessionMu.RUnlock()

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %s - %s", resp.Status, string(body))
	}

	return io.ReadAll(resp.Body)
}

// Logout logs out from vCenter.
func (c *VMwareCollector) Logout(ctx context.Context) error {
	c.sessionMu.RLock()
	sessionID := c.sessionID
	c.sessionMu.RUnlock()

	if sessionID == "" {
		return nil
	}

	logoutURL := fmt.Sprintf("https://%s/api/session", c.config.Address)
	req, err := http.NewRequestWithContext(ctx, "DELETE", logoutURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("vmware-api-session-id", sessionID)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	c.sessionMu.Lock()
	c.sessionID = ""
	c.sessionMu.Unlock()

	return nil
}

// vSphere API response structures.
type vsphereHost struct {
	Host            string `json:"host"`
	Name            string `json:"name"`
	ConnectionState string `json:"connection_state"`
	PowerState      string `json:"power_state"`
}

type vsphereHostSummary struct {
	Name   string         `json:"name"`
	CPU    vsphereHostCPU `json:"cpu"`
	Memory int64          `json:"memory_size_bytes"`
}

type vsphereHostCPU struct {
	Cores   int `json:"core_count"`
	Threads int `json:"thread_count"`
}

type vsphereVM struct {
	VM            string `json:"vm"`
	Name          string `json:"name"`
	PowerState    string `json:"power_state"`
	CPUCount      int    `json:"cpu_count"`
	MemorySizeMiB int    `json:"memory_size_MiB"`
}

type vsphereDatastore struct {
	Datastore string `json:"datastore"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Capacity  int64  `json:"capacity"`
	FreeSpace int64  `json:"free_space"`
}

type vsphereNetwork struct {
	Network string `json:"network"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

type vsphereCluster struct {
	Cluster    string `json:"cluster"`
	Name       string `json:"name"`
	HAEnabled  bool   `json:"ha_enabled"`
	DRSEnabled bool   `json:"drs_enabled"`
}
