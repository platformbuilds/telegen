// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package arista

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/platformbuilds/telegen/internal/netinfra/types"
)

// InventoryCollector collects device inventory from CloudVision
type InventoryCollector struct {
	cvp *CloudVisionCollector
}

// Device represents an Arista device in CloudVision
type Device struct {
	SystemMacAddress string `json:"systemMacAddress"`
	Hostname         string `json:"hostname"`
	FQDN             string `json:"fqdn"`
	SerialNumber     string `json:"serialNumber"`
	ModelName        string `json:"modelName"`
	Version          string `json:"version"`
	Status           string `json:"status"`
	StreamingStatus  string `json:"streamingStatus"`
	ContainerName    string `json:"containerName"`
	IPAddress        string `json:"ipAddress"`
	BootupTimestamp  int64  `json:"bootupTimestamp"`
	InternalVersion  string `json:"internalVersion"`
	ZtpMode          string `json:"ztpMode"`
	ComplianceCode   string `json:"complianceCode"`
}

// DeviceInventory represents the inventory response
type DeviceInventory struct {
	Devices []Device `json:"data"`
	Total   int      `json:"total"`
}

// NewInventoryCollector creates a new inventory collector
func NewInventoryCollector(cvp *CloudVisionCollector) *InventoryCollector {
	return &InventoryCollector{cvp: cvp}
}

// Collect gathers device inventory metrics
func (i *InventoryCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/cvpservice/inventory/devices", i.cvp.GetBaseURL())

	req, err := i.cvp.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := i.cvp.GetClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch inventory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inventory request failed with status: %d", resp.StatusCode)
	}

	var inventory DeviceInventory
	if err := json.NewDecoder(resp.Body).Decode(&inventory); err != nil {
		return nil, fmt.Errorf("failed to decode inventory: %w", err)
	}

	return i.buildMetrics(inventory), nil
}

// buildMetrics converts inventory data to metrics
func (i *InventoryCollector) buildMetrics(inventory DeviceInventory) []*types.NetworkMetric {
	var metrics []*types.NetworkMetric

	// Track counts by status and model
	statusCounts := make(map[string]int)
	modelCounts := make(map[string]int)
	versionCounts := make(map[string]int)

	for _, device := range inventory.Devices {
		statusCounts[device.Status]++
		modelCounts[device.ModelName]++
		versionCounts[device.Version]++

		labels := i.cvp.BaseLabels()
		labels["device"] = device.Hostname
		labels["model"] = device.ModelName
		labels["serial"] = device.SerialNumber
		labels["version"] = device.Version
		labels["container"] = device.ContainerName
		labels["status"] = device.Status
		labels["ip_address"] = device.IPAddress

		// Device health metric
		healthy := 0.0
		if device.Status == "Registered" {
			healthy = 1.0
		}
		metrics = append(metrics, types.NewMetric("arista_device_healthy", healthy, labels))

		// Streaming status metric
		streaming := 0.0
		if device.StreamingStatus == "Active" {
			streaming = 1.0
		}
		metrics = append(metrics, types.NewMetric("arista_device_streaming", streaming, labels))

		// ZTP mode metric
		ztpEnabled := 0.0
		if device.ZtpMode == "true" || device.ZtpMode == "enabled" {
			ztpEnabled = 1.0
		}
		metrics = append(metrics, types.NewMetric("arista_device_ztp_enabled", ztpEnabled, labels))

		// Uptime metric (if bootup timestamp is available)
		if device.BootupTimestamp > 0 {
			metrics = append(metrics, types.NewCounterMetric(
				"arista_device_boot_timestamp_seconds",
				float64(device.BootupTimestamp),
				labels,
			))
		}
	}

	// Add aggregated counts
	baseLabels := i.cvp.BaseLabels()

	// Total devices
	metrics = append(metrics, types.NewMetric(
		"arista_devices_total",
		float64(len(inventory.Devices)),
		baseLabels,
	))

	// Devices by status
	for status, count := range statusCounts {
		labels := i.cvp.BaseLabels()
		labels["status"] = status
		metrics = append(metrics, types.NewMetric(
			"arista_devices_by_status",
			float64(count),
			labels,
		))
	}

	// Devices by model
	for model, count := range modelCounts {
		labels := i.cvp.BaseLabels()
		labels["model"] = model
		metrics = append(metrics, types.NewMetric(
			"arista_devices_by_model",
			float64(count),
			labels,
		))
	}

	// Devices by EOS version
	for version, count := range versionCounts {
		labels := i.cvp.BaseLabels()
		labels["version"] = version
		metrics = append(metrics, types.NewMetric(
			"arista_devices_by_version",
			float64(count),
			labels,
		))
	}

	return metrics
}

// GetDevices fetches all devices from inventory
func (i *InventoryCollector) GetDevices(ctx context.Context) ([]Device, error) {
	url := fmt.Sprintf("%s/cvpservice/inventory/devices", i.cvp.GetBaseURL())

	req, err := i.cvp.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := i.cvp.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var inventory DeviceInventory
	if err := json.NewDecoder(resp.Body).Decode(&inventory); err != nil {
		return nil, err
	}

	return inventory.Devices, nil
}

// GetDeviceByHostname fetches a specific device
func (i *InventoryCollector) GetDeviceByHostname(ctx context.Context, hostname string) (*Device, error) {
	devices, err := i.GetDevices(ctx)
	if err != nil {
		return nil, err
	}

	for _, device := range devices {
		if device.Hostname == hostname {
			return &device, nil
		}
	}

	return nil, fmt.Errorf("device not found: %s", hostname)
}
