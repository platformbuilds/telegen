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

// SystemCollector collects system resource metrics from CloudVision
type SystemCollector struct {
	cvp *CloudVisionCollector
}

// SystemStats represents system resource statistics
type SystemStats struct {
	DeviceID          string  `json:"deviceId"`
	Hostname          string  `json:"hostname"`
	CPUUtilization    float64 `json:"cpuUtilization"`
	MemoryTotal       int64   `json:"memoryTotal"`
	MemoryUsed        int64   `json:"memoryUsed"`
	MemoryFree        int64   `json:"memoryFree"`
	MemoryUtilization float64 `json:"memoryUtilization"`
	SystemUptime      int64   `json:"uptime"`
	BootTime          int64   `json:"bootTime"`
	ProcessCount      int     `json:"processCount"`
}

// TemperatureSensor represents a temperature sensor reading
type TemperatureSensor struct {
	DeviceID     string  `json:"deviceId"`
	SensorName   string  `json:"sensorName"`
	Temperature  float64 `json:"temperature"`
	AlertStatus  string  `json:"alertStatus"`
	MaxThreshold float64 `json:"maxThreshold"`
	Description  string  `json:"description"`
}

// PowerSupply represents power supply status
type PowerSupply struct {
	DeviceID      string  `json:"deviceId"`
	Name          string  `json:"name"`
	Status        string  `json:"status"`
	InputVoltage  float64 `json:"inputVoltage"`
	OutputVoltage float64 `json:"outputVoltage"`
	OutputPower   float64 `json:"outputPower"`
	Model         string  `json:"model"`
}

// Fan represents fan status
type Fan struct {
	DeviceID  string  `json:"deviceId"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Speed     int     `json:"speed"`
	SpeedPct  float64 `json:"speedPercent"`
	Direction string  `json:"direction"`
}

// SystemStatsResponse represents the API response
type SystemStatsResponse struct {
	Data []SystemStats `json:"data"`
}

// TemperatureResponse represents temperature API response
type TemperatureResponse struct {
	Data []TemperatureSensor `json:"data"`
}

// PowerSupplyResponse represents power supply API response
type PowerSupplyResponse struct {
	Data []PowerSupply `json:"data"`
}

// FanResponse represents fan API response
type FanResponse struct {
	Data []Fan `json:"data"`
}

// NewSystemCollector creates a new system collector
func NewSystemCollector(cvp *CloudVisionCollector) *SystemCollector {
	return &SystemCollector{cvp: cvp}
}

// Collect gathers system resource metrics
func (c *SystemCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	var allMetrics []*types.NetworkMetric

	// Collect CPU/Memory metrics
	cpuMem, err := c.collectCPUMemory(ctx)
	if err != nil {
		c.cvp.log.Warn("failed to collect CPU/memory metrics", "error", err)
	} else {
		allMetrics = append(allMetrics, cpuMem...)
	}

	// Collect temperature metrics
	temps, err := c.collectTemperature(ctx)
	if err != nil {
		c.cvp.log.Warn("failed to collect temperature metrics", "error", err)
	} else {
		allMetrics = append(allMetrics, temps...)
	}

	// Collect power supply metrics
	power, err := c.collectPowerSupply(ctx)
	if err != nil {
		c.cvp.log.Warn("failed to collect power supply metrics", "error", err)
	} else {
		allMetrics = append(allMetrics, power...)
	}

	// Collect fan metrics
	fans, err := c.collectFans(ctx)
	if err != nil {
		c.cvp.log.Warn("failed to collect fan metrics", "error", err)
	} else {
		allMetrics = append(allMetrics, fans...)
	}

	return allMetrics, nil
}

// collectCPUMemory collects CPU and memory utilization
func (c *SystemCollector) collectCPUMemory(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/resources/system/v1/SystemStats/all", c.cvp.GetBaseURL())

	req, err := c.cvp.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.cvp.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var response SystemStatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric

	for _, stats := range response.Data {
		labels := c.cvp.BaseLabels()
		labels["device"] = stats.DeviceID
		labels["hostname"] = stats.Hostname

		// CPU utilization
		metrics = append(metrics, types.NewMetric(
			"arista_cpu_utilization_percent",
			stats.CPUUtilization,
			labels,
		))

		// Memory metrics
		metrics = append(metrics,
			types.NewMetric("arista_memory_total_bytes", float64(stats.MemoryTotal), labels),
			types.NewMetric("arista_memory_used_bytes", float64(stats.MemoryUsed), labels),
			types.NewMetric("arista_memory_free_bytes", float64(stats.MemoryFree), labels),
			types.NewMetric("arista_memory_utilization_percent", stats.MemoryUtilization, labels),
		)

		// Uptime
		metrics = append(metrics, types.NewCounterMetric(
			"arista_system_uptime_seconds",
			float64(stats.SystemUptime),
			labels,
		))

		// Process count
		metrics = append(metrics, types.NewMetric(
			"arista_process_count",
			float64(stats.ProcessCount),
			labels,
		))
	}

	return metrics, nil
}

// collectTemperature collects temperature sensor metrics
func (c *SystemCollector) collectTemperature(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/resources/environment/v1/Temperature/all", c.cvp.GetBaseURL())

	req, err := c.cvp.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.cvp.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var response TemperatureResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric

	for _, sensor := range response.Data {
		labels := c.cvp.BaseLabels()
		labels["device"] = sensor.DeviceID
		labels["sensor"] = sensor.SensorName
		labels["description"] = sensor.Description

		// Temperature reading
		metrics = append(metrics, types.NewMetric(
			"arista_temperature_celsius",
			sensor.Temperature,
			labels,
		))

		// Alert status
		alertActive := 0.0
		if sensor.AlertStatus == "alert" || sensor.AlertStatus == "critical" {
			alertActive = 1.0
		}
		metrics = append(metrics, types.NewMetric(
			"arista_temperature_alert",
			alertActive,
			labels,
		))

		// Threshold
		if sensor.MaxThreshold > 0 {
			metrics = append(metrics, types.NewMetric(
				"arista_temperature_threshold_celsius",
				sensor.MaxThreshold,
				labels,
			))
		}
	}

	return metrics, nil
}

// collectPowerSupply collects power supply metrics
func (c *SystemCollector) collectPowerSupply(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/resources/environment/v1/PowerSupply/all", c.cvp.GetBaseURL())

	req, err := c.cvp.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.cvp.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var response PowerSupplyResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric

	for _, psu := range response.Data {
		labels := c.cvp.BaseLabels()
		labels["device"] = psu.DeviceID
		labels["psu"] = psu.Name
		labels["model"] = psu.Model

		// Status (1 = ok, 0 = not ok)
		statusOk := 0.0
		if psu.Status == "ok" || psu.Status == "powerOutput" {
			statusOk = 1.0
		}
		metrics = append(metrics, types.NewMetric(
			"arista_power_supply_status",
			statusOk,
			labels,
		))

		// Power metrics
		metrics = append(metrics,
			types.NewMetric("arista_power_supply_input_voltage", psu.InputVoltage, labels),
			types.NewMetric("arista_power_supply_output_voltage", psu.OutputVoltage, labels),
			types.NewMetric("arista_power_supply_output_watts", psu.OutputPower, labels),
		)
	}

	return metrics, nil
}

// collectFans collects fan metrics
func (c *SystemCollector) collectFans(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/resources/environment/v1/Fan/all", c.cvp.GetBaseURL())

	req, err := c.cvp.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.cvp.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var response FanResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric

	for _, fan := range response.Data {
		labels := c.cvp.BaseLabels()
		labels["device"] = fan.DeviceID
		labels["fan"] = fan.Name
		labels["direction"] = fan.Direction

		// Status
		statusOk := 0.0
		if fan.Status == "ok" {
			statusOk = 1.0
		}
		metrics = append(metrics, types.NewMetric(
			"arista_fan_status",
			statusOk,
			labels,
		))

		// Speed metrics
		metrics = append(metrics,
			types.NewMetric("arista_fan_speed_rpm", float64(fan.Speed), labels),
			types.NewMetric("arista_fan_speed_percent", fan.SpeedPct, labels),
		)
	}

	return metrics, nil
}
