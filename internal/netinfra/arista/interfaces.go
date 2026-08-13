// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package arista

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/netinfra/types"
)

// InterfaceCollector collects interface metrics from CloudVision
type InterfaceCollector struct {
	cvp *CloudVisionCollector
}

// InterfaceStats represents interface statistics
type InterfaceStats struct {
	InterfaceName   string `json:"interfaceName"`
	DeviceID        string `json:"deviceId"`
	Description     string `json:"description"`
	OperStatus      string `json:"operStatus"`
	AdminStatus     string `json:"adminStatus"`
	Speed           int64  `json:"speed"`
	MTU             int    `json:"mtu"`
	Type            string `json:"type"`
	InOctets        int64  `json:"inOctets"`
	OutOctets       int64  `json:"outOctets"`
	InPackets       int64  `json:"inUcastPkts"`
	OutPackets      int64  `json:"outUcastPkts"`
	InErrors        int64  `json:"inErrors"`
	OutErrors       int64  `json:"outErrors"`
	InDiscards      int64  `json:"inDiscards"`
	OutDiscards     int64  `json:"outDiscards"`
	InBroadcast     int64  `json:"inBroadcastPkts"`
	OutBroadcast    int64  `json:"outBroadcastPkts"`
	InMulticast     int64  `json:"inMulticastPkts"`
	OutMulticast    int64  `json:"outMulticastPkts"`
	InUnknownProtos int64  `json:"inUnknownProtos"`
}

// InterfacesResponse represents the API response
type InterfacesResponse struct {
	Data []InterfaceStats `json:"data"`
}

// NewInterfaceCollector creates a new interface collector
func NewInterfaceCollector(cvp *CloudVisionCollector) *InterfaceCollector {
	return &InterfaceCollector{cvp: cvp}
}

// Collect gathers interface metrics
func (c *InterfaceCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	// Use the Resource API for interface data
	url := fmt.Sprintf("%s/api/resources/interface/v1/Interface/all", c.cvp.GetBaseURL())

	req, err := c.cvp.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.cvp.GetClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch interfaces: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("interfaces request failed with status: %d", resp.StatusCode)
	}

	var response InterfacesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode interfaces: %w", err)
	}

	// CVP interface stats carry no per-sample time, so one hoisted instant
	// stamps the whole cycle. The octet/packet counters below depend on it: a
	// smear divides their deltas by a wrong dt and corrupts every rate.
	return c.buildMetrics(response.Data, time.Now().UTC()), nil
}

// buildMetrics converts interface data to metrics
func (c *InterfaceCollector) buildMetrics(interfaces []InterfaceStats, timestamp time.Time) []*types.NetworkMetric {
	var metrics []*types.NetworkMetric

	// Track interface status counts
	operUpCount := 0
	operDownCount := 0
	adminUpCount := 0
	adminDownCount := 0

	for _, iface := range interfaces {
		labels := c.cvp.BaseLabels()
		labels["device"] = iface.DeviceID
		labels["interface"] = iface.InterfaceName
		labels["description"] = iface.Description
		labels["type"] = iface.Type

		// Operational status
		operUp := 0.0
		if iface.OperStatus == "up" {
			operUp = 1.0
			operUpCount++
		} else {
			operDownCount++
		}
		metrics = append(metrics, types.NewMetricAt("arista_interface_oper_status", operUp, labels, timestamp))

		// Admin status
		adminUp := 0.0
		if iface.AdminStatus == "up" {
			adminUp = 1.0
			adminUpCount++
		} else {
			adminDownCount++
		}
		metrics = append(metrics, types.NewMetricAt("arista_interface_admin_status", adminUp, labels, timestamp))

		// Speed
		metrics = append(metrics, types.NewMetricAt(
			"arista_interface_speed_bps",
			float64(iface.Speed),
			labels,
			timestamp,
		))

		// MTU
		metrics = append(metrics, types.NewMetricAt(
			"arista_interface_mtu",
			float64(iface.MTU),
			labels,
			timestamp,
		))

		// Traffic counters (as counters)
		metrics = append(metrics,
			types.NewCounterMetricAt("arista_interface_in_octets_total", float64(iface.InOctets), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_out_octets_total", float64(iface.OutOctets), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_in_packets_total", float64(iface.InPackets), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_out_packets_total", float64(iface.OutPackets), labels, timestamp),
		)

		// Error and discard counters
		metrics = append(metrics,
			types.NewCounterMetricAt("arista_interface_in_errors_total", float64(iface.InErrors), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_out_errors_total", float64(iface.OutErrors), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_in_discards_total", float64(iface.InDiscards), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_out_discards_total", float64(iface.OutDiscards), labels, timestamp),
		)

		// Broadcast/Multicast counters
		metrics = append(metrics,
			types.NewCounterMetricAt("arista_interface_in_broadcast_total", float64(iface.InBroadcast), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_out_broadcast_total", float64(iface.OutBroadcast), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_in_multicast_total", float64(iface.InMulticast), labels, timestamp),
			types.NewCounterMetricAt("arista_interface_out_multicast_total", float64(iface.OutMulticast), labels, timestamp),
		)

		// Unknown protocol counter
		metrics = append(metrics, types.NewCounterMetricAt(
			"arista_interface_in_unknown_protos_total",
			float64(iface.InUnknownProtos),
			labels,
			timestamp,
		))
	}

	// Add summary metrics
	baseLabels := c.cvp.BaseLabels()
	metrics = append(metrics,
		types.NewMetricAt("arista_interfaces_total", float64(len(interfaces)), baseLabels, timestamp),
		types.NewMetricAt("arista_interfaces_oper_up", float64(operUpCount), baseLabels, timestamp),
		types.NewMetricAt("arista_interfaces_oper_down", float64(operDownCount), baseLabels, timestamp),
		types.NewMetricAt("arista_interfaces_admin_up", float64(adminUpCount), baseLabels, timestamp),
		types.NewMetricAt("arista_interfaces_admin_down", float64(adminDownCount), baseLabels, timestamp),
	)

	return metrics
}

// GetInterfacesByDevice fetches interfaces for a specific device
func (c *InterfaceCollector) GetInterfacesByDevice(ctx context.Context, deviceID string) ([]InterfaceStats, error) {
	url := fmt.Sprintf("%s/api/resources/interface/v1/Interface/all?device=%s", c.cvp.GetBaseURL(), deviceID)

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

	var response InterfacesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.Data, nil
}
