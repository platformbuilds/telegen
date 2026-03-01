// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cisco

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mirastacklabs-ai/telegen/internal/netinfra/types"
)

// InterfaceCollector collects interface statistics from ACI
type InterfaceCollector struct {
	aci *ACICollector
}

// PhysInterface represents a physical interface
type PhysInterface struct {
	DN          string `json:"dn"`
	ID          string `json:"id"`
	AdminState  string `json:"adminSt"`
	OperState   string `json:"operSt"`
	Speed       string `json:"speed"`
	Mode        string `json:"mode"`
	MTU         string `json:"mtu"`
	Usage       string `json:"usage"`
	Layer       string `json:"layer"`
	RouterMac   string `json:"routerMac"`
	SwitchingSt string `json:"switchingSt"`
}

// InterfaceCounters represents interface traffic counters
type InterfaceCounters struct {
	DN        string `json:"dn"`
	RxBytes   string `json:"bytesRcvd"`
	TxBytes   string `json:"bytesSent"`
	RxPackets string `json:"pktsRcvd"`
	TxPackets string `json:"pktsSent"`
	RxUcast   string `json:"ucastPktsRcvd"`
	TxUcast   string `json:"ucastPktsSent"`
	RxMcast   string `json:"multicastPktsRcvd"`
	TxMcast   string `json:"multicastPktsSent"`
	RxBcast   string `json:"broadcastPktsRcvd"`
	TxBcast   string `json:"broadcastPktsSent"`
}

// InterfaceErrors represents interface error counters
type InterfaceErrors struct {
	DN             string `json:"dn"`
	CRCErrors      string `json:"crcErrors"`
	InErrors       string `json:"inErrors"`
	OutErrors      string `json:"outErrors"`
	InDiscards     string `json:"inDiscards"`
	OutDiscards    string `json:"outDiscards"`
	CollisionCount string `json:"collisions"`
	CarrierErrors  string `json:"carrierSenseErrors"`
	Giants         string `json:"oversizedPkts"`
	Runts          string `json:"undersizedPkts"`
}

// NewInterfaceCollector creates a new interface collector
func NewInterfaceCollector(aci *ACICollector) *InterfaceCollector {
	return &InterfaceCollector{aci: aci}
}

// Collect gathers interface metrics
func (c *InterfaceCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	var allMetrics []*types.NetworkMetric

	// Get interface states
	interfaces, err := c.getInterfaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	// Get interface counters
	counters, err := c.getInterfaceCounters(ctx)
	if err != nil {
		c.aci.log.Warn("failed to get interface counters", "error", err)
		counters = make(map[string]InterfaceCounters)
	}

	// Get interface errors
	errors, err := c.getInterfaceErrors(ctx)
	if err != nil {
		c.aci.log.Warn("failed to get interface errors", "error", err)
		errors = make(map[string]InterfaceErrors)
	}

	// Build metrics
	allMetrics = append(allMetrics, c.buildMetrics(interfaces, counters, errors)...)

	return allMetrics, nil
}

// getInterfaces fetches all physical interfaces
func (c *InterfaceCollector) getInterfaces(ctx context.Context) ([]PhysInterface, error) {
	url := fmt.Sprintf("%s/api/class/l1PhysIf.json", c.aci.GetBaseURL())

	req, err := c.aci.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.aci.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Imdata []struct {
			L1PhysIf struct {
				Attributes PhysInterface `json:"attributes"`
			} `json:"l1PhysIf"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	interfaces := make([]PhysInterface, 0, len(result.Imdata))
	for _, item := range result.Imdata {
		interfaces = append(interfaces, item.L1PhysIf.Attributes)
	}

	return interfaces, nil
}

// getInterfaceCounters fetches interface traffic counters
func (c *InterfaceCollector) getInterfaceCounters(ctx context.Context) (map[string]InterfaceCounters, error) {
	url := fmt.Sprintf("%s/api/class/rmonEtherStats.json", c.aci.GetBaseURL())

	req, err := c.aci.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.aci.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Imdata []struct {
			RmonEtherStats struct {
				Attributes InterfaceCounters `json:"attributes"`
			} `json:"rmonEtherStats"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	counters := make(map[string]InterfaceCounters)
	for _, item := range result.Imdata {
		counters[item.RmonEtherStats.Attributes.DN] = item.RmonEtherStats.Attributes
	}

	return counters, nil
}

// getInterfaceErrors fetches interface error counters
func (c *InterfaceCollector) getInterfaceErrors(ctx context.Context) (map[string]InterfaceErrors, error) {
	url := fmt.Sprintf("%s/api/class/rmonIfIn.json", c.aci.GetBaseURL())

	req, err := c.aci.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.aci.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Imdata []struct {
			RmonIfIn struct {
				Attributes InterfaceErrors `json:"attributes"`
			} `json:"rmonIfIn"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	errors := make(map[string]InterfaceErrors)
	for _, item := range result.Imdata {
		errors[item.RmonIfIn.Attributes.DN] = item.RmonIfIn.Attributes
	}

	return errors, nil
}

// buildMetrics converts interface data to metrics
func (c *InterfaceCollector) buildMetrics(interfaces []PhysInterface, counters map[string]InterfaceCounters, errors map[string]InterfaceErrors) []*types.NetworkMetric {
	var metrics []*types.NetworkMetric

	operUpCount := 0
	operDownCount := 0

	for _, iface := range interfaces {
		// Extract node ID from DN
		nodeID := extractNodeID(iface.DN)

		labels := c.aci.BaseLabels()
		labels["node"] = nodeID
		labels["interface"] = iface.ID
		labels["speed"] = iface.Speed
		labels["mode"] = iface.Mode
		labels["usage"] = iface.Usage
		labels["layer"] = iface.Layer

		// Operational status
		operUp := 0.0
		if iface.OperState == "up" {
			operUp = 1.0
			operUpCount++
		} else {
			operDownCount++
		}
		metrics = append(metrics, types.NewMetric("aci_interface_oper_status", operUp, labels))

		// Admin status
		adminUp := 0.0
		if iface.AdminState == "up" {
			adminUp = 1.0
		}
		metrics = append(metrics, types.NewMetric("aci_interface_admin_status", adminUp, labels))

		// MTU
		mtu := parseFloat(iface.MTU)
		if mtu > 0 {
			metrics = append(metrics, types.NewMetric("aci_interface_mtu", mtu, labels))
		}

		// Find matching counters
		for counterDN, counter := range counters {
			if dnMatches(counterDN, iface.DN) {
				metrics = append(metrics,
					types.NewCounterMetric("aci_interface_rx_bytes_total", parseFloat(counter.RxBytes), labels),
					types.NewCounterMetric("aci_interface_tx_bytes_total", parseFloat(counter.TxBytes), labels),
					types.NewCounterMetric("aci_interface_rx_packets_total", parseFloat(counter.RxPackets), labels),
					types.NewCounterMetric("aci_interface_tx_packets_total", parseFloat(counter.TxPackets), labels),
					types.NewCounterMetric("aci_interface_rx_unicast_total", parseFloat(counter.RxUcast), labels),
					types.NewCounterMetric("aci_interface_tx_unicast_total", parseFloat(counter.TxUcast), labels),
					types.NewCounterMetric("aci_interface_rx_multicast_total", parseFloat(counter.RxMcast), labels),
					types.NewCounterMetric("aci_interface_tx_multicast_total", parseFloat(counter.TxMcast), labels),
					types.NewCounterMetric("aci_interface_rx_broadcast_total", parseFloat(counter.RxBcast), labels),
					types.NewCounterMetric("aci_interface_tx_broadcast_total", parseFloat(counter.TxBcast), labels),
				)
				break
			}
		}

		// Find matching errors
		for errorDN, errStats := range errors {
			if dnMatches(errorDN, iface.DN) {
				metrics = append(metrics,
					types.NewCounterMetric("aci_interface_crc_errors_total", parseFloat(errStats.CRCErrors), labels),
					types.NewCounterMetric("aci_interface_in_errors_total", parseFloat(errStats.InErrors), labels),
					types.NewCounterMetric("aci_interface_out_errors_total", parseFloat(errStats.OutErrors), labels),
					types.NewCounterMetric("aci_interface_in_discards_total", parseFloat(errStats.InDiscards), labels),
					types.NewCounterMetric("aci_interface_out_discards_total", parseFloat(errStats.OutDiscards), labels),
					types.NewCounterMetric("aci_interface_giants_total", parseFloat(errStats.Giants), labels),
					types.NewCounterMetric("aci_interface_runts_total", parseFloat(errStats.Runts), labels),
				)
				break
			}
		}
	}

	// Summary metrics
	baseLabels := c.aci.BaseLabels()
	metrics = append(metrics,
		types.NewMetric("aci_interfaces_total", float64(len(interfaces)), baseLabels),
		types.NewMetric("aci_interfaces_oper_up", float64(operUpCount), baseLabels),
		types.NewMetric("aci_interfaces_oper_down", float64(operDownCount), baseLabels),
	)

	return metrics
}

// extractNodeID extracts the node ID from a DN
// Example: topology/pod-1/node-101/sys/phys-[eth1/1]
func extractNodeID(dn string) string {
	// Simple parsing
	for i := 0; i < len(dn)-5; i++ {
		if dn[i:i+5] == "node-" {
			end := i + 5
			for end < len(dn) && dn[end] != '/' {
				end++
			}
			return dn[i+5 : end]
		}
	}
	return "unknown"
}

// dnMatches checks if two DNs refer to the same interface
func dnMatches(dn1, dn2 string) bool {
	// Simple check - in production use proper DN parsing
	return len(dn1) > 0 && len(dn2) > 0 &&
		(contains(dn1, dn2) || contains(dn2, dn1))
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
