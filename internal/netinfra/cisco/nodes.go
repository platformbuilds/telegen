// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cisco

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/platformbuilds/telegen/internal/netinfra/types"
)

// NodeCollector collects fabric node metrics from ACI
type NodeCollector struct {
	aci *ACICollector
}

// FabricNode represents an ACI fabric node (spine/leaf)
type FabricNode struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	ID          string `json:"id"`
	Role        string `json:"role"`
	Model       string `json:"model"`
	Serial      string `json:"serial"`
	Version     string `json:"version"`
	FabricState string `json:"fabricSt"`
	OOBMgmtAddr string `json:"oobMgmtAddr"`
	AdminState  string `json:"adminSt"`
	OperState   string `json:"operSt"`
}

// NodeHealth represents node health information
type NodeHealth struct {
	DN     string `json:"dn"`
	Health string `json:"cur"`
	ChgPct string `json:"chgPct"`
	MaxSev string `json:"maxSev"`
}

// NodeStats represents node statistics
type NodeStats struct {
	DN            string `json:"dn"`
	CPUUsage      string `json:"cpuUsage"`
	MemoryUsed    string `json:"memoryUsed"`
	MemoryTotal   string `json:"memoryAvailable"`
	MemoryUtilPct string `json:"memoryUsedPct"`
}

// NewNodeCollector creates a new node collector
func NewNodeCollector(aci *ACICollector) *NodeCollector {
	return &NodeCollector{aci: aci}
}

// Collect gathers fabric node metrics
func (c *NodeCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	var allMetrics []*types.NetworkMetric

	// Collect node inventory
	nodes, err := c.getNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get nodes: %w", err)
	}

	// Collect node health
	healthMap, err := c.getNodeHealth(ctx)
	if err != nil {
		c.aci.log.Warn("failed to get node health", "error", err)
		healthMap = make(map[string]NodeHealth)
	}

	// Build metrics
	allMetrics = append(allMetrics, c.buildMetrics(nodes, healthMap)...)

	return allMetrics, nil
}

// getNodes fetches all fabric nodes
func (c *NodeCollector) getNodes(ctx context.Context) ([]FabricNode, error) {
	url := fmt.Sprintf("%s/api/class/fabricNode.json", c.aci.GetBaseURL())

	req, err := c.aci.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.aci.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Imdata []struct {
			FabricNode struct {
				Attributes FabricNode `json:"attributes"`
			} `json:"fabricNode"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	nodes := make([]FabricNode, 0, len(result.Imdata))
	for _, item := range result.Imdata {
		nodes = append(nodes, item.FabricNode.Attributes)
	}

	return nodes, nil
}

// getNodeHealth fetches health for all nodes
func (c *NodeCollector) getNodeHealth(ctx context.Context) (map[string]NodeHealth, error) {
	url := fmt.Sprintf("%s/api/class/fabricNode.json?rsp-subtree-include=health", c.aci.GetBaseURL())

	req, err := c.aci.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.aci.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Imdata []struct {
			FabricNode struct {
				Attributes struct {
					DN string `json:"dn"`
				} `json:"attributes"`
				Children []struct {
					HealthInst struct {
						Attributes NodeHealth `json:"attributes"`
					} `json:"healthInst"`
				} `json:"children"`
			} `json:"fabricNode"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	healthMap := make(map[string]NodeHealth)
	for _, item := range result.Imdata {
		dn := item.FabricNode.Attributes.DN
		for _, child := range item.FabricNode.Children {
			if child.HealthInst.Attributes.Health != "" {
				healthMap[dn] = child.HealthInst.Attributes
				break
			}
		}
	}

	return healthMap, nil
}

// buildMetrics converts node data to metrics
func (c *NodeCollector) buildMetrics(nodes []FabricNode, healthMap map[string]NodeHealth) []*types.NetworkMetric {
	var metrics []*types.NetworkMetric

	// Track counts by role
	roleCounts := make(map[string]int)
	stateUp := 0
	stateDown := 0

	for _, node := range nodes {
		roleCounts[node.Role]++

		labels := c.aci.BaseLabels()
		labels["node"] = node.Name
		labels["node_id"] = node.ID
		labels["role"] = node.Role
		labels["model"] = node.Model
		labels["serial"] = node.Serial
		labels["version"] = node.Version

		// Node state metric
		up := 0.0
		if node.FabricState == "active" {
			up = 1.0
			stateUp++
		} else {
			stateDown++
		}
		metrics = append(metrics, types.NewMetric("aci_node_up", up, labels))

		// Admin state
		adminUp := 0.0
		if node.AdminState == "in-service" {
			adminUp = 1.0
		}
		metrics = append(metrics, types.NewMetric("aci_node_admin_state", adminUp, labels))

		// Health score
		if health, ok := healthMap[node.DN]; ok {
			healthScore := parseFloat(health.Health)
			metrics = append(metrics, types.NewMetric("aci_node_health", healthScore, labels))
		}
	}

	// Summary metrics
	baseLabels := c.aci.BaseLabels()
	metrics = append(metrics,
		types.NewMetric("aci_nodes_total", float64(len(nodes)), baseLabels),
		types.NewMetric("aci_nodes_up", float64(stateUp), baseLabels),
		types.NewMetric("aci_nodes_down", float64(stateDown), baseLabels),
	)

	// Nodes by role
	for role, count := range roleCounts {
		labels := c.aci.BaseLabels()
		labels["role"] = role
		metrics = append(metrics, types.NewMetric("aci_nodes_by_role", float64(count), labels))
	}

	return metrics
}

// GetNodes returns all fabric nodes
func (c *NodeCollector) GetNodes(ctx context.Context) ([]FabricNode, error) {
	return c.getNodes(ctx)
}

// parseFloat safely parses a string to float64
func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}
