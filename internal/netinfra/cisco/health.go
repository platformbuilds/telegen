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

// HealthCollector collects fabric health metrics from ACI
type HealthCollector struct {
	aci *ACICollector
}

// FabricHealth represents overall fabric health
type FabricHealth struct {
	HealthAvg string `json:"healthAvg"`
	HealthMax string `json:"healthMax"`
	HealthMin string `json:"healthMin"`
}

// NewHealthCollector creates a new health collector
func NewHealthCollector(aci *ACICollector) *HealthCollector {
	return &HealthCollector{aci: aci}
}

// CollectFabricHealth collects overall fabric health metrics
func (c *HealthCollector) CollectFabricHealth(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/class/fabricHealthTotal.json", c.aci.GetBaseURL())

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
			FabricHealthTotal struct {
				Attributes FabricHealth `json:"attributes"`
			} `json:"fabricHealthTotal"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric
	labels := c.aci.BaseLabels()

	if len(result.Imdata) > 0 {
		health := result.Imdata[0].FabricHealthTotal.Attributes
		metrics = append(metrics,
			types.NewMetric("aci_fabric_health_avg", parseFloat(health.HealthAvg), labels),
			types.NewMetric("aci_fabric_health_max", parseFloat(health.HealthMax), labels),
			types.NewMetric("aci_fabric_health_min", parseFloat(health.HealthMin), labels),
		)
	}

	// Get pod health
	podHealth, err := c.collectPodHealth(ctx)
	if err != nil {
		c.aci.log.Warn("failed to collect pod health", "error", err)
	} else {
		metrics = append(metrics, podHealth...)
	}

	return metrics, nil
}

// collectPodHealth collects health per pod
func (c *HealthCollector) collectPodHealth(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/class/fabricPod.json?rsp-subtree-include=health", c.aci.GetBaseURL())

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
			FabricPod struct {
				Attributes struct {
					ID string `json:"id"`
				} `json:"attributes"`
				Children []struct {
					HealthInst struct {
						Attributes struct {
							Cur string `json:"cur"`
						} `json:"attributes"`
					} `json:"healthInst"`
				} `json:"children"`
			} `json:"fabricPod"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric

	for _, item := range result.Imdata {
		pod := item.FabricPod
		labels := c.aci.BaseLabels()
		labels["pod"] = pod.Attributes.ID

		for _, child := range pod.Children {
			if child.HealthInst.Attributes.Cur != "" {
				metrics = append(metrics, types.NewMetric(
					"aci_pod_health",
					parseFloat(child.HealthInst.Attributes.Cur),
					labels,
				))
				break
			}
		}
	}

	return metrics, nil
}

// CollectSystemHealth collects system-wide health metrics
func (c *HealthCollector) CollectSystemHealth(ctx context.Context) ([]*types.NetworkMetric, error) {
	var metrics []*types.NetworkMetric

	// Get capacity metrics
	capacity, err := c.collectCapacity(ctx)
	if err != nil {
		c.aci.log.Warn("failed to collect capacity", "error", err)
	} else {
		metrics = append(metrics, capacity...)
	}

	return metrics, nil
}

// collectCapacity collects capacity/utilization metrics
func (c *HealthCollector) collectCapacity(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/class/eqptCapacity.json", c.aci.GetBaseURL())

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
			EqptCapacity struct {
				Attributes struct {
					DN           string `json:"dn"`
					TcamEntryCur string `json:"tcamEntryCur"`
					TcamEntryMax string `json:"tcamEntryMax"`
					TcamEntryPct string `json:"tcamEntryPct"`
				} `json:"attributes"`
			} `json:"eqptCapacity"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric

	for _, item := range result.Imdata {
		cap := item.EqptCapacity.Attributes
		nodeID := extractNodeID(cap.DN)

		labels := c.aci.BaseLabels()
		labels["node"] = nodeID

		metrics = append(metrics,
			types.NewMetric("aci_tcam_entries_current", parseFloat(cap.TcamEntryCur), labels),
			types.NewMetric("aci_tcam_entries_max", parseFloat(cap.TcamEntryMax), labels),
			types.NewMetric("aci_tcam_utilization_percent", parseFloat(cap.TcamEntryPct), labels),
		)
	}

	return metrics, nil
}
