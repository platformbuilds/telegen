// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cisco

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/platformbuilds/telegen/internal/netinfra/types"
)

// TenantCollector collects tenant and EPG metrics from ACI
type TenantCollector struct {
	aci *ACICollector
}

// Tenant represents an ACI tenant
type Tenant struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Description string `json:"descr"`
	OwnerKey    string `json:"ownerKey"`
	OwnerTag    string `json:"ownerTag"`
}

// TenantHealth represents tenant health information
type TenantHealth struct {
	TenantName  string
	HealthScore float64
	MaxSeverity string
}

// EPG represents an Endpoint Group
type EPG struct {
	DN           string `json:"dn"`
	Name         string `json:"name"`
	TenantName   string
	AppProfile   string
	Description  string `json:"descr"`
	ConfigIssues string `json:"configIssues"`
	FloodOnEncap string `json:"floodOnEncap"`
	MatchT       string `json:"matchT"`
	PCEnfPref    string `json:"pcEnfPref"`
	PrefGrMemb   string `json:"prefGrMemb"`
}

// EPGHealth represents EPG health information
type EPGHealth struct {
	EPGName     string
	TenantName  string
	AppProfile  string
	HealthScore float64
	MaxSeverity string
}

// NewTenantCollector creates a new tenant collector
func NewTenantCollector(aci *ACICollector) *TenantCollector {
	return &TenantCollector{aci: aci}
}

// CollectTenantHealth collects tenant health metrics
func (c *TenantCollector) CollectTenantHealth(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/class/fvTenant.json?rsp-subtree-include=health", c.aci.GetBaseURL())

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
			FvTenant struct {
				Attributes Tenant `json:"attributes"`
				Children   []struct {
					HealthInst struct {
						Attributes struct {
							Cur    string `json:"cur"`
							MaxSev string `json:"maxSev"`
						} `json:"attributes"`
					} `json:"healthInst"`
				} `json:"children"`
			} `json:"fvTenant"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric

	for _, item := range result.Imdata {
		tenant := item.FvTenant.Attributes
		labels := c.aci.BaseLabels()
		labels["tenant"] = tenant.Name
		labels["description"] = tenant.Description

		// Find health
		for _, child := range item.FvTenant.Children {
			if child.HealthInst.Attributes.Cur != "" {
				healthScore := parseFloat(child.HealthInst.Attributes.Cur)
				labels["max_severity"] = child.HealthInst.Attributes.MaxSev
				metrics = append(metrics, types.NewMetric("aci_tenant_health", healthScore, labels))
				break
			}
		}
	}

	// Summary metric
	baseLabels := c.aci.BaseLabels()
	metrics = append(metrics, types.NewMetric("aci_tenants_total", float64(len(result.Imdata)), baseLabels))

	return metrics, nil
}

// CollectEPGHealth collects EPG health metrics
func (c *TenantCollector) CollectEPGHealth(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/class/fvAEPg.json?rsp-subtree-include=health", c.aci.GetBaseURL())

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
			FvAEPg struct {
				Attributes EPG `json:"attributes"`
				Children   []struct {
					HealthInst struct {
						Attributes struct {
							Cur    string `json:"cur"`
							MaxSev string `json:"maxSev"`
						} `json:"attributes"`
					} `json:"healthInst"`
				} `json:"children"`
			} `json:"fvAEPg"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric
	epgCount := 0

	for _, item := range result.Imdata {
		epg := item.FvAEPg.Attributes
		epgCount++

		// Parse DN to extract tenant and app profile
		tenant, appProfile := parseDN(epg.DN)

		labels := c.aci.BaseLabels()
		labels["tenant"] = tenant
		labels["app_profile"] = appProfile
		labels["epg"] = epg.Name
		labels["description"] = epg.Description

		// Find health
		for _, child := range item.FvAEPg.Children {
			if child.HealthInst.Attributes.Cur != "" {
				healthScore := parseFloat(child.HealthInst.Attributes.Cur)
				labels["max_severity"] = child.HealthInst.Attributes.MaxSev
				metrics = append(metrics, types.NewMetric("aci_epg_health", healthScore, labels))
				break
			}
		}
	}

	// Summary metric
	baseLabels := c.aci.BaseLabels()
	metrics = append(metrics, types.NewMetric("aci_epgs_total", float64(epgCount), baseLabels))

	return metrics, nil
}

// CollectEndpoints collects endpoint count metrics
func (c *TenantCollector) CollectEndpoints(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/class/fvCEp.json?rsp-subtree-include=count", c.aci.GetBaseURL())

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
			MoCount struct {
				Attributes struct {
					Count string `json:"count"`
				} `json:"attributes"`
			} `json:"moCount"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var metrics []*types.NetworkMetric
	baseLabels := c.aci.BaseLabels()

	if len(result.Imdata) > 0 {
		count := parseFloat(result.Imdata[0].MoCount.Attributes.Count)
		metrics = append(metrics, types.NewMetric("aci_endpoints_total", count, baseLabels))
	}

	return metrics, nil
}

// GetTenants returns all tenants
func (c *TenantCollector) GetTenants(ctx context.Context) ([]Tenant, error) {
	url := fmt.Sprintf("%s/api/class/fvTenant.json", c.aci.GetBaseURL())

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
			FvTenant struct {
				Attributes Tenant `json:"attributes"`
			} `json:"fvTenant"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	tenants := make([]Tenant, 0, len(result.Imdata))
	for _, item := range result.Imdata {
		tenants = append(tenants, item.FvTenant.Attributes)
	}

	return tenants, nil
}

// parseDN extracts tenant and app profile from DN
// Example DN: uni/tn-{tenant}/ap-{app}/epg-{epg}
func parseDN(dn string) (tenant, appProfile string) {
	// Simple parsing - in production use regex
	var parts []string
	start := 0
	for i := 0; i < len(dn); i++ {
		if dn[i] == '/' {
			parts = append(parts, dn[start:i])
			start = i + 1
		}
	}
	parts = append(parts, dn[start:])

	for _, part := range parts {
		if len(part) > 3 && part[:3] == "tn-" {
			tenant = part[3:]
		}
		if len(part) > 3 && part[:3] == "ap-" {
			appProfile = part[3:]
		}
	}

	return tenant, appProfile
}
