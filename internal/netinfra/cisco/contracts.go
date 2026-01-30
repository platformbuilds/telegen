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

// ContractCollector collects contract statistics from ACI
type ContractCollector struct {
	aci *ACICollector
}

// Contract represents an ACI contract
type Contract struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Scope       string `json:"scope"`
	TargetDscp  string `json:"targetDscp"`
	Description string `json:"descr"`
	OwnerKey    string `json:"ownerKey"`
	OwnerTag    string `json:"ownerTag"`
}

// ContractSubject represents a contract subject
type ContractSubject struct {
	DN           string `json:"dn"`
	Name         string `json:"name"`
	ContractDN   string
	Description  string `json:"descr"`
	ProvMatchT   string `json:"provMatchT"`
	ConsMatchT   string `json:"consMatchT"`
	RevFiltPorts string `json:"revFltPorts"`
}

// FilterEntry represents a filter entry
type FilterEntry struct {
	DN         string `json:"dn"`
	Name       string `json:"name"`
	FilterName string
	EtherType  string `json:"etherT"`
	Protocol   string `json:"prot"`
	DFromPort  string `json:"dFromPort"`
	DToPort    string `json:"dToPort"`
	SFromPort  string `json:"sFromPort"`
	SToPort    string `json:"sToPort"`
	TCPRules   string `json:"tcpRules"`
	Stateful   string `json:"stateful"`
}

// ContractStats represents contract hit statistics
type ContractStats struct {
	DN            string `json:"dn"`
	PermitBytes   string `json:"permitBytes"`
	PermitPackets string `json:"permitPkts"`
	DenyBytes     string `json:"denyBytes"`
	DenyPackets   string `json:"denyPkts"`
}

// NewContractCollector creates a new contract collector
func NewContractCollector(aci *ACICollector) *ContractCollector {
	return &ContractCollector{aci: aci}
}

// Collect gathers contract metrics
func (c *ContractCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	var allMetrics []*types.NetworkMetric

	// Get contracts
	contracts, err := c.getContracts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get contracts: %w", err)
	}

	// Get contract stats
	stats, err := c.getContractStats(ctx)
	if err != nil {
		c.aci.log.Warn("failed to get contract stats", "error", err)
		stats = make(map[string]ContractStats)
	}

	// Build metrics
	allMetrics = append(allMetrics, c.buildMetrics(contracts, stats)...)

	return allMetrics, nil
}

// getContracts fetches all contracts
func (c *ContractCollector) getContracts(ctx context.Context) ([]Contract, error) {
	url := fmt.Sprintf("%s/api/class/vzBrCP.json", c.aci.GetBaseURL())

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
			VzBrCP struct {
				Attributes Contract `json:"attributes"`
			} `json:"vzBrCP"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	contracts := make([]Contract, 0, len(result.Imdata))
	for _, item := range result.Imdata {
		contracts = append(contracts, item.VzBrCP.Attributes)
	}

	return contracts, nil
}

// getContractStats fetches contract hit statistics
func (c *ContractCollector) getContractStats(ctx context.Context) (map[string]ContractStats, error) {
	url := fmt.Sprintf("%s/api/class/actrlRuleHit5min.json", c.aci.GetBaseURL())

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
			ActrlRuleHit5min struct {
				Attributes ContractStats `json:"attributes"`
			} `json:"actrlRuleHit5min"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	stats := make(map[string]ContractStats)
	for _, item := range result.Imdata {
		stats[item.ActrlRuleHit5min.Attributes.DN] = item.ActrlRuleHit5min.Attributes
	}

	return stats, nil
}

// buildMetrics converts contract data to metrics
func (c *ContractCollector) buildMetrics(contracts []Contract, stats map[string]ContractStats) []*types.NetworkMetric {
	var metrics []*types.NetworkMetric

	// Count by scope
	scopeCounts := make(map[string]int)

	for _, contract := range contracts {
		scopeCounts[contract.Scope]++

		// Extract tenant from DN
		tenant, _ := parseDN(contract.DN)

		labels := c.aci.BaseLabels()
		labels["tenant"] = tenant
		labels["contract"] = contract.Name
		labels["scope"] = contract.Scope

		// Contract exists metric
		metrics = append(metrics, types.NewMetric("aci_contract_info", 1.0, labels))
	}

	// Add stats from contract rules
	for _, stat := range stats {
		labels := c.aci.BaseLabels()
		labels["rule_dn"] = stat.DN

		metrics = append(metrics,
			types.NewCounterMetric("aci_contract_permit_bytes_total", parseFloat(stat.PermitBytes), labels),
			types.NewCounterMetric("aci_contract_permit_packets_total", parseFloat(stat.PermitPackets), labels),
			types.NewCounterMetric("aci_contract_deny_bytes_total", parseFloat(stat.DenyBytes), labels),
			types.NewCounterMetric("aci_contract_deny_packets_total", parseFloat(stat.DenyPackets), labels),
		)
	}

	// Summary metrics
	baseLabels := c.aci.BaseLabels()
	metrics = append(metrics, types.NewMetric("aci_contracts_total", float64(len(contracts)), baseLabels))

	// Contracts by scope
	for scope, count := range scopeCounts {
		labels := c.aci.BaseLabels()
		labels["scope"] = scope
		metrics = append(metrics, types.NewMetric("aci_contracts_by_scope", float64(count), labels))
	}

	return metrics
}

// GetContracts returns all contracts
func (c *ContractCollector) GetContracts(ctx context.Context) ([]Contract, error) {
	return c.getContracts(ctx)
}

// GetFilterEntries returns filter entries for a contract
func (c *ContractCollector) GetFilterEntries(ctx context.Context, contractDN string) ([]FilterEntry, error) {
	url := fmt.Sprintf("%s/api/mo/%s.json?rsp-subtree=full&rsp-subtree-class=vzEntry",
		c.aci.GetBaseURL(), contractDN)

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
			VzEntry struct {
				Attributes FilterEntry `json:"attributes"`
			} `json:"vzEntry"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	entries := make([]FilterEntry, 0, len(result.Imdata))
	for _, item := range result.Imdata {
		entries = append(entries, item.VzEntry.Attributes)
	}

	return entries, nil
}
