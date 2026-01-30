// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cisco

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/platformbuilds/telegen/internal/netinfra/types"
)

// FaultCollector collects fault metrics from ACI
type FaultCollector struct {
	aci *ACICollector
}

// Fault represents an ACI fault
type Fault struct {
	DN          string `json:"dn"`
	Code        string `json:"code"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Cause       string `json:"cause"`
	Description string `json:"descr"`
	Domain      string `json:"domain"`
	Subject     string `json:"subject"`
	Created     string `json:"created"`
	LastChanged string `json:"lastTransition"`
	LifeCycle   string `json:"lc"`
	Rule        string `json:"rule"`
	Ack         string `json:"ack"`
}

// NewFaultCollector creates a new fault collector
func NewFaultCollector(aci *ACICollector) *FaultCollector {
	return &FaultCollector{aci: aci}
}

// Collect gathers fault metrics
func (c *FaultCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/class/faultInst.json?query-target-filter=eq(faultInst.lc,\"raised\")", c.aci.GetBaseURL())

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
			FaultInst struct {
				Attributes Fault `json:"attributes"`
			} `json:"faultInst"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	faults := make([]Fault, 0, len(result.Imdata))
	for _, item := range result.Imdata {
		faults = append(faults, item.FaultInst.Attributes)
	}

	return c.buildMetrics(faults), nil
}

// buildMetrics converts fault data to metrics
func (c *FaultCollector) buildMetrics(faults []Fault) []*types.NetworkMetric {
	var metrics []*types.NetworkMetric

	// Count faults by severity
	severityCounts := make(map[string]int)
	domainCounts := make(map[string]int)
	typeCounts := make(map[string]int)
	acknowledgedCount := 0

	for _, fault := range faults {
		severityCounts[fault.Severity]++
		domainCounts[fault.Domain]++
		typeCounts[fault.Type]++

		if fault.Ack == "yes" {
			acknowledgedCount++
		}

		// Individual fault metrics for critical and major faults
		if fault.Severity == "critical" || fault.Severity == "major" {
			labels := c.aci.BaseLabels()
			labels["code"] = fault.Code
			labels["severity"] = fault.Severity
			labels["domain"] = fault.Domain
			labels["subject"] = fault.Subject
			labels["cause"] = fault.Cause
			labels["type"] = fault.Type
			labels["acknowledged"] = fault.Ack

			// Calculate age
			age := c.calculateFaultAge(fault.Created)
			metrics = append(metrics, types.NewMetric(
				"aci_fault_age_seconds",
				age.Seconds(),
				labels,
			))

			// Fault present metric
			metrics = append(metrics, types.NewMetric(
				"aci_fault_active",
				1.0,
				labels,
			))
		}
	}

	// Summary metrics
	baseLabels := c.aci.BaseLabels()
	metrics = append(metrics,
		types.NewMetric("aci_faults_total", float64(len(faults)), baseLabels),
		types.NewMetric("aci_faults_acknowledged", float64(acknowledgedCount), baseLabels),
		types.NewMetric("aci_faults_unacknowledged", float64(len(faults)-acknowledgedCount), baseLabels),
	)

	// Faults by severity
	for severity, count := range severityCounts {
		labels := c.aci.BaseLabels()
		labels["severity"] = severity
		metrics = append(metrics, types.NewMetric("aci_faults_by_severity", float64(count), labels))
	}

	// Faults by domain
	for domain, count := range domainCounts {
		labels := c.aci.BaseLabels()
		labels["domain"] = domain
		metrics = append(metrics, types.NewMetric("aci_faults_by_domain", float64(count), labels))
	}

	// Faults by type
	for faultType, count := range typeCounts {
		labels := c.aci.BaseLabels()
		labels["type"] = faultType
		metrics = append(metrics, types.NewMetric("aci_faults_by_type", float64(count), labels))
	}

	return metrics
}

// calculateFaultAge calculates the age of a fault
func (c *FaultCollector) calculateFaultAge(created string) time.Duration {
	if created == "" {
		return 0
	}

	// ACI timestamp format: 2024-01-15T10:30:00.000+00:00
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		// Try alternative format
		t, err = time.Parse("2006-01-02T15:04:05.000-07:00", created)
		if err != nil {
			return 0
		}
	}

	return time.Since(t)
}

// GetActiveFaults returns all active faults
func (c *FaultCollector) GetActiveFaults(ctx context.Context) ([]Fault, error) {
	url := fmt.Sprintf("%s/api/class/faultInst.json?query-target-filter=eq(faultInst.lc,\"raised\")", c.aci.GetBaseURL())

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
			FaultInst struct {
				Attributes Fault `json:"attributes"`
			} `json:"faultInst"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	faults := make([]Fault, 0, len(result.Imdata))
	for _, item := range result.Imdata {
		faults = append(faults, item.FaultInst.Attributes)
	}

	return faults, nil
}

// GetFaultsBySeverity returns faults filtered by severity
func (c *FaultCollector) GetFaultsBySeverity(ctx context.Context, severity string) ([]Fault, error) {
	url := fmt.Sprintf("%s/api/class/faultInst.json?query-target-filter=and(eq(faultInst.lc,\"raised\"),eq(faultInst.severity,\"%s\"))",
		c.aci.GetBaseURL(), severity)

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
			FaultInst struct {
				Attributes Fault `json:"attributes"`
			} `json:"faultInst"`
		} `json:"imdata"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	faults := make([]Fault, 0, len(result.Imdata))
	for _, item := range result.Imdata {
		faults = append(faults, item.FaultInst.Attributes)
	}

	return faults, nil
}
