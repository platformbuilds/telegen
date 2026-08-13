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

// BGPCollector collects BGP session metrics from CloudVision
type BGPCollector struct {
	cvp *CloudVisionCollector
}

// BGPSession represents a BGP session
type BGPSession struct {
	DeviceID         string `json:"deviceId"`
	NeighborAddress  string `json:"neighborAddr"`
	NeighborHostname string `json:"neighborHostname,omitempty"`
	PeerAS           int64  `json:"peerAs"`
	LocalAS          int64  `json:"localAs"`
	State            string `json:"state"`
	VRF              string `json:"vrf"`
	AFI              string `json:"afi"`
	SAFI             string `json:"safi"`
	PrefixesReceived int64  `json:"prefixesReceived"`
	PrefixesSent     int64  `json:"prefixesSent"`
	PrefixesAccepted int64  `json:"prefixesAccepted"`
	EstablishedTime  int64  `json:"establishedTime"`
	UpdatesReceived  int64  `json:"updatesReceived"`
	UpdatesSent      int64  `json:"updatesSent"`
	KeepalivesSent   int64  `json:"keepalivesSent"`
	KeepalivesRecv   int64  `json:"keepalivesRecv"`
	HoldTime         int    `json:"holdTime"`
	KeepaliveTime    int    `json:"keepaliveTime"`
	Description      string `json:"description,omitempty"`
}

// BGPResponse represents the API response
type BGPResponse struct {
	Data []BGPSession `json:"data"`
}

// NewBGPCollector creates a new BGP collector
func NewBGPCollector(cvp *CloudVisionCollector) *BGPCollector {
	return &BGPCollector{cvp: cvp}
}

// Collect gathers BGP session metrics
func (c *BGPCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	url := fmt.Sprintf("%s/api/resources/routing/bgp/v1/BGPPeerSession/all", c.cvp.GetBaseURL())

	req, err := c.cvp.auth.CreateAuthenticatedRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.cvp.GetClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch BGP sessions: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("BGP request failed with status: %d", resp.StatusCode)
	}

	var response BGPResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode BGP sessions: %w", err)
	}

	// CVP BGP session objects carry no per-sample time, so one hoisted instant
	// stamps the whole cycle. The update/keepalive counters below depend on it:
	// a smear divides their deltas by a wrong dt and corrupts every rate.
	return c.buildMetrics(response.Data, time.Now().UTC()), nil
}

// buildMetrics converts BGP session data to metrics
func (c *BGPCollector) buildMetrics(sessions []BGPSession, timestamp time.Time) []*types.NetworkMetric {
	var metrics []*types.NetworkMetric

	// Track state counts
	stateCounts := make(map[string]int)
	establishedCount := 0

	for _, session := range sessions {
		stateCounts[session.State]++

		labels := c.cvp.BaseLabels()
		labels["device"] = session.DeviceID
		labels["neighbor"] = session.NeighborAddress
		labels["vrf"] = session.VRF
		labels["peer_as"] = fmt.Sprintf("%d", session.PeerAS)
		labels["local_as"] = fmt.Sprintf("%d", session.LocalAS)
		labels["state"] = session.State
		labels["afi"] = session.AFI
		labels["safi"] = session.SAFI
		if session.NeighborHostname != "" {
			labels["neighbor_hostname"] = session.NeighborHostname
		}

		// Session established metric
		established := 0.0
		if session.State == "Established" {
			established = 1.0
			establishedCount++
		}
		metrics = append(metrics, types.NewMetricAt("arista_bgp_session_established", established, labels, timestamp))

		// Prefix metrics
		metrics = append(metrics,
			types.NewMetricAt("arista_bgp_prefixes_received", float64(session.PrefixesReceived), labels, timestamp),
			types.NewMetricAt("arista_bgp_prefixes_sent", float64(session.PrefixesSent), labels, timestamp),
			types.NewMetricAt("arista_bgp_prefixes_accepted", float64(session.PrefixesAccepted), labels, timestamp),
		)

		// Update counters
		metrics = append(metrics,
			types.NewCounterMetricAt("arista_bgp_updates_received_total", float64(session.UpdatesReceived), labels, timestamp),
			types.NewCounterMetricAt("arista_bgp_updates_sent_total", float64(session.UpdatesSent), labels, timestamp),
		)

		// Keepalive counters
		metrics = append(metrics,
			types.NewCounterMetricAt("arista_bgp_keepalives_sent_total", float64(session.KeepalivesSent), labels, timestamp),
			types.NewCounterMetricAt("arista_bgp_keepalives_received_total", float64(session.KeepalivesRecv), labels, timestamp),
		)

		// Timer configuration
		metrics = append(metrics,
			types.NewMetricAt("arista_bgp_hold_time_seconds", float64(session.HoldTime), labels, timestamp),
			types.NewMetricAt("arista_bgp_keepalive_time_seconds", float64(session.KeepaliveTime), labels, timestamp),
		)

		// Established time (uptime)
		if session.EstablishedTime > 0 {
			metrics = append(metrics, types.NewMetricAt(
				"arista_bgp_established_time_seconds",
				float64(session.EstablishedTime),
				labels,
				timestamp,
			))
		}
	}

	// Summary metrics
	baseLabels := c.cvp.BaseLabels()
	metrics = append(metrics,
		types.NewMetricAt("arista_bgp_sessions_total", float64(len(sessions)), baseLabels, timestamp),
		types.NewMetricAt("arista_bgp_sessions_established", float64(establishedCount), baseLabels, timestamp),
	)

	// Sessions by state
	for state, count := range stateCounts {
		labels := c.cvp.BaseLabels()
		labels["state"] = state
		metrics = append(metrics, types.NewMetricAt(
			"arista_bgp_sessions_by_state",
			float64(count),
			labels,
			timestamp,
		))
	}

	return metrics
}

// GetSessionsByDevice fetches BGP sessions for a specific device
func (c *BGPCollector) GetSessionsByDevice(ctx context.Context, deviceID string) ([]BGPSession, error) {
	url := fmt.Sprintf("%s/api/resources/routing/bgp/v1/BGPPeerSession/all?device=%s", c.cvp.GetBaseURL(), deviceID)

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

	var response BGPResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.Data, nil
}
