// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netapp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
)

// Capabilities describes ONTAP cluster features relevant to collector selection.
type Capabilities struct {
	VersionFull    string
	Generation     int
	Major          int
	Minor          int
	UUID           string
	Name           string
	HasRESTPerf    bool
	IsDisaggregated bool
	IsASAr2        bool
	GCNVMode       bool
}

type clusterInfo struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Version struct {
		Full       string `json:"full"`
		Generation int    `json:"generation"`
		Major      int    `json:"major"`
		Minor      int    `json:"minor"`
	} `json:"version"`
	Disaggregated bool `json:"disaggregated"`
}

// ProbeCapabilities queries the cluster and counter-tables availability.
func ProbeCapabilities(ctx context.Context, c *client.Client, gcnv bool) (Capabilities, error) {
	var info clusterInfo
	if err := c.GetJSON(ctx, "api/cluster", &info); err != nil {
		return Capabilities{}, fmt.Errorf("probe cluster: %w", err)
	}
	cap := Capabilities{
		VersionFull:     info.Version.Full,
		Generation:      info.Version.Generation,
		Major:           info.Version.Major,
		Minor:           info.Version.Minor,
		UUID:            info.UUID,
		Name:            info.Name,
		IsDisaggregated: info.Disaggregated,
		GCNVMode:        gcnv,
	}
	// ASA r2 heuristic: disaggregated storage units style clusters
	cap.IsASAr2 = info.Disaggregated

	// Probe REST perf counter tables (available ~9.11.1+)
	if !gcnv && !cap.IsASAr2 {
		_, err := c.GetBytes(ctx, "api/cluster/counter/tables?max_records=1")
		cap.HasRESTPerf = err == nil
	}
	return cap, nil
}

// VersionString returns N.N.N for template resolution.
func (c Capabilities) VersionString() string {
	if c.Generation > 0 {
		return fmt.Sprintf("%d.%d.%d", c.Generation, c.Major, c.Minor)
	}
	// parse from Full e.g. "NetApp Release 9.16.1: ..."
	return parseVersionFromFull(c.VersionFull)
}

func parseVersionFromFull(full string) string {
	fields := strings.Fields(full)
	for _, f := range fields {
		f = strings.TrimSuffix(f, ":")
		parts := strings.Split(f, ".")
		if len(parts) >= 2 {
			if _, err := strconv.Atoi(parts[0]); err == nil {
				return f
			}
		}
	}
	return "9.12.0"
}

// UseRestPerf reports whether RestPerf engines should run.
func (c Capabilities) UseRestPerf() bool {
	return c.HasRESTPerf && !c.IsASAr2 && !c.GCNVMode
}

// DecodeRecords is a helper for tests.
func DecodeRecords(raw []json.RawMessage) []json.RawMessage { return raw }
