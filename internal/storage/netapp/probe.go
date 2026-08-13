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
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/jsonpath"
)

// Capabilities describes ONTAP cluster features relevant to collector selection.
type Capabilities struct {
	VersionFull     string
	Generation      int
	Major           int
	Minor           int
	UUID            string
	Name            string
	HasRESTPerf     bool
	IsDisaggregated bool
	IsASAr2         bool
	GCNVMode        bool
}

// ProbeCapabilities queries the cluster and counter-tables availability.
func ProbeCapabilities(ctx context.Context, c *client.Client, gcnv bool) (Capabilities, error) {
	raw, err := c.GetBytes(ctx, "api/cluster")
	if err != nil {
		return Capabilities{}, fmt.Errorf("probe cluster: %w", err)
	}
	rec := json.RawMessage(raw)

	uuid, _ := jsonpath.GetString(rec, "uuid")
	name, _ := jsonpath.GetString(rec, "name")
	full, _ := jsonpath.GetString(rec, "version.full")
	gen, _ := jsonpath.GetFloat(rec, "version.generation")
	major, _ := jsonpath.GetFloat(rec, "version.major")
	minor, _ := jsonpath.GetFloat(rec, "version.minor")

	disaggregated := false
	if s, ok := jsonpath.GetString(rec, "disaggregated"); ok {
		if parsed, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(s))); err == nil {
			disaggregated = parsed
		}
	}

	cap := Capabilities{
		VersionFull:     full,
		Generation:      int(gen),
		Major:           int(major),
		Minor:           int(minor),
		UUID:            uuid,
		Name:            name,
		IsDisaggregated: disaggregated,
		GCNVMode:        gcnv,
	}
	// ASA r2 heuristic: disaggregated storage units style clusters
	cap.IsASAr2 = disaggregated

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
	// No valid version found - return empty string to signal error
	// Caller (VersionString) will use this as-is, causing template resolution to fail
	// which is preferable to silently falling back to an arbitrary version
	return ""
}

// UseRestPerf reports whether RestPerf engines should run.
func (c Capabilities) UseRestPerf() bool {
	return c.HasRESTPerf && !c.IsASAr2 && !c.GCNVMode
}
