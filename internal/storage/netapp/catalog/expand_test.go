// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
)

func TestExpandCoversCoreFamilies(t *testing.T) {
	out, err := Expand(ExpandOptions{Templates: configs.NetAppTemplates(), Version: "9.16.1", IncludeASAr2: true})
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"ems_events",
		"volume_read_ops",
		"aggr_disk_busy",
		"node_disk_max_busy",
		"volume_top_clients_read_ops",
		"health_disk_alerts",
		"metadata_collector_poll_time",
		"poller_status",
		"storage_unit_read_ops",
	}
	for _, n := range required {
		if _, ok := out[n]; !ok {
			t.Errorf("missing family %s (total=%d)", n, len(out))
		}
	}
	if len(out) < 1558 {
		t.Errorf("expected at least 1558 families, got %d", len(out))
	}
}
