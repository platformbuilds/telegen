// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestExpandCoversCoreFamilies(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/storage/netapp/catalog -> repo root configs/netapp
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "configs", "netapp"))
	out, err := Expand(ExpandOptions{TemplatesDir: dir, Version: "9.16.1", IncludeASAr2: true})
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
