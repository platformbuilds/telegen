// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
)

func TestAggregatorHarvestRenamesObject(t *testing.T) {
	src := matrix.New("disk")
	src.NewMetric("busy", "busy", "gauge")
	inst, err := src.NewInstance("d1")
	if err != nil {
		t.Fatal(err)
	}
	inst.Labels["aggr"] = "aggr1"
	inst.Labels["node"] = "node1"
	_ = src.SetValue("busy", "d1", 40)

	mats := AggregatorHarvest(src, []any{"aggr ...", "node"}, slog.Default())
	if len(mats) < 3 {
		t.Fatalf("expected source + 2 aggregates, got %d", len(mats))
	}
	var foundAggr bool
	for _, m := range mats[1:] {
		if m.Object == "aggr_disk" {
			foundAggr = true
			if _, ok := m.GetValue("busy", "aggr1"); !ok {
				t.Fatal("missing aggr1 busy")
			}
		}
	}
	if !foundAggr {
		t.Fatal("missing aggr_disk matrix")
	}

	maxMats := MaxHarvest(src, []any{"node<>node_disk_max"}, slog.Default())
	if len(maxMats) != 1 || maxMats[0].Object != "node_disk_max" {
		t.Fatalf("unexpected max mats: %+v", maxMats)
	}
}

func TestApplyAllExportsMaxMatrix(t *testing.T) {
	src := matrix.New("disk")
	src.NewMetric("busy", "busy", "gauge")
	inst, _ := src.NewInstance("d1")
	inst.Labels["node"] = "n1"
	_ = src.SetValue("busy", "d1", 10)
	plugins := []any{
		map[string]any{
			"Max": []any{"node<>node_disk_max"},
		},
	}
	mats := ApplyAll(src, plugins, slog.Default())
	if len(mats) < 2 {
		t.Fatalf("expected max matrix, got %d", len(mats))
	}
}
