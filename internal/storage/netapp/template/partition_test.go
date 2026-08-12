// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"slices"
	"testing"
)

func displays(defs []CounterDef) []string {
	out := make([]string, 0, len(defs))
	for _, d := range defs {
		out = append(out, d.Display)
	}
	return out
}

// TestPartition_KeysAreAlsoLabels is the contract that keeps the primary
// identity on every exported series. A `^^` counter names the instance AND is
// exported as a label; if it only did the former, `volume_size` would ship
// without a `volume` label and every volume would collapse into one series.
func TestPartition_KeysAreAlsoLabels(t *testing.T) {
	defs := []CounterDef{
		{APIName: "volume", Display: "volume", Kind: "key"},
		{APIName: "vserver", Display: "svm", Kind: "key"},
		{APIName: "state", Display: "state", Kind: "label"},
		{APIName: "size", Display: "size"},
	}

	keys, labels, metrics := Partition(defs)

	if got := displays(keys); !slices.Equal(got, []string{"svm", "volume"}) {
		t.Errorf("keys = %v, want [svm volume]", got)
	}
	if got := displays(labels); !slices.Contains(got, "volume") || !slices.Contains(got, "svm") {
		t.Errorf("labels = %v, want the `^^` keys volume and svm to appear as labels", got)
	}
	if got := displays(labels); !slices.Contains(got, "state") {
		t.Errorf("labels = %v, missing the plain `^` label state", got)
	}
	if got := displays(metrics); !slices.Equal(got, []string{"size"}) {
		t.Errorf("metrics = %v, want [size]", got)
	}
}

// TestPartition_KeysAreSortedByDisplay pins the ordering rule. The composed
// instance key must agree between an object's primary query and an endpoint
// join, and the two templates may declare their keys in any order — sorting by
// display name is what makes the two agree.
func TestPartition_KeysAreSortedByDisplay(t *testing.T) {
	// The two templates reach the same two labels through different API
	// names and declare them in the opposite order. Only ordering by display
	// name makes the composed keys line up.
	primary := []CounterDef{
		{APIName: "volume", Display: "volume", Kind: "key"},
		{APIName: "vserver", Display: "svm", Kind: "key"},
	}
	endpoint := []CounterDef{
		{APIName: "svm.name", Display: "svm", Kind: "key"},
		{APIName: "zz_name", Display: "volume", Kind: "key"},
	}

	primaryKeys, _, _ := Partition(primary)
	endpointKeys, _, _ := Partition(endpoint)

	if !slices.Equal(displays(primaryKeys), displays(endpointKeys)) {
		t.Fatalf("key order differs between primary %v and endpoint %v; the join would never match",
			displays(primaryKeys), displays(endpointKeys))
	}
}

// TestPartition_StableForEqualDisplays keeps template order for ties so the
// composed key is deterministic across polls.
func TestPartition_StableForEqualDisplays(t *testing.T) {
	defs := []CounterDef{
		{APIName: "a", Display: "dup", Kind: "key"},
		{APIName: "b", Display: "dup", Kind: "key"},
	}
	keys, _, _ := Partition(defs)
	if len(keys) != 2 || keys[0].APIName != "a" || keys[1].APIName != "b" {
		t.Fatalf("Partition reordered equal displays: %v", keys)
	}
}

func TestPartition_Empty(t *testing.T) {
	keys, labels, metrics := Partition(nil)
	if len(keys)+len(labels)+len(metrics) != 0 {
		t.Fatalf("Partition(nil) produced %d/%d/%d", len(keys), len(labels), len(metrics))
	}
}
