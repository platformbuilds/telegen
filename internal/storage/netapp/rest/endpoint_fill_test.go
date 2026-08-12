// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package rest

import (
	"encoding/json"
	"io/fs"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
)

func newFilledMatrix(t *testing.T) *matrix.Matrix {
	t.Helper()

	mat := matrix.New("aggr")
	inst, err := mat.NewInstance("known")
	if err != nil {
		t.Fatalf("seed instance: %v", err)
	}
	inst.Labels["aggr"] = "primary_value"
	return mat
}

var (
	epKeyDefs   = []template.CounterDef{{APIName: "uuid", Display: "uuid", Kind: "key"}}
	epLabelDefs = []template.CounterDef{{APIName: "node", Display: "node", Kind: "label"}}
)

func TestFillMatrixEndpoint_PreservesPrimaryLabels(t *testing.T) {
	mat := newFilledMatrix(t)
	records := []json.RawMessage{json.RawMessage(`{"uuid":"known","node":"node-1"}`)}

	if err := fillMatrixEndpoint(mat, records, epKeyDefs, epLabelDefs, nil, false); err != nil {
		t.Fatalf("fillMatrixEndpoint: %v", err)
	}

	inst := mat.GetInstance("known")
	if inst == nil {
		t.Fatal("instance disappeared")
	}
	if got := inst.Labels["aggr"]; got != "primary_value" {
		t.Errorf("primary label overwritten: aggr = %q", got)
	}
	if got := inst.Labels["node"]; got != "node-1" {
		t.Errorf("endpoint label missing: node = %q", got)
	}
}

func TestFillMatrixEndpoint_SkipsUnknownWithoutInstanceAdd(t *testing.T) {
	mat := newFilledMatrix(t)
	records := []json.RawMessage{json.RawMessage(`{"uuid":"unknown","node":"node-2"}`)}

	if err := fillMatrixEndpoint(mat, records, epKeyDefs, epLabelDefs, nil, false); err != nil {
		t.Fatalf("fillMatrixEndpoint: %v", err)
	}

	if mat.GetInstance("unknown") != nil {
		t.Fatal("endpoint created an instance without instance_add")
	}
}

func TestFillMatrixEndpoint_AddsUnknownWithInstanceAdd(t *testing.T) {
	mat := newFilledMatrix(t)
	records := []json.RawMessage{json.RawMessage(`{"uuid":"unknown","node":"node-2"}`)}

	if err := fillMatrixEndpoint(mat, records, epKeyDefs, epLabelDefs, nil, true); err != nil {
		t.Fatalf("fillMatrixEndpoint: %v", err)
	}

	inst := mat.GetInstance("unknown")
	if inst == nil {
		t.Fatal("instance_add endpoint did not create the instance")
	}
	if got := inst.Labels["node"]; got != "node-2" {
		t.Errorf("node = %q, want %q", got, "node-2")
	}
}

// TestEndpointInstanceAddIsParsed pins that `instance_add` is read off the
// template rather than silently defaulting to false.
func TestEndpointInstanceAddIsParsed(t *testing.T) {
	tmpl, _, err := template.LoadObjectTemplate(embeddedTemplates(t), "rest", "aggr.yaml", "9.14.1")
	if err != nil {
		t.Fatalf("load aggr.yaml: %v", err)
	}

	var found bool
	for _, ep := range tmpl.Endpoints {
		if ep.Query == "api/private/cli/aggr" {
			found = true
			if !ep.InstanceAdd {
				t.Error("aggr.yaml declares instance_add: true but it parsed as false")
			}
		}
	}
	if !found {
		t.Fatal("api/private/cli/aggr endpoint not found in aggr.yaml")
	}
}

func embeddedTemplates(t *testing.T) fs.FS {
	t.Helper()
	return configs.NetAppTemplates()
}
