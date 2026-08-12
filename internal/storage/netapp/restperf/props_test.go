// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package restperf

import (
	"encoding/json"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
)

// lunRow is a counter-table row shaped the way ONTAP returns one: identity
// lives in the `properties` array, never as top-level fields.
const lunRow = `{
  "id": "umeng-aff300-01:svm1:/vol/vol1/lun1",
  "properties": [
    {"name": "node.name", "value": "umeng-aff300-01"},
    {"name": "svm.name",  "value": "svm1"},
    {"name": "volume",    "value": "vol1"},
    {"name": "aggregates","value": ["aggr1", "aggr2"]},
    {"name": "state",     "value": "online"}
  ],
  "counters": [
    {"name": "read_ops", "value": 42}
  ]
}`

func TestParseProps_ReadsPropertiesArray(t *testing.T) {
	props := parseProps(json.RawMessage(lunRow))

	want := map[string]string{
		"id":         "umeng-aff300-01:svm1:/vol/vol1/lun1",
		"node.name":  "umeng-aff300-01",
		"svm.name":   "svm1",
		"volume":     "vol1",
		"aggregates": "aggr1,aggr2",
		"state":      "online",
	}
	for k, v := range want {
		if got := props[k]; got != v {
			t.Errorf("props[%q] = %q, want %q", k, got, v)
		}
	}
}

// TestBuildKey_UsesProperties pins that the instance key is composed from the
// declared `^^` counters resolved against the properties map.
func TestBuildKey_UsesProperties(t *testing.T) {
	props := parseProps(json.RawMessage(lunRow))

	keys := []template.CounterDef{
		{APIName: "node.name", Display: "node", Kind: "key"},
		{APIName: "svm.name", Display: "svm", Kind: "key"},
	}
	if got, want := buildKey(props, keys), "umeng-aff300-01svm1"; got != want {
		t.Fatalf("buildKey = %q, want %q", got, want)
	}
}

// TestBuildKey_MissingPropertyDoesNotVoidKey mirrors Harvest: a row missing one
// declared key still yields an instance from the keys it does carry.
func TestBuildKey_MissingPropertyDoesNotVoidKey(t *testing.T) {
	props := parseProps(json.RawMessage(lunRow))

	keys := []template.CounterDef{
		{APIName: "svm.name", Display: "svm", Kind: "key"},
		{APIName: "not.present", Display: "nope", Kind: "key"},
	}
	if got, want := buildKey(props, keys), "svm1"; got != want {
		t.Fatalf("buildKey = %q, want %q", got, want)
	}
}

// TestPropertyValue covers the value shapes ONTAP returns for a property.
func TestPropertyValue(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"string", "svm1", "svm1"},
		{"list joins with comma", []any{"a", "b"}, "a,b"},
		{"empty list", []any{}, ""},
		{"number", float64(7), "7"},
		{"fractional number", 1.5, "1.5"},
		{"bool", true, "true"},
		{"nil", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := propertyValue(tt.in); got != tt.want {
				t.Fatalf("propertyValue(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseProps_MalformedRowIsEmptyNotPanic(t *testing.T) {
	for _, raw := range []string{`not json`, `[]`, `{"properties": "scalar"}`, `{}`} {
		props := parseProps(json.RawMessage(raw))
		if props == nil {
			t.Fatalf("parseProps(%s) returned nil map", raw)
		}
	}
}
