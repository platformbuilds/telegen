// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"reflect"
	"testing"
)

func TestReattachOrphanedRules(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]any
		want map[string]any
	}{
		{
			name: "mis-indented rule is reattached",
			in: map[string]any{
				"LabelAgent": nil,
				"split":      []any{"fcvi `:` ,fcvi"},
			},
			want: map[string]any{
				"LabelAgent": map[string]any{"split": []any{"fcvi `:` ,fcvi"}},
			},
		},
		{
			name: "multiple mis-indented rules are reattached together",
			in: map[string]any{
				"LabelAgent":   nil,
				"split":        []any{"a"},
				"value_to_num": []any{"b"},
			},
			want: map[string]any{
				"LabelAgent": map[string]any{
					"split":        []any{"a"},
					"value_to_num": []any{"b"},
				},
			},
		},
		{
			name: "correctly nested entry is untouched",
			in: map[string]any{
				"LabelAgent": map[string]any{"split": []any{"a"}},
			},
			want: map[string]any{
				"LabelAgent": map[string]any{"split": []any{"a"}},
			},
		},
		{
			name: "bare plugin with no siblings is untouched",
			in:   map[string]any{"FabricPool": nil},
			want: map[string]any{"FabricPool": nil},
		},
		{
			name: "two bare plugins are ambiguous and left alone",
			in: map[string]any{
				"LabelAgent": nil,
				"Volume":     nil,
				"split":      []any{"a"},
			},
			want: map[string]any{
				"LabelAgent": nil,
				"Volume":     nil,
				"split":      []any{"a"},
			},
		},
		{
			name: "unknown plugin with siblings is left alone",
			in: map[string]any{
				"NotAPlugin": nil,
				"split":      []any{"a"},
			},
			want: map[string]any{
				"NotAPlugin": nil,
				"split":      []any{"a"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reattachOrphanedRules(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("reattachOrphanedRules() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
