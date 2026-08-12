// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package rest

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
	"gopkg.in/yaml.v3"
)

// TestSanitizeFields covers the fallback rules for a malformed counter path.
func TestSanitizeFields(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		fields []string
		want   []string
	}{
		{
			name:   "valid public fields pass through",
			query:  "api/storage/aggregates",
			fields: []string{"uuid", "space", "block_storage"},
			want:   []string{"uuid", "space", "block_storage"},
		},
		{
			name:   "star is always valid",
			query:  "api/storage/volumes",
			fields: []string{"*"},
			want:   []string{"*"},
		},
		{
			name:   "gjson multipath on a public query falls back to star",
			query:  "api/network/ip/routes",
			fields: []string{"uuid", "{interfaces", "gateway"},
			want:   []string{"*"},
		},
		{
			name:   "array selector on a public query falls back to star",
			query:  "api/storage/aggregates",
			fields: []string{"uuid", "cloud_storage#"},
			want:   []string{"*"},
		},
		{
			name:   "private cli drops the bad field and keeps the rest",
			query:  "api/private/cli/aggr",
			fields: []string{"aggregate", "{bogus", "node"},
			want:   []string{"aggregate", "node"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeFields(tt.query, tt.fields)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("sanitizeFields(%q, %v) = %v, want %v",
					tt.query, tt.fields, got, tt.want)
			}
		})
	}
}

// TestEmbeddedTemplatesProduceValidFields walks every shipped template and
// asserts the collector can never build a `fields` argument ONTAP rejects.
func TestEmbeddedTemplatesProduceValidFields(t *testing.T) {
	fsys := configs.NetAppTemplates()

	var checked int
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return werr
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return rerr
		}
		var tmpl template.Template
		if yaml.Unmarshal(data, &tmpl) != nil || len(tmpl.Counters) == 0 {
			return nil
		}
		checked++

		assertValidFields(t, p, tmpl.Query,
			sanitizeFields(tmpl.Query, collectFields(template.FlattenCounters(tmpl.Counters))))
		for _, ep := range tmpl.Endpoints {
			assertValidFields(t, p+" endpoint "+ep.Query, ep.Query,
				sanitizeFields(ep.Query, collectFields(template.FlattenCounters(ep.Counters))))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded templates: %v", err)
	}
	if checked == 0 {
		t.Fatal("no templates were checked; the embedded FS is empty")
	}
}

func assertValidFields(t *testing.T, where, query string, fields []string) {
	t.Helper()
	for _, f := range fields {
		if f == "*" {
			if !template.IsPublicAPI(query) {
				t.Errorf("%s: `*` is not supported on the private CLI passthrough", where)
			}
			continue
		}
		if !ontapFieldRe.MatchString(f) {
			t.Errorf("%s: ONTAP would reject field %q", where, f)
		}
	}
}
