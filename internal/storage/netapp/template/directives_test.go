// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
	"gopkg.in/yaml.v3"
)

// rootField mirrors how the REST collector derives an ONTAP `fields` argument
// from a counter: everything up to the first dot.
func rootField(apiName string) string {
	if i := strings.IndexByte(apiName, '.'); i > 0 {
		return apiName[:i]
	}
	return apiName
}

// TestNoDirectiveLeaksAcrossEmbeddedTemplates walks every shipped template and
// asserts that no Harvest directive survives counter flattening. A leak puts
// `hidden_fields` or `filter` into the ONTAP `fields` argument, and ONTAP
// rejects the whole request with HTTP 400 — which takes the object's metrics
// down entirely, not just the leaked field.
func TestNoDirectiveLeaksAcrossEmbeddedTemplates(t *testing.T) {
	fsys := configs.NetAppTemplates()

	var checked int
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return walkErr
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		var tmpl Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			// default.yaml catalogs are not object templates.
			return nil
		}
		if len(tmpl.Counters) == 0 {
			return nil
		}
		checked++

		assertNoDirective(t, p, FlattenCounters(tmpl.Counters))
		for _, ep := range tmpl.Endpoints {
			assertNoDirective(t, p+" endpoint "+ep.Query, FlattenCounters(ep.Counters))
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

func assertNoDirective(t *testing.T, where string, defs []CounterDef) {
	t.Helper()
	for _, c := range defs {
		if isDirective(rootField(c.APIName)) {
			t.Errorf("%s: directive leaked into counters as %q", where, c.APIName)
		}
	}
}

// TestEmbeddedDirectivesAreExtracted asserts the directives are not merely
// dropped: templates that declare them must surface them as query arguments.
func TestEmbeddedDirectivesAreExtracted(t *testing.T) {
	fsys := configs.NetAppTemplates()

	tests := []struct {
		path             string
		wantHiddenFields []string
		wantFilter       []string
	}{
		{
			path:             "rest/9.11.0/aggr.yaml",
			wantHiddenFields: []string{"space"},
		},
		{
			path:             "keyperf/9.15.0/volume.yaml",
			wantHiddenFields: []string{"statistics"},
			wantFilter:       []string{`statistics.timestamp=!"-"`, "style=!flexgroup"},
		},
		{
			path:       "rest/9.12.0/shelf.yaml",
			wantFilter: []string{"local=true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			data, err := fs.ReadFile(fsys, tt.path)
			if err != nil {
				t.Fatalf("read %s: %v", tt.path, err)
			}
			var tmpl Template
			if err := yaml.Unmarshal(data, &tmpl); err != nil {
				t.Fatalf("parse %s: %v", tt.path, err)
			}
			hidden, filter := ExtractDirectives(tmpl.Counters)
			assertContainsAll(t, "hidden_fields", hidden, tt.wantHiddenFields)
			assertContainsAll(t, "filter", filter, tt.wantFilter)
		})
	}
}

func assertContainsAll(t *testing.T, label string, got, want []string) {
	t.Helper()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: missing %q, got %v", label, w, got)
		}
	}
}
