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

// loadAllEmbeddedObjectTemplates returns every shipped object template keyed by
// its path. Catalogs (`default.yaml`) and files that carry neither counters nor
// a query are skipped — they are not object templates.
func loadAllEmbeddedObjectTemplates(t *testing.T) map[string]*Template {
	t.Helper()

	fsys := configs.NetAppTemplates()
	out := map[string]*Template{}

	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return werr
		}
		if strings.HasSuffix(p, "default.yaml") {
			return nil
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return rerr
		}
		var tmpl Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			t.Errorf("%s: %v", p, err)
			return nil
		}
		if len(tmpl.Counters) == 0 && tmpl.Query == "" {
			return nil
		}
		out[p] = &tmpl
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded templates: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no embedded object templates found")
	}
	return out
}
