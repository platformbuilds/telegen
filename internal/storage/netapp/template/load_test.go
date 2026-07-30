// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
)

func repoConfigsNetapp(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../internal/storage/netapp/template/load_test.go -> repo root
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	return filepath.Join(root, "configs", "netapp")
}

func TestLoadRestPerfCatalog(t *testing.T) {
	base := repoConfigsNetapp(t)
	cat, err := template.LoadCatalog(filepath.Join(base, "restperf", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Objects) < 30 {
		t.Fatalf("expected many restperf objects, got %d", len(cat.Objects))
	}
	tmpl, path, err := template.LoadObjectTemplate(filepath.Join(base, "restperf"), "system_node.yaml", "9.16.1")
	if err != nil {
		t.Fatal(err)
	}
	floats := 0
	for _, c := range tmpl.RawCounters {
		if c.Kind == "float" {
			floats++
		}
	}
	if floats < 10 {
		t.Fatalf("expected many float counters in %s, got %d", path, floats)
	}
}

func TestResolveFallsBackAcrossVersions(t *testing.T) {
	base := repoConfigsNetapp(t)
	// volume.yaml for rest exists in 9.14.0 among others; request 9.16.1
	tmpl, path, err := template.LoadObjectTemplate(filepath.Join(base, "rest"), "volume.yaml", "9.16.1")
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.Object != "volume" {
		t.Fatalf("object=%q", tmpl.Object)
	}
	if path == "" {
		t.Fatal("empty path")
	}
}
