// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
)

func embeddedTemplates() fs.FS { return configs.NetAppTemplates() }

func diskTemplates(t *testing.T) fs.FS {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../internal/storage/netapp/template/load_test.go -> repo root
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	return os.DirFS(filepath.Join(root, "configs", "netapp"))
}

func TestLoadRestPerfCatalog(t *testing.T) {
	fsys := embeddedTemplates()
	cat, err := template.LoadCatalog(fsys, "restperf/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Objects) < 30 {
		t.Fatalf("expected many restperf objects, got %d", len(cat.Objects))
	}
	tmpl, tmplPath, err := template.LoadObjectTemplate(fsys, "restperf", "system_node.yaml", "9.16.1")
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
		t.Fatalf("expected many float counters in %s, got %d", tmplPath, floats)
	}
}

func TestResolveFallsBackAcrossVersions(t *testing.T) {
	// volume.yaml for rest exists in 9.14.0 among others; request 9.16.1
	tmpl, tmplPath, err := template.LoadObjectTemplate(embeddedTemplates(), "rest", "volume.yaml", "9.16.1")
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.Object != "volume" {
		t.Fatalf("object=%q", tmpl.Object)
	}
	if tmplPath == "" {
		t.Fatal("empty path")
	}
}

func TestEmbeddedMatchesDisk(t *testing.T) {
	for _, tc := range []struct{ base, file string }{
		{"rest", "volume.yaml"},
		{"rest", "node.yaml"},
		{"rest", "aggr.yaml"},
		{"restperf", "system_node.yaml"},
	} {
		embedded, embeddedPath, err := template.LoadObjectTemplate(embeddedTemplates(), tc.base, tc.file, "9.16.1")
		if err != nil {
			t.Fatalf("embedded %s/%s: %v", tc.base, tc.file, err)
		}
		onDisk, diskPath, err := template.LoadObjectTemplate(diskTemplates(t), tc.base, tc.file, "9.16.1")
		if err != nil {
			t.Fatalf("disk %s/%s: %v", tc.base, tc.file, err)
		}
		if embeddedPath != diskPath {
			t.Errorf("%s/%s resolved path embedded=%q disk=%q", tc.base, tc.file, embeddedPath, diskPath)
		}
		if len(embedded.RawCounters) != len(onDisk.RawCounters) {
			t.Errorf("%s/%s counters embedded=%d disk=%d", tc.base, tc.file, len(embedded.RawCounters), len(onDisk.RawCounters))
		}
	}
}
