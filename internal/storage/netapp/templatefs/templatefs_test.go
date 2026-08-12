// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package templatefs_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/templatefs"
)

func TestResolveFallsBackToEmbedded(t *testing.T) {
	fsys, src := templatefs.Resolve(filepath.Join(t.TempDir(), "does-not-exist"))
	if src != templatefs.EmbeddedSource {
		t.Fatalf("source = %q, want %q", src, templatefs.EmbeddedSource)
	}
	if _, err := fs.ReadFile(fsys, "rest/default.yaml"); err != nil {
		t.Fatalf("embedded rest/default.yaml unreadable: %v", err)
	}
}

func TestResolvePrefersConfiguredDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rest"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rest", "default.yaml"), []byte("objects:\n  Marker: marker.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fsys, src := templatefs.Resolve(dir)
	if src != dir {
		t.Fatalf("source = %q, want %q", src, dir)
	}
	data, err := fs.ReadFile(fsys, "rest/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "objects:\n  Marker: marker.yaml\n" {
		t.Fatalf("configured dir not used, got %q", data)
	}
}

func TestResolveIgnoresConfiguredDirWithoutMarker(t *testing.T) {
	_, src := templatefs.Resolve(t.TempDir())
	if src != templatefs.EmbeddedSource {
		t.Fatalf("source = %q, want %q", src, templatefs.EmbeddedSource)
	}
}

func TestResolveAcceptsESeriesMarker(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "eseries"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "eseries", "default.yaml"), []byte("objects: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, src := templatefs.Resolve(dir); src != dir {
		t.Fatalf("source = %q, want %q", src, dir)
	}
}
