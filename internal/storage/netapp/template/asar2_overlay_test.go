// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"strings"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
)

// TestLoadCatalogMerged_ASAr2IsAnOverlay pins the ASA r2 contract. The
// model-specific catalog names only the objects that differ; loading it on its
// own would drop every other object the cluster still serves.
func TestLoadCatalogMerged_ASAr2IsAnOverlay(t *testing.T) {
	fsys := configs.NetAppTemplates()

	tests := []struct {
		name         string
		base         string
		overlay      string
		wantOverlay  []string
		wantInherit  []string
		overlayFiles map[string]string
	}{
		{
			name:        "rest",
			base:        "rest/default.yaml",
			overlay:     "rest/asar2/default.yaml",
			wantOverlay: []string{"AvailabilityZone", "StorageUnit"},
			wantInherit: []string{"Aggregate", "Volume", "Qtree", "Shelf", "Disk", "SnapMirror"},
		},
		{
			name:        "keyperf",
			base:        "keyperf/default.yaml",
			overlay:     "keyperf/asar2/default.yaml",
			wantOverlay: []string{"StorageUnit"},
			wantInherit: []string{"Aggregate", "Volume", "Lun", "SystemNode", "NFSv3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, err := LoadCatalog(fsys, tt.base)
			if err != nil {
				t.Fatalf("load base catalog: %v", err)
			}
			merged, err := LoadCatalogMerged(fsys, tt.base, tt.overlay)
			if err != nil {
				t.Fatalf("load merged catalog: %v", err)
			}

			if len(merged.Objects) <= len(base.Objects) {
				t.Fatalf("merged catalog has %d objects, base has %d: the overlay replaced the base instead of extending it",
					len(merged.Objects), len(base.Objects))
			}
			for _, obj := range tt.wantOverlay {
				if _, ok := merged.Objects[obj]; !ok {
					t.Errorf("overlay object %q missing from merged catalog", obj)
				}
			}
			for _, obj := range tt.wantInherit {
				if _, ok := merged.Objects[obj]; !ok {
					t.Errorf("base object %q was dropped by the overlay", obj)
				}
			}
		})
	}
}

// TestLoadObjectTemplateFrom_PrefersOverlayThenFallsBack asserts the per-object
// half of the same contract: an object the ASA r2 tree redefines resolves
// there, and everything else resolves in the base tree rather than failing.
func TestLoadObjectTemplateFrom_PrefersOverlayThenFallsBack(t *testing.T) {
	fsys := configs.NetAppTemplates()
	bases := []string{"rest/asar2", "rest"}

	t.Run("overlay wins", func(t *testing.T) {
		_, path, err := LoadObjectTemplateFrom(fsys, bases, "storage_unit.yaml", "9.16.1")
		if err != nil {
			t.Fatalf("resolve storage_unit.yaml: %v", err)
		}
		if !strings.Contains(path, "asar2") {
			t.Fatalf("resolved %q, want the asar2 template", path)
		}
	})

	t.Run("falls back to base", func(t *testing.T) {
		_, path, err := LoadObjectTemplateFrom(fsys, bases, "volume.yaml", "9.16.1")
		if err != nil {
			t.Fatalf("volume.yaml did not fall back to the base tree: %v", err)
		}
		if strings.Contains(path, "asar2") {
			t.Fatalf("resolved %q, but the asar2 tree has no volume.yaml", path)
		}
	})

	t.Run("cluster prefers the asar2 variant", func(t *testing.T) {
		_, path, err := LoadObjectTemplateFrom(fsys, bases, "cluster.yaml", "9.16.1")
		if err != nil {
			t.Fatalf("resolve cluster.yaml: %v", err)
		}
		if !strings.Contains(path, "asar2") {
			t.Fatalf("resolved %q, want the asar2 template", path)
		}
	})
}

// TestLoadCatalogMerged_MissingOverlayIsNotFatal keeps a non-ASA r2 cluster
// working when only the base catalog is passed.
func TestLoadCatalogMerged_MissingOverlayIsNotFatal(t *testing.T) {
	fsys := configs.NetAppTemplates()

	merged, err := LoadCatalogMerged(fsys, "rest/default.yaml", "rest/does-not-exist.yaml")
	if err != nil {
		t.Fatalf("a missing overlay should be skipped, got: %v", err)
	}
	if len(merged.Objects) == 0 {
		t.Fatal("merged catalog is empty")
	}
}

func TestLoadCatalogMerged_MissingBaseIsFatal(t *testing.T) {
	fsys := configs.NetAppTemplates()

	if _, err := LoadCatalogMerged(fsys, "rest/does-not-exist.yaml"); err == nil {
		t.Fatal("a missing base catalog must be an error")
	}
}
