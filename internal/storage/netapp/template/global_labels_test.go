// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"strings"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
)

// TestNFSVersionsHaveDisjointLabels verifies that the four NFS templates
// (nfsv3, nfsv4, nfsv4_1, nfsv4_2) each declare a unique global_labels nfsv
// value, preventing series identity collisions.
func TestNFSVersionsHaveDisjointLabels(t *testing.T) {
	fsys := configs.NetAppTemplates()
	
	nfsTemplates := map[string]string{
		"restperf/9.12.0/nfsv3.yaml":   "v3",
		"restperf/9.12.0/nfsv4.yaml":   "v4",
		"restperf/9.12.0/nfsv4_1.yaml": "v4.1",
		"restperf/9.12.0/nfsv4_2.yaml": "v4.2",
	}
	
	seenLabels := make(map[string]string) // nfsv value -> template name
	
	for path, expectedVersion := range nfsTemplates {
		tmpl, _, err := LoadObjectTemplate(fsys, "restperf", strings.TrimPrefix(path, "restperf/9.12.0/"), "9.12.0")
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		
		globalLabels := tmpl.GetGlobalLabels()
		if len(globalLabels) == 0 {
			t.Errorf("%s: missing global_labels", path)
			continue
		}
		
		nfsv, ok := globalLabels["nfsv"]
		if !ok {
			t.Errorf("%s: global_labels missing 'nfsv' key", path)
			continue
		}
		
		if nfsv != expectedVersion {
			t.Errorf("%s: nfsv = %q, want %q", path, nfsv, expectedVersion)
		}
		
		if prev, collision := seenLabels[nfsv]; collision {
			t.Errorf("%s and %s both declare nfsv=%q (series identity collision)", prev, path, nfsv)
		}
		seenLabels[nfsv] = path
	}
	
	if len(seenLabels) != len(nfsTemplates) {
		t.Errorf("expected %d distinct nfsv values, got %d", len(nfsTemplates), len(seenLabels))
	}
}
