// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package keyperf

import (
	"slices"
	"testing"
)

func TestTemplateBasesDefaultToKeyperf(t *testing.T) {
	c := NewCollector()
	if got := c.templateBases(); !slices.Equal(got, []string{"keyperf"}) {
		t.Fatalf("templateBases() = %v, want [keyperf]", got)
	}
}

// TestTemplateBasesKeepBaseFallback pins the ASA r2 overlay contract: the
// model-specific tree is searched first, but the base tree must remain in the
// list or every object it does not redefine is silently dropped.
func TestTemplateBasesHonourResolvedBases(t *testing.T) {
	c := NewCollector()
	c.bases = []string{"keyperf/asar2", "keyperf"}

	got := c.templateBases()
	if !slices.Equal(got, []string{"keyperf/asar2", "keyperf"}) {
		t.Fatalf("templateBases() = %v, want [keyperf/asar2 keyperf]", got)
	}
}
