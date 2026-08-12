// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package keyperf

import "testing"

func TestTemplateBaseDefaultsToKeyperf(t *testing.T) {
	c := NewCollector()
	if got := c.templateBase(); got != "keyperf" {
		t.Fatalf("templateBase() = %q, want %q", got, "keyperf")
	}
}

func TestTemplateBaseHonoursResolvedBase(t *testing.T) {
	c := NewCollector()
	c.base = "keyperf/asar2"
	if got := c.templateBase(); got != "keyperf/asar2" {
		t.Fatalf("templateBase() = %q, want %q", got, "keyperf/asar2")
	}
}
