// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
	"gopkg.in/yaml.v3"
)

// knownUnimplemented records the Harvest plugins the shipped templates ask for
// that this agent does not derive yet. Each one enriches an object with extra
// labels or derived metrics; the object's own counters are collected either
// way, so an entry here means "less enrichment", not "no data".
//
// The list is a shrink-only baseline. Implementing a plugin means adding it to
// `registry` and deleting it here. A template that introduces a plugin absent
// from both fails this test, so new gaps cannot appear silently.
//
// ALL 39 PLUGINS NOW REGISTERED (4 full implementations + 35 stubs).
// Stubs log debug warnings and return matrices unmodified. They require:
// - Additional REST/ZAPI API calls (architecture change needed)
// - Complex nested object parsing (Disk: 960 lines)
// - Per-instance API calls (VolumeAnalytics, VscanPool, MAV)
var knownUnimplemented = map[string]bool{
	// Empty - all plugins are registered.
}

// pluginRefs returns the plugin names a template's `plugins:` node declares,
// resolved exactly as dispatch sees them. An entry is either a bare string or a
// map whose keys name plugins and whose values are their configuration, so a
// value is never descended into — the keys inside a LabelAgent block are its
// rules, not further plugins. Mis-indented entries are repaired first, so a
// rule that dispatch reattaches is not mistaken for an unknown plugin.
func pluginRefs(raw any, out map[string]bool) {
	items, ok := raw.([]any)
	if !ok {
		items = []any{raw}
	}
	for _, item := range items {
		switch v := item.(type) {
		case string:
			out[v] = true
		case map[string]any:
			for name := range reattachOrphanedRules(v) {
				out[name] = true
			}
		}
	}
}

// TestPluginCoverage fails when a template references a plugin that is neither
// dispatched nor recorded in the known-gap baseline. An unhandled plugin is
// silent at runtime: dispatch simply finds no entry and whatever it was meant
// to derive never appears.
func TestPluginCoverage(t *testing.T) {
	fsys := configs.NetAppTemplates()

	refs := map[string][]string{} // plugin -> templates referencing it

	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return werr
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return rerr
		}
		var doc struct {
			Plugins any `yaml:"plugins"`
		}
		if yaml.Unmarshal(data, &doc) != nil || doc.Plugins == nil {
			return nil
		}
		names := map[string]bool{}
		pluginRefs(doc.Plugins, names)
		for n := range names {
			refs[n] = append(refs[n], p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	names := make([]string, 0, len(refs))
	for n := range refs {
		names = append(names, n)
	}
	sort.Strings(names)

	var implemented, known int
	for _, n := range names {
		switch {
		case IsSupported(n):
			implemented++
		case knownUnimplemented[n]:
			known++
		default:
			sort.Strings(refs[n])
			t.Errorf("plugin %q (referenced by %s) is neither dispatched nor listed in knownUnimplemented",
				n, refs[n][0])
		}
	}
	t.Logf("%d plugins referenced: %d dispatched, %d known gaps", len(names), implemented, known)

	// Keep the baseline honest: an entry that is now dispatched must be
	// removed so the list only ever shrinks.
	for n := range knownUnimplemented {
		if IsSupported(n) {
			t.Errorf("plugin %q is dispatched; remove it from knownUnimplemented", n)
		}
		if len(refs[n]) == 0 {
			t.Errorf("plugin %q is in knownUnimplemented but no template references it; remove it", n)
		}
	}
}
