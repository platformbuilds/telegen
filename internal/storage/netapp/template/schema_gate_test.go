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

// TestTemplateSchemaGate ensures every top-level key in every shipped template
// is either a field in the Template struct or explicitly allowlisted. This is
// the gate that would have caught hidden_fields, filter, export_data,
// global_labels, override, and client_timeout being silently ignored.
func TestTemplateSchemaGate(t *testing.T) {
	// Fields that map to Template struct tags
	knownFields := map[string]bool{
		"name":           true,
		"query":          true,
		"object":         true,
		"ignore":         true,
		"counters":       true,
		"filter":         true,
		"plugins":        true,
		"export_options": true,
		"endpoints":      true,
		"override":       true,
		"global_labels":  true,
		"export_data":    true,
	}

	// Fields that appear in templates but are not yet implemented.
	// This is a SHRINK-ONLY allowlist. Adding a field here requires:
	// 1. A comment explaining WHY it is not in the Template struct
	// 2. A reference to where/how it should be implemented
	// 3. Approval in code review
	allowlisted := map[string]bool{
		// Aggregator plugin behavior control - plugin-specific config, not template-level
		"allow_partial_aggregation": true,
		// Per-object HTTP timeout - should be added to Template as ClientTimeout time.Duration
		"client_timeout": true,
		// QoS workload label mapping - workload plugin-specific config
		"qos_labels": true,
		// Catalog-file only fields (not in per-object templates)
		"collector": true,
		"schedule":  true,
		"objects":   true,
		// E-Series counter table definition file field
		"type": true,
		// EMS event configuration
		"events": true,
		// EMS exports (distinct from export_options)
		"exports": true,
		// RestPerf vscan template uses this instead of ^^counters
		"instance_key": true,
	}

	fsys := configs.NetAppTemplates()
	var failures []string

	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return werr
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return rerr
		}

		var doc map[string]any
		if yaml.Unmarshal(data, &doc) != nil {
			return nil // YAML parse error; not this test's job
		}

		for key := range doc {
			if knownFields[key] || allowlisted[key] {
				continue
			}
			failures = append(failures, p+": unknown key '"+key+"'")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(failures) > 0 {
		t.Errorf("Found %d unknown template keys (add to Template struct or document in allowlist):", len(failures))
		for _, f := range failures {
			t.Errorf("  %s", f)
		}
	}

	t.Logf("Validated %d template files; 0 unknown keys", countYAMLFiles(t, fsys))
}

func countYAMLFiles(t *testing.T, fsys fs.FS) int {
	t.Helper()
	count := 0
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, _ error) error {
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			count++
		}
		return nil
	})
	return count
}
