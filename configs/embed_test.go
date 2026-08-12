// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package configs_test

import (
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
	"gopkg.in/yaml.v3"
)

func TestNetAppTemplatesFileCount(t *testing.T) {
	fsys := configs.NetAppTemplates()
	var total, yamls int
	if err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		total++
		if strings.HasSuffix(p, ".yaml") {
			yamls++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if total != 178 {
		t.Fatalf("embedded file count = %d, want 178", total)
	}
	if yamls != 176 {
		t.Fatalf("embedded yaml count = %d, want 176", yamls)
	}
}

func TestNetAppTemplatesKnownEntries(t *testing.T) {
	fsys := configs.NetAppTemplates()
	for _, p := range []string{
		"rest/default.yaml",
		"rest/9.12.0/node.yaml",
		"rest/9.12.0/aggr.yaml",
		"restperf/default.yaml",
		"keyperf/default.yaml",
		"ems/9.6.0/ems.yaml",
		"eseries/default.yaml",
		"eseriesperf/default.yaml",
	} {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
	}
}

func TestNetAppTemplatesRejectsParentEscape(t *testing.T) {
	if _, err := fs.ReadFile(configs.NetAppTemplates(), path.Clean("../storage.yaml")); err == nil {
		t.Fatal("expected escape outside the netapp subtree to fail")
	}
}
