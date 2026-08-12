// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netapp

import (
	"sort"
	"strings"
	"testing"

	"github.com/mirastacklabs-ai/telegen/configs"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
)

// ontapVersions are the ONTAP releases a shipped template set must serve.
var ontapVersions = []string{"9.6.0", "9.8.0", "9.10.1", "9.12.1", "9.14.1", "9.15.1", "9.16.1"}

type catalogSpec struct {
	catalog string
	// bases are the template roots searched in order, mirroring what the
	// collector does at runtime.
	bases []string
}

var catalogs = []catalogSpec{
	{catalog: "rest/default.yaml", bases: []string{"rest"}},
	{catalog: "rest/asar2/default.yaml", bases: []string{"rest/asar2", "rest"}},
	{catalog: "restperf/default.yaml", bases: []string{"restperf"}},
	{catalog: "keyperf/default.yaml", bases: []string{"keyperf"}},
	{catalog: "keyperf/asar2/default.yaml", bases: []string{"keyperf/asar2", "keyperf"}},
	{catalog: "ems/default.yaml", bases: []string{"ems"}},
	{catalog: "eseries/default.yaml", bases: []string{"eseries"}},
	{catalog: "eseriesperf/default.yaml", bases: []string{"eseriesperf"}},
}

// TestEveryCatalogObjectResolves asserts that every object named by every
// shipped catalog resolves to a loadable template at every supported ONTAP
// version. An unresolved object is silent at runtime — the collector logs a
// warning and the object's entire metric family goes missing.
func TestEveryCatalogObjectResolves(t *testing.T) {
	fsys := configs.NetAppTemplates()

	var checked int
	for _, spec := range catalogs {
		cat, err := template.LoadCatalog(fsys, spec.catalog)
		if err != nil {
			t.Errorf("catalog %s: %v", spec.catalog, err)
			continue
		}
		names := make([]string, 0, len(cat.Objects))
		for k := range cat.Objects {
			names = append(names, k)
		}
		sort.Strings(names)

		for _, object := range names {
			file := strings.TrimSpace(cat.Objects[object])
			if file == "" {
				continue
			}
			// RestPerf delegates some objects to a KeyPerf template.
			if rest, ok := strings.CutPrefix(file, "KeyPerf:"); ok {
				file = strings.TrimSpace(rest)
				for _, v := range ontapVersions {
					checked++
					if _, _, err := template.LoadObjectTemplateFrom(
						fsys, []string{"keyperf"}, file, v); err != nil {
						t.Errorf("%s: %s -> KeyPerf:%s unresolved at %s: %v",
							spec.catalog, object, file, v, err)
					}
				}
				continue
			}
			for _, v := range ontapVersions {
				checked++
				if _, _, err := template.LoadObjectTemplateFrom(
					fsys, spec.bases, file, v); err != nil {
					t.Errorf("%s: %s -> %s unresolved at %s: %v",
						spec.catalog, object, file, v, err)
				}
			}
		}
	}
	t.Logf("resolved %d (catalog object x ONTAP version) pairs", checked)
	if checked == 0 {
		t.Fatal("no catalog objects were checked")
	}
}
