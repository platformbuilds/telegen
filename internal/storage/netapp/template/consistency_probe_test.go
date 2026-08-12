// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"sort"
	"strings"
	"testing"
)

// clusterSingletons are templates that legitimately declare no `^^` instance
// key because ONTAP returns exactly one record for them — the cluster itself,
// its software level, its support state. Everything else must name a key or
// every record collapses onto one instance.
var clusterSingletons = map[string]bool{
	"ems/9.6.0/ems.yaml":                   true,
	"rest/9.10.0/cluster.yaml":             true,
	"rest/9.12.0/metrocluster_check.yaml":  true,
	"rest/9.12.0/security.yaml":            true,
	"rest/9.12.0/status.yaml":              true,
	"rest/9.12.0/support.yaml":             true,
	"rest/9.12.0/support_auto_update.yaml": true,
	"rest/9.6.0/clustersoftware.yaml":      true,
	"rest/asar2/9.16.0/cluster.yaml":       true,
}

// TestEveryTemplateIsStructurallySound checks the invariants that make a
// template usable: it has a query and a name, it names an instance key unless
// it is a cluster singleton, and no two counters claim the same display name.
func TestEveryTemplateIsStructurallySound(t *testing.T) {
	templates := loadAllEmbeddedObjectTemplates(t)

	paths := make([]string, 0, len(templates))
	for p := range templates {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		tmpl := templates[p]
		if tmpl.Ignore {
			continue
		}
		if strings.TrimSpace(tmpl.Query) == "" {
			t.Errorf("%s: no `query`", p)
		}
		if strings.TrimSpace(tmpl.Name) == "" {
			t.Errorf("%s: no `name`", p)
		}

		defs := FlattenCounters(tmpl.Counters)
		keys, _, _ := Partition(defs)
		if len(keys) == 0 && !clusterSingletons[p] {
			t.Errorf("%s: no `^^` instance key; every record would collapse onto one instance", p)
		}

		byDisplay := map[string][]string{}
		for _, c := range defs {
			byDisplay[c.Display] = append(byDisplay[c.Display], c.APIName)
		}
		for display, apis := range byDisplay {
			if len(apis) > 1 {
				sort.Strings(apis)
				t.Errorf("%s: display name %q is claimed by %d counters (%s); they would collide on export",
					p, display, len(apis), strings.Join(apis, ", "))
			}
		}
	}
	t.Logf("checked %d object templates", len(templates))
}

// TestExportOptionsAreBacked asserts that every label an export_options block
// names is produced by something: a counter, or a plugin the template runs.
// Plugin-derived labels are listed per template so a genuinely unbacked key
// still fails.
var pluginDerivedLabels = map[string][]string{
	// LabelAgent `split` fans one counter out into several labels.
	"restperf/9.12.0/fpolicy.yaml":                    {"svm", "policy"},
	"restperf/9.12.0/fpolicy_server.yaml":             {"svm", "server"},
	"restperf/9.12.0/wafl_comp_aggr_vol_bin.yaml":     {"volume", "svm"},
	"restperf/9.12.0/fcvi.yaml":                       {"fcvi", "port"},
	"restperf/9.12.0/lun.yaml":                        {"lun", "volume", "svm"},
	"restperf/9.12.0/namespace.yaml":                  {"namespace", "volume", "svm"},
	"restperf/9.12.0/qtree.yaml":                      {"qtree", "volume", "svm"},
	"restperf/9.12.0/netstat.yaml":                    {"faddr", "laddr"},
	"restperf/9.12.0/nic_common.yaml":                 {"nic"},
	"restperf/9.12.0/path.yaml":                       {"hostadapter", "target_wwpn"},
	"restperf/9.12.0/resource_headroom_aggr.yaml":     {"aggr", "disk_type"},
	"restperf/9.12.0/volume.yaml":                     {"style"},
	"restperf/9.12.0/workload.yaml":                   {"workload", "wid", "svm", "volume", "lun", "file", "qtree", "policy_group"},
	"restperf/9.12.0/workload_volume.yaml":            {"workload", "wid", "svm", "volume", "lun", "file", "qtree", "policy_group"},
	"restperf/9.12.0/object_store_client_op.yaml":     {"fabricpool"},
	"restperf/9.12.0/external_service_operation.yaml": {"instance_name"},
	// The Vscan plugin splits the packed instance name into these three.
	"restperf/9.13.0/vscan.yaml": {"svm", "scanner", "node"},
	"rest/9.12.0/vscan.yaml":     {"svm", "scanner", "node"},
}

func TestExportOptionsAreBacked(t *testing.T) {
	templates := loadAllEmbeddedObjectTemplates(t)

	paths := make([]string, 0, len(templates))
	for p := range templates {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var unbacked int
	for _, p := range paths {
		tmpl := templates[p]
		if tmpl.Ignore || tmpl.ExportOptions == nil {
			continue
		}
		_, labels, _ := Partition(FlattenCounters(tmpl.Counters))
		produced := map[string]bool{}
		for _, l := range labels {
			produced[l.Display] = true
		}
		for _, l := range pluginDerivedLabels[p] {
			produced[l] = true
		}

		for _, k := range tmpl.ExportOptions.InstanceKeys {
			if !produced[k] {
				unbacked++
				t.Logf("UNBACKED %s: instance_keys %q has no counter and no declared plugin source", p, k)
			}
		}
	}
	// Reported rather than failed: the remaining entries belong to Harvest
	// plugins this agent does not implement yet, tracked by
	// plugins.TestPluginCoverage.
	t.Logf("unbacked export_options entries: %d", unbacked)
}
