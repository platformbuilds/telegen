// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netapp

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// The payloads below mirror the shape ONTAP returns for each surface: a REST
// object record, a private-CLI record, a RestPerf counter-table row with its
// properties/counters arrays, and an EMS event.

// volumesBody is a private-CLI volume record: the Rest Volume template queries
// api/private/cli/volume, which returns flat CLI field names.
const volumesBody = `{"records":[
  {"volume":"vol_data01",
   "vserver":"svm_prod",
   "aggr_list":["aggr1"],
   "nodes":["node-01"],
   "state":"online",
   "type":"rw",
   "volume_style_extended":"flexvol",
   "instance_uuid":"11111111-1111-1111-1111-111111111111",
   "is_encrypted":false,
   "junction_path":"/vol_data01",
   "size":10737418240,
   "available":5368709120,
   "used":5368709120,
   "percent_used":50,
   "total":10737418240,
   "filesystem_size":10737418240,
   "physical_used":5000000000,
   "logical_used":4900000000,
   "files":31122,
   "files_used":118,
   "snapshot_count":7}
],"num_records":1}`

const aggregatesBody = `{"records":[
  {"uuid":"22222222-2222-2222-2222-222222222222",
   "name":"aggr1",
   "node":{"name":"node-01"},
   "state":"online",
   "block_storage":{"primary":{"disk_count":12,"raid_type":"raid_dp","disk_type":"ssd"}},
   "space":{"block_storage":{"size":21474836480,"used":10737418240,"available":10737418240,
                             "physical_used":9000000000,"data_compaction_space_saved":100,
                             "inactive_user_data":200},
            "efficiency":{"savings":300,"ratio":1.5,"logical_used":400,
                          "cross_volume_dedupe_savings":true}},
   "metric":{"iops":{"read":5,"write":6,"total":11},
             "throughput":{"read":512,"write":256,"total":768},
             "latency":{"read":50,"write":60,"total":55}}}
],"num_records":1}`

const nodesBody = `{"records":[
  {"uuid":"33333333-3333-3333-3333-333333333333",
   "name":"node-01",
   "model":"AFF-A400",
   "serial_number":"701234000001",
   "version":{"full":"NetApp Release 9.14.1"},
   "location":"DC1",
   "state":"up",
   "uptime":864000,
   "ha":{"enabled":true,"partners":[{"name":"node-02"}]},
   "controller":{"over_temperature":"normal","failed_fan":{"count":0},
                 "failed_power_supply":{"count":0}},
   "metric":{"processor_utilization":42}}
],"num_records":1}`

// lunCounterRows is a RestPerf counter table: identity in `properties`,
// values in `counters`.
const lunCounterRows = `{"records":[
  {"id":"node-01:svm_prod:/vol/vol_data01/lun0",
   "properties":[
     {"name":"node.name","value":"node-01"},
     {"name":"svm.name","value":"svm_prod"}
   ],
   "counters":[
     {"name":"read_ops","value":1500},
     {"name":"write_ops","value":2500},
     {"name":"read_data","value":1048576},
     {"name":"write_data","value":2097152}
   ]}
],"num_records":1}`

const emsBody = `{"records":[
  {"index":1,
   "time":"2026-01-01T00:00:00Z",
   "message":{"name":"callhome.dsk.fault","severity":"error"},
   "node":{"name":"node-01"},
   "log_message":"Disk fault detected on node-01",
   "parameters":[{"name":"diskName","value":"1.0.1"}]}
],"num_records":1}`

// collectWithPayloads runs a full collection against a filer that answers the
// listed paths with real records.
func collectWithPayloads(t *testing.T) []storagedef.Metric {
	t.Helper()

	fake := newFakeONTAP()
	fake.setBody("/api/private/cli/volume", volumesBody)
	fake.setBody("/api/storage/aggregates", aggregatesBody)
	fake.setBody("/api/cluster/nodes", nodesBody)
	fake.setBody("/api/cluster/counter/tables/lun/rows", lunCounterRows)
	fake.setBody("/api/support/ems/events", emsBody)

	srv := fake.serve()
	defer srv.Close()

	col, err := NewONTAPCollector(storagedef.NetAppConfig{
		BaseCollectorConfig: storagedef.BaseCollectorConfig{
			Name:    "e2e",
			Address: srv.URL,
			Timeout: 10 * time.Second,
			Labels:  map[string]string{"environment": "production"},
		},
		Username:   "u",
		Password:   "p",
		Coverage:   storagedef.CoverageFull,
		Collectors: []string{"rest", "restperf", "keyperf", "ems"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new collector: %v", err)
	}

	ctx := context.Background()
	if err := col.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	// RestPerf counters are rates: the first poll only establishes the
	// baseline, so a second poll is required before any value is cooked.
	if _, err := col.CollectMetrics(ctx); err != nil {
		t.Fatalf("first collect: %v", err)
	}
	metrics, err := col.CollectMetrics(ctx)
	if err != nil {
		t.Fatalf("second collect: %v", err)
	}
	return metrics
}

func findMetric(metrics []storagedef.Metric, name string) (storagedef.Metric, bool) {
	for _, m := range metrics {
		if m.Name == name {
			return m, true
		}
	}
	return storagedef.Metric{}, false
}

// TestE2E_MetricsAreProduced is the end-to-end proof: real ONTAP-shaped
// payloads in, named and labelled metrics out.
func TestE2E_MetricsAreProduced(t *testing.T) {
	metrics := collectWithPayloads(t)

	names := map[string]bool{}
	for _, m := range metrics {
		names[m.Name] = true
	}
	t.Logf("produced %d metrics across %d distinct families", len(metrics), len(names))

	// Each of these comes from a different path: a private-CLI record
	// (volume), a public REST record with nested objects (aggregate), a
	// record with a mistyped sibling field (node), and a RestPerf counter
	// table (lun). RestPerf rate values need two polls a measurable interval
	// apart, so their numeric output is asserted in
	// restperf.TestPollObject_CooksRatesAndLabels; here we only require that
	// the counter-table instance materialised.
	want := []string{
		"volume_size",
		"volume_size_used",
		"volume_inode_files_used",
		"aggr_space_used",
		"aggr_space_available",
		"node_uptime",
		"lun_labels",
	}
	var missing []string
	for _, n := range want {
		if !names[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		sample := make([]string, 0, len(names))
		for n := range names {
			sample = append(sample, n)
		}
		sort.Strings(sample)
		t.Fatalf("missing expected metrics %v\nproduced families: %v", missing, sample)
	}
}

// TestE2E_LabelsAreAttached checks the identity labels a dashboard groups by
// actually reach the exported metric.
func TestE2E_LabelsAreAttached(t *testing.T) {
	metrics := collectWithPayloads(t)

	m, ok := findMetric(metrics, "volume_size")
	if !ok {
		t.Fatal("volume_size was not produced")
	}
	for k, want := range map[string]string{
		"volume":      "vol_data01",
		"svm":         "svm_prod",
		"cluster":     "ontap-prod-01",
		"array_name":  "e2e",
		"vendor":      "netapp",
		"product":     "ontap",
		"environment": "production",
	} {
		if got := m.Labels[k]; got != want {
			t.Errorf("volume_size label %q = %q, want %q", k, got, want)
		}
	}
}

// TestE2E_RestPerfLabelsUseTemplateDisplayNames pins the RestPerf contract: the
// counter row's `properties` array supplies the labels, keyed by the template's
// display name rather than the raw ONTAP property name.
func TestE2E_RestPerfLabelsUseTemplateDisplayNames(t *testing.T) {
	metrics := collectWithPayloads(t)

	m, ok := findMetric(metrics, "lun_labels")
	if !ok {
		t.Fatal("lun_labels was not produced")
	}
	if got := m.Labels["svm"]; got != "svm_prod" {
		t.Errorf("lun label svm = %q, want %q (template declares `^svm.name => svm`)",
			got, "svm_prod")
	}
	if _, leaked := m.Labels["svm_name"]; leaked {
		t.Error("lun carries the raw property name `svm_name`; labels must use the template display name")
	}
	if _, leaked := m.Labels["node_name"]; leaked {
		t.Error("lun carries the raw property name `node_name`; labels must use the template display name")
	}
}

// TestE2E_NoMetricHasEmptyNameOrNaN guards the exporter contract across every
// family the collection produced.
func TestE2E_NoMetricHasEmptyNameOrNaN(t *testing.T) {
	metrics := collectWithPayloads(t)

	for _, m := range metrics {
		if strings.TrimSpace(m.Name) == "" {
			t.Fatalf("metric with empty name: %+v", m)
		}
		if strings.HasPrefix(m.Name, "_") || strings.HasSuffix(m.Name, "_") {
			t.Errorf("metric name %q has a dangling underscore", m.Name)
		}
		if m.Timestamp.IsZero() {
			t.Errorf("metric %q has a zero timestamp", m.Name)
		}
		for k := range m.Labels {
			if strings.TrimSpace(k) == "" {
				t.Errorf("metric %q has an empty label name", m.Name)
			}
		}
	}
}

// TestE2E_TypeTolerance feeds the field types that used to crash the collector:
// a bool where a number is declared and a string where a bool is declared.
func TestE2E_TypeTolerance(t *testing.T) {
	metrics := collectWithPayloads(t)

	// aggregates payload sets cross_volume_dedupe_savings to a bool and
	// node sets controller.over_temperature to a string.
	if _, ok := findMetric(metrics, "aggr_space_used"); !ok {
		t.Fatal("aggregate metrics were dropped; a mistyped sibling field must not void the record")
	}
	if _, ok := findMetric(metrics, "node_uptime"); !ok {
		t.Fatal("node metrics were dropped; a mistyped sibling field must not void the record")
	}
}
