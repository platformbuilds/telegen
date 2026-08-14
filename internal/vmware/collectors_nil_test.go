// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"testing"
	"time"

	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

func hasMetric(metrics []string, want string) bool {
	for _, m := range metrics {
		if m == want {
			return true
		}
	}
	return false
}

func metricNames(out []vmwareMetric) []string {
	names := make([]string, 0, len(out))
	for _, m := range out {
		names = append(names, m.Name)
	}
	return names
}

type vmwareMetric = struct {
	Name   string
	Labels map[string]string
}

func collectSinkMetrics(sink *metricSink) []vmwareMetric {
	ms := sink.metrics()
	out := make([]vmwareMetric, 0, len(ms))
	for _, m := range ms {
		out = append(out, vmwareMetric{Name: m.Name, Labels: m.Labels})
	}
	return out
}

func TestCollectHostFromData_NilHardware(t *testing.T) {
	t.Parallel()

	s := &vcSession{target: "vc", ctx: context.Background(), interval: 20, cfg: vmwaredef.Config{CollectInterval: time.Minute, Interval: 20}}
	sink := &metricSink{timestamp: time.Now().UTC()}
	st := newTargetState()
	hosts := []mo.HostSystem{
		{
			ManagedEntity: mo.ManagedEntity{
				ExtensibleManagedObject: mo.ExtensibleManagedObject{
					Self: types.ManagedObjectReference{Type: "HostSystem", Value: "host-1"},
				},
				Parent: &types.ManagedObjectReference{Type: "ClusterComputeResource", Value: "domain-c7"},
			},
			Summary: types.HostListSummary{
				Config:   types.HostConfigSummary{Name: "esx-1"},
				Hardware: nil,
			},
			Runtime: types.HostRuntimeInfo{
				PowerState:        "poweredOn",
				ConnectionState:   "connected",
				InMaintenanceMode: false,
			},
		},
	}

	if err := collectHostFromData(s, sink, st, testLogger(), hosts); err != nil {
		t.Fatalf("collectHostFromData: %v", err)
	}
	got := metricNames(collectSinkMetrics(sink))
	if !hasMetric(got, "vmware_host_info") {
		t.Fatal("vmware_host_info missing")
	}
	if hasMetric(got, "vmware_host_hardware_info") {
		t.Fatal("vmware_host_hardware_info should be skipped when hardware is nil")
	}
	if hasMetric(got, "vmware_host_cpu_corecount") {
		t.Fatal("vmware_host_cpu_corecount should be skipped when hardware is nil")
	}
}

func TestCollectHostFromData_NilProduct(t *testing.T) {
	t.Parallel()

	s := &vcSession{target: "vc", ctx: context.Background(), interval: 20, cfg: vmwaredef.Config{CollectInterval: time.Minute, Interval: 20}}
	sink := &metricSink{timestamp: time.Now().UTC()}
	st := newTargetState()
	hosts := []mo.HostSystem{
		{
			ManagedEntity: mo.ManagedEntity{
				ExtensibleManagedObject: mo.ExtensibleManagedObject{
					Self: types.ManagedObjectReference{Type: "HostSystem", Value: "host-1"},
				},
				Parent: &types.ManagedObjectReference{Type: "ClusterComputeResource", Value: "domain-c7"},
			},
			Summary: types.HostListSummary{
				Config: types.HostConfigSummary{Name: "esx-1", Product: nil},
				Hardware: &types.HostHardwareSummary{
					Vendor:        "Dell",
					Model:         "R750",
					CpuModel:      "Xeon",
					NumCpuCores:   16,
					NumCpuThreads: 32,
					CpuMhz:        2200,
					MemorySize:    128,
				},
			},
			Runtime: types.HostRuntimeInfo{
				PowerState:        "poweredOn",
				ConnectionState:   "connected",
				InMaintenanceMode: false,
			},
		},
	}

	if err := collectHostFromData(s, sink, st, testLogger(), hosts); err != nil {
		t.Fatalf("collectHostFromData: %v", err)
	}
	got := metricNames(collectSinkMetrics(sink))
	if !hasMetric(got, "vmware_host_hardware_info") {
		t.Fatal("vmware_host_hardware_info missing")
	}
	if hasMetric(got, "vmware_host_software_info") {
		t.Fatal("vmware_host_software_info should be skipped when product is nil")
	}
}

func TestCollectHostFromData_NilParent(t *testing.T) {
	t.Parallel()

	s := &vcSession{target: "vc", ctx: context.Background(), interval: 20, cfg: vmwaredef.Config{CollectInterval: time.Minute, Interval: 20}}
	sink := &metricSink{timestamp: time.Now().UTC()}
	st := newTargetState()
	hosts := []mo.HostSystem{
		{
			ManagedEntity: mo.ManagedEntity{
				ExtensibleManagedObject: mo.ExtensibleManagedObject{
					Self: types.ManagedObjectReference{Type: "HostSystem", Value: "host-1"},
				},
			},
			Summary: types.HostListSummary{
				Config:   types.HostConfigSummary{Name: "esx-1"},
				Hardware: &types.HostHardwareSummary{},
			},
			Runtime: types.HostRuntimeInfo{
				PowerState:        "poweredOn",
				ConnectionState:   "connected",
				InMaintenanceMode: false,
			},
		},
	}

	if err := collectHostFromData(s, sink, st, testLogger(), hosts); err != nil {
		t.Fatalf("collectHostFromData: %v", err)
	}
	found := false
	for _, m := range sink.metrics() {
		if m.Name == "vmware_host_info" {
			found = true
			if got := m.Labels["cmo"]; got != "" {
				t.Fatalf("cmo label = %q, want empty string", got)
			}
		}
	}
	if !found {
		t.Fatal("vmware_host_info missing")
	}
}

func TestCollectVMFromData_NilRuntimeHost(t *testing.T) {
	t.Parallel()

	s := &vcSession{target: "vc", ctx: context.Background(), interval: 20, cfg: vmwaredef.Config{CollectInterval: time.Minute, Interval: 20}}
	sink := &metricSink{timestamp: time.Now().UTC()}
	st := newTargetState()
	vms := []mo.VirtualMachine{
		{
			ManagedEntity: mo.ManagedEntity{
				ExtensibleManagedObject: mo.ExtensibleManagedObject{
					Self: types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-1"},
				},
			},
			Summary: types.VirtualMachineSummary{
				Config: types.VirtualMachineConfigSummary{
					Name:         "vm-1",
					NumCpu:       2,
					MemorySizeMB: 4096,
				},
			},
			Runtime: types.VirtualMachineRuntimeInfo{
				PowerState: "poweredOn",
				Host:       nil,
			},
		},
	}

	if err := collectVMFromData(s, sink, st, testLogger(), vms); err != nil {
		t.Fatalf("collectVMFromData: %v", err)
	}
	for _, m := range sink.metrics() {
		if m.Name == "vmware_vm_info" || m.Name == "vmware_vm_cpu_corecount" || m.Name == "vmware_vm_mem_capacity" {
			if got := m.Labels["hostmo"]; got != "" {
				t.Fatalf("%s hostmo = %q, want empty string", m.Name, got)
			}
		}
	}
}

func TestCollectDatastoreFromData_NilRefs(t *testing.T) {
	t.Parallel()

	s := &vcSession{target: "vc", ctx: context.Background(), interval: 20, cfg: vmwaredef.Config{CollectInterval: time.Minute, Interval: 20}}
	sink := &metricSink{timestamp: time.Now().UTC()}
	ds := []mo.Datastore{
		{
			ManagedEntity: mo.ManagedEntity{
				ExtensibleManagedObject: mo.ExtensibleManagedObject{
					Self: types.ManagedObjectReference{Type: "Datastore", Value: "datastore-1"},
				},
			},
			Summary: types.DatastoreSummary{
				Datastore:  nil,
				Name:       "ds-1",
				Type:       "VMFS",
				Url:        "ds:///vmfs/volumes/foo",
				Capacity:   100,
				FreeSpace:  50,
				Accessible: true,
			},
		},
	}

	if err := collectDatastoreFromData(s, sink, nil, testLogger(), ds); err != nil {
		t.Fatalf("collectDatastoreFromData: %v", err)
	}
	for _, m := range sink.metrics() {
		if m.Name == "vmware_datastore_info" || m.Name == "vmware_datastore_capacity" || m.Name == "vmware_datastore_free" || m.Name == "vmware_datastore_accessible" {
			if got := m.Labels["dsmo"]; got != "" {
				t.Fatalf("%s dsmo = %q, want empty string", m.Name, got)
			}
		}
	}
}

func TestCollectDatastoreFromData_CadenceGate(t *testing.T) {
	t.Parallel()

	st := newTargetState()
	s := &vcSession{target: "vc", ctx: context.Background(), interval: 20, cfg: vmwaredef.Config{CollectInterval: time.Minute, Interval: 20}}
	ds := []mo.Datastore{
		{
			ManagedEntity: mo.ManagedEntity{
				ExtensibleManagedObject: mo.ExtensibleManagedObject{
					Self: types.ManagedObjectReference{Type: "Datastore", Value: "datastore-1"},
				},
			},
			Summary: types.DatastoreSummary{
				Datastore:  &types.ManagedObjectReference{Type: "Datastore", Value: "datastore-1"},
				Name:       "ds-1",
				Type:       "VMFS",
				Url:        "ds:///vmfs/volumes/foo",
				Capacity:   100,
				FreeSpace:  50,
				Accessible: true,
			},
		},
	}

	t0 := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	assertInventoryGauges := func(sink *metricSink, when string) {
		got := metricNames(collectSinkMetrics(sink))
		for _, name := range []string{
			"vmware_datastore_info",
			"vmware_datastore_capacity",
			"vmware_datastore_free",
			"vmware_datastore_accessible",
		} {
			if !hasMetric(got, name) {
				t.Fatalf("%s missing inventory metric %s", when, name)
			}
		}
	}

	sink1 := &metricSink{timestamp: t0}
	if err := collectDatastoreFromData(s, sink1, st, testLogger(), ds); err != nil {
		t.Fatalf("first collectDatastoreFromData: %v", err)
	}
	assertInventoryGauges(sink1, "first call")
	if got := st.lastDatastorePerf(); !got.Equal(t0) {
		t.Fatalf("first scrape timestamp = %v, want %v", got, t0)
	}

	sink2 := &metricSink{timestamp: t0.Add(60 * time.Second)}
	if err := collectDatastoreFromData(s, sink2, st, testLogger(), ds); err != nil {
		t.Fatalf("second collectDatastoreFromData: %v", err)
	}
	assertInventoryGauges(sink2, "second call")
	if got := st.lastDatastorePerf(); !got.Equal(t0) {
		t.Fatalf("second scrape should be skipped; got %v want %v", got, t0)
	}

	t3 := t0.Add(301 * time.Second)
	sink3 := &metricSink{timestamp: t3}
	if err := collectDatastoreFromData(s, sink3, st, testLogger(), ds); err != nil {
		t.Fatalf("third collectDatastoreFromData: %v", err)
	}
	assertInventoryGauges(sink3, "third call")
	if got := st.lastDatastorePerf(); !got.Equal(t3) {
		t.Fatalf("third scrape timestamp = %v, want %v", got, t3)
	}
}
