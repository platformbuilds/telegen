// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	esxclisdk "github.com/mirastacklabs-ai/telegen/internal/vmware/esxcli"
	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

type fakeEsxcliRoundTripper struct {
	mu        sync.Mutex
	active    int
	peak      int
	sleep     time.Duration
	nicByName map[string]DriverInfo
}

func (f *fakeEsxcliRoundTripper) RoundTrip(_ context.Context, req, res soap.HasFault) error {
	f.mu.Lock()
	f.active++
	if f.active > f.peak {
		f.peak = f.active
	}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()
	if f.sleep > 0 {
		time.Sleep(f.sleep)
	}

	switch r := req.(type) {
	case *esxclisdk.RetrieveManagedMethodExecuterBody:
		_ = r
		out := res.(*esxclisdk.RetrieveManagedMethodExecuterBody)
		out.Res = &esxclisdk.RetrieveManagedMethodExecuterResponse{
			Returnval: &esxclisdk.ReflectManagedMethodExecuter{
				ManagedObjectReference: types.ManagedObjectReference{Type: "HostEsxCLI", Value: "ha-cli-handler"},
			},
		}
	case *esxclisdk.ExecuteSoapBody:
		out := res.(*esxclisdk.ExecuteSoapBody)
		switch r.Req.Method {
		case "vim.EsxCLI.storage.core.device.list":
			out.Res = &esxclisdk.ExecuteSoapResponse{
				Returnval: &esxclisdk.ReflectManagedMethodExecuterSoapResult{
					Response: `<StorageResponse>
						<DataObject><Vendor> DELL </Vendor><Model>PERC H730</Model><Revision> 1.0 </Revision></DataObject>
						<DataObject><Vendor> DELL </Vendor><Model>PERC H730</Model><Revision> 1.0 </Revision></DataObject>
						<DataObject><Vendor> DELL </Vendor><Model>PERC H730</Model><Revision> 2.0 </Revision></DataObject>
					</StorageResponse>`,
				},
			}
		case "vim.EsxCLI.network.nic.list":
			out.Res = &esxclisdk.ExecuteSoapResponse{
				Returnval: &esxclisdk.ReflectManagedMethodExecuterSoapResult{
					Response: `<NicListResponse>
						<DataObject><Name>vmnic0</Name><Description>nic-0</Description></DataObject>
						<DataObject><Name>vmnic1</Name><Description>nic-1</Description></DataObject>
					</NicListResponse>`,
				},
			}
		case "vim.EsxCLI.network.nic.get":
			nicName := "vmnic0"
			if len(r.Req.Argument) > 0 {
				if strings.Contains(r.Req.Argument[0].Val, "vmnic1") {
					nicName = "vmnic1"
				}
			}
			info := f.nicByName[nicName]
			out.Res = &esxclisdk.ExecuteSoapResponse{
				Returnval: &esxclisdk.ReflectManagedMethodExecuterSoapResult{
					Response: fmt.Sprintf(`<NicResponse><DriverInfo><Driver>%s</Driver><Version>%s</Version><FirmwareVersion>%s</FirmwareVersion></DriverInfo></NicResponse>`,
						info.Driver, info.Version, info.Firmware),
				},
			}
		default:
			return fmt.Errorf("unexpected method %q", r.Req.Method)
		}
	default:
		return fmt.Errorf("unexpected request type %T", req)
	}

	return nil
}

func testSessionWithRT(rt soap.RoundTripper) *vcSession {
	return &vcSession{
		target: "vc",
		client: &vim25.Client{RoundTripper: rt},
		ctx:    context.Background(),
		cfg:    vmwaredef.Config{CollectInterval: time.Minute, Interval: 20},
	}
}

func activeHost(name, moref string) mo.HostSystem {
	return mo.HostSystem{
		ManagedEntity: mo.ManagedEntity{
			ExtensibleManagedObject: mo.ExtensibleManagedObject{
				Self: types.ManagedObjectReference{Type: "HostSystem", Value: moref},
			},
		},
		Summary: types.HostListSummary{
			Config: types.HostConfigSummary{Name: name},
		},
		Runtime: types.HostRuntimeInfo{
			PowerState:        "poweredOn",
			ConnectionState:   "connected",
			InMaintenanceMode: false,
		},
	}
}

func TestCollectEsxcliStorageFromData_DedupAndTrim(t *testing.T) {
	t.Parallel()

	rt := &fakeEsxcliRoundTripper{}
	s := testSessionWithRT(rt)
	sink := &metricSink{timestamp: time.Now().UTC()}
	hosts := []mo.HostSystem{activeHost("esx-1", "host-1")}

	if err := collectEsxcliStorageFromData(s, sink, testLogger(), hosts); err != nil {
		t.Fatalf("collectEsxcliStorageFromData: %v", err)
	}

	var count int
	for _, m := range sink.metrics() {
		if m.Name != "vmware_esxcli_storage_driver" {
			continue
		}
		count++
		if m.Labels["vendor"] != "DELL" {
			t.Fatalf("vendor should be trimmed, got %q", m.Labels["vendor"])
		}
	}
	if count != 2 {
		t.Fatalf("expected deduplicated storage entries = 2, got %d", count)
	}
}

func TestCollectEsxcliHostNICFromData_Dedup(t *testing.T) {
	t.Parallel()

	rt := &fakeEsxcliRoundTripper{
		nicByName: map[string]DriverInfo{
			"vmnic0": {Driver: "ixgben", Version: "1.0", Firmware: "2.0"},
			"vmnic1": {Driver: "ixgben", Version: "1.0", Firmware: "2.0"},
		},
	}
	s := testSessionWithRT(rt)
	sink := &metricSink{timestamp: time.Now().UTC()}
	hosts := []mo.HostSystem{activeHost("esx-1", "host-1")}

	if err := collectEsxcliHostNICFromData(s, sink, testLogger(), hosts); err != nil {
		t.Fatalf("collectEsxcliHostNICFromData: %v", err)
	}

	var count int
	for _, m := range sink.metrics() {
		if m.Name == "vmware_esxcli_host_nic_driver" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected deduplicated NIC entries = 1, got %d", count)
	}
}

func TestCollectEsxcliHostNICFromData_ConcurrencyBound(t *testing.T) {
	t.Parallel()

	rt := &fakeEsxcliRoundTripper{
		sleep: 20 * time.Millisecond,
		nicByName: map[string]DriverInfo{
			"vmnic0": {Driver: "ixgben", Version: "1.0", Firmware: "2.0"},
			"vmnic1": {Driver: "ixgben", Version: "1.0", Firmware: "2.0"},
		},
	}
	s := testSessionWithRT(rt)
	sink := &metricSink{timestamp: time.Now().UTC()}
	hosts := make([]mo.HostSystem, 0, 20)
	for i := 0; i < 20; i++ {
		hosts = append(hosts, activeHost(fmt.Sprintf("esx-%d", i), fmt.Sprintf("host-%d", i)))
	}

	if err := collectEsxcliHostNICFromData(s, sink, testLogger(), hosts); err != nil {
		t.Fatalf("collectEsxcliHostNICFromData: %v", err)
	}
	if rt.peak > esxcliMaxConcurrentHosts {
		t.Fatalf("peak concurrency = %d, exceeds limit %d", rt.peak, esxcliMaxConcurrentHosts)
	}
}

func TestEsxcliCollectors_DefaultDisabled(t *testing.T) {
	t.Parallel()

	var collectors vmwaredef.Collectors
	if collectors.Enabled("esxcli_storage") {
		t.Fatal("esxcli_storage should be disabled by default")
	}
	if collectors.Enabled("esxcli_host_nic") {
		t.Fatal("esxcli_host_nic should be disabled by default")
	}
}
