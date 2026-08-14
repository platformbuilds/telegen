// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package esxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

type fakeRoundTripper struct {
	executeResp *ExecuteSoapResponse
	mmeResp     *RetrieveManagedMethodExecuterResponse
	err         error
}

func (f *fakeRoundTripper) RoundTrip(_ context.Context, _ soap.HasFault, res soap.HasFault) error {
	if f.err != nil {
		return f.err
	}

	switch body := res.(type) {
	case *ExecuteSoapBody:
		body.Res = f.executeResp
	case *RetrieveManagedMethodExecuterBody:
		body.Res = f.mmeResp
	}
	return nil
}

func TestConfigArguments(t *testing.T) {
	args := ConfigArguments(map[string]string{"nicname": "vmnic0"})
	if len(args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(args))
	}
	if args[0].Name != "nicname" {
		t.Fatalf("arg name = %q, want nicname", args[0].Name)
	}
	if args[0].Val != "<nicname>vmnic0</nicname>" {
		t.Fatalf("arg val = %q", args[0].Val)
	}
}

func TestGetHostMME(t *testing.T) {
	rt := &fakeRoundTripper{
		mmeResp: &RetrieveManagedMethodExecuterResponse{
			Returnval: &ReflectManagedMethodExecuter{
				ManagedObjectReference: types.ManagedObjectReference{Type: "HostEsxCLI", Value: "ha-cli-handler"},
			},
		},
	}
	client := &vim25.Client{RoundTripper: rt}
	host := &types.ManagedObjectReference{Type: "HostSystem", Value: "host-1"}
	got, err := GetHostMME(context.Background(), client, host)
	if err != nil {
		t.Fatalf("GetHostMME: %v", err)
	}
	if got.Type != "HostEsxCLI" || got.Value != "ha-cli-handler" {
		t.Fatalf("unexpected MME ref %+v", *got)
	}
}

func TestGetSOAP_FaultAndNil(t *testing.T) {
	req := &ExecuteSoapRequest{}
	client := &vim25.Client{RoundTripper: &fakeRoundTripper{
		executeResp: &ExecuteSoapResponse{
			Returnval: &ReflectManagedMethodExecuterSoapResult{
				Fault: &ReflectManagedMethodExecuterSoapFault{FaultMsg: "permission denied"},
			},
		},
	}}
	var dst struct{}
	err := GetSOAP(context.Background(), client, req, &dst)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected fault message in error, got %v", err)
	}

	client = &vim25.Client{RoundTripper: &fakeRoundTripper{
		executeResp: &ExecuteSoapResponse{Returnval: nil},
	}}
	err = GetSOAP(context.Background(), client, req, &dst)
	if err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Fatalf("expected empty response error, got %v", err)
	}
}

type storageListFixture struct {
	DataObject []struct {
		Vendor   string `xml:"Vendor"`
		Model    string `xml:"Model"`
		Revision string `xml:"Revision"`
	} `xml:"DataObject"`
}

type nicListFixture struct {
	DataObject []struct {
		Name        string `xml:"Name"`
		Description string `xml:"Description"`
	} `xml:"DataObject"`
}

type nicGetFixture struct {
	DriverInfo struct {
		Driver          string `xml:"Driver"`
		Version         string `xml:"Version"`
		FirmwareVersion string `xml:"FirmwareVersion"`
	} `xml:"DriverInfo"`
}

func TestGetSOAP_XMLFixtures(t *testing.T) {
	t.Run("storage core device list", func(t *testing.T) {
		xmlBody := `<StorageResponse><DataObject><Vendor>DELL</Vendor><Model>PERC</Model><Revision>3.1</Revision></DataObject></StorageResponse>`
		client := &vim25.Client{RoundTripper: &fakeRoundTripper{
			executeResp: &ExecuteSoapResponse{
				Returnval: &ReflectManagedMethodExecuterSoapResult{Response: xmlBody},
			},
		}}
		var out storageListFixture
		if err := GetSOAP(context.Background(), client, &ExecuteSoapRequest{}, &out); err != nil {
			t.Fatalf("GetSOAP storage fixture: %v", err)
		}
		if len(out.DataObject) != 1 || out.DataObject[0].Vendor != "DELL" || out.DataObject[0].Model != "PERC" {
			t.Fatalf("unexpected storage fixture decode: %+v", out)
		}
	})

	t.Run("network nic list", func(t *testing.T) {
		xmlBody := `<NicListResponse><DataObject><Name>vmnic0</Name><Description>Intel NIC</Description></DataObject></NicListResponse>`
		client := &vim25.Client{RoundTripper: &fakeRoundTripper{
			executeResp: &ExecuteSoapResponse{
				Returnval: &ReflectManagedMethodExecuterSoapResult{Response: xmlBody},
			},
		}}
		var out nicListFixture
		if err := GetSOAP(context.Background(), client, &ExecuteSoapRequest{}, &out); err != nil {
			t.Fatalf("GetSOAP nic list fixture: %v", err)
		}
		if len(out.DataObject) != 1 || out.DataObject[0].Name != "vmnic0" {
			t.Fatalf("unexpected nic list decode: %+v", out)
		}
	})

	t.Run("network nic get", func(t *testing.T) {
		xmlBody := `<NicResponse><DriverInfo><Driver>ixgben</Driver><Version>1.0</Version><FirmwareVersion>2.0</FirmwareVersion></DriverInfo></NicResponse>`
		client := &vim25.Client{RoundTripper: &fakeRoundTripper{
			executeResp: &ExecuteSoapResponse{
				Returnval: &ReflectManagedMethodExecuterSoapResult{Response: xmlBody},
			},
		}}
		var out nicGetFixture
		if err := GetSOAP(context.Background(), client, &ExecuteSoapRequest{}, &out); err != nil {
			t.Fatalf("GetSOAP nic get fixture: %v", err)
		}
		if out.DriverInfo.Driver != "ixgben" || out.DriverInfo.Version != "1.0" || out.DriverInfo.FirmwareVersion != "2.0" {
			t.Fatalf("unexpected nic get decode: %+v", out)
		}
	})
}
