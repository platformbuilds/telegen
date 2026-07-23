package paloalto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSystemInfoFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "system_info.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	base := map[string]string{"vendor": "paloalto", "device": "pa-1"}
	metrics, err := parseSystemInfo(data, base)
	if err != nil {
		t.Fatalf("parseSystemInfo failed: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics (info + uptime), got %d", len(metrics))
	}

	if metrics[0].Name != "netinfra_paloalto_device_info" {
		t.Fatalf("unexpected metric name: %s", metrics[0].Name)
	}
	if metrics[0].Labels["hostname"] != "pa-fw-01" {
		t.Fatalf("expected hostname label, got %+v", metrics[0].Labels)
	}
	if metrics[1].Name != "netinfra_paloalto_uptime_seconds" {
		t.Fatalf("unexpected uptime metric name: %s", metrics[1].Name)
	}
	if metrics[1].Value != 468672 {
		t.Fatalf("unexpected uptime seconds: %v", metrics[1].Value)
	}
}

func TestParseInterfacesFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "interfaces.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	base := map[string]string{"vendor": "paloalto", "device": "pa-1"}
	metrics, err := parseInterfaces(data, base)
	if err != nil {
		t.Fatalf("parseInterfaces failed: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 interface metrics, got %d", len(metrics))
	}

	if metrics[0].Labels["interface"] != "ethernet1/1" || metrics[0].Value != 1 {
		t.Fatalf("unexpected first interface metric: %+v", metrics[0])
	}
	if metrics[1].Labels["interface"] != "ethernet1/2" || metrics[1].Value != 0 {
		t.Fatalf("unexpected second interface metric: %+v", metrics[1])
	}
}
