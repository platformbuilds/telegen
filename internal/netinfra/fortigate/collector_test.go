package fortigate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedCollectionInstant is the hoisted per-cycle instant the collector would
// pass in. Tests assert it survives onto every emitted metric so a regression
// back to per-metric time.Now() is caught.
var fixedCollectionInstant = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func TestParseSystemStatusFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "system_status.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	base := map[string]string{"vendor": "fortinet", "device": "fg-1"}
	metrics, err := parseSystemStatus(data, base, fixedCollectionInstant)
	if err != nil {
		t.Fatalf("parseSystemStatus failed: %v", err)
	}
	for i, m := range metrics {
		if !m.Timestamp.Equal(fixedCollectionInstant) {
			t.Fatalf("metric %d: expected hoisted timestamp %v, got %v", i, fixedCollectionInstant, m.Timestamp)
		}
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics (info + uptime), got %d", len(metrics))
	}

	if metrics[0].Name != "netinfra_fortigate_device_info" {
		t.Fatalf("unexpected first metric: %s", metrics[0].Name)
	}
	if metrics[0].Labels["hostname"] != "fg-01" {
		t.Fatalf("expected hostname label, got %+v", metrics[0].Labels)
	}
	if metrics[1].Name != "netinfra_fortigate_uptime_seconds" || metrics[1].Value != 86400 {
		t.Fatalf("unexpected uptime metric: %+v", metrics[1])
	}
}

func TestParseInterfacesFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "interfaces.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	base := map[string]string{"vendor": "fortinet", "device": "fg-1"}
	metrics, err := parseInterfaces(data, base, fixedCollectionInstant)
	if err != nil {
		t.Fatalf("parseInterfaces failed: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 interface metrics, got %d", len(metrics))
	}
	for i, m := range metrics {
		if !m.Timestamp.Equal(fixedCollectionInstant) {
			t.Fatalf("metric %d: expected hoisted timestamp %v, got %v", i, fixedCollectionInstant, m.Timestamp)
		}
	}
	if metrics[0].Labels["interface"] != "port1" || metrics[0].Value != 1 {
		t.Fatalf("unexpected first interface metric: %+v", metrics[0])
	}
	if metrics[1].Labels["interface"] != "port2" || metrics[1].Value != 0 {
		t.Fatalf("unexpected second interface metric: %+v", metrics[1])
	}
}
