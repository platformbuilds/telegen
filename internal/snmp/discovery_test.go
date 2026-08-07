package snmp

import (
	"log/slog"
	"testing"
	"time"
)

func TestDiscoverySweepStaleDevices(t *testing.T) {
	t.Parallel()

	d, err := NewDiscovery(DiscoveryConfig{Interval: time.Minute}, nil, slog.Default())
	if err != nil {
		t.Fatalf("new discovery: %v", err)
	}
	now := time.Now()
	d.devices["fresh"] = &DiscoveredDevice{Address: "fresh", LastSeenAt: now}
	d.devices["stale"] = &DiscoveredDevice{Address: "stale", LastSeenAt: now.Add(-10 * time.Minute)}

	d.sweepStaleDevices()

	if _, ok := d.devices["fresh"]; !ok {
		t.Fatal("expected fresh device to be retained")
	}
	if _, ok := d.devices["stale"]; ok {
		t.Fatal("expected stale device to be evicted")
	}
}

func TestStaleDeviceTTLMinimum(t *testing.T) {
	t.Parallel()
	if got := staleDeviceTTL(10 * time.Second); got < 5*time.Minute {
		t.Fatalf("expected minimum stale TTL of 5m, got %s", got)
	}
}
