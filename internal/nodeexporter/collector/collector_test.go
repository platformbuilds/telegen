// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// testCollectorConfig creates a CollectorConfig for testing.
func testCollectorConfig(procPath, sysPath string) CollectorConfig {
	return CollectorConfig{
		Paths: PathConfig{
			ProcPath:   procPath,
			SysPath:    sysPath,
			RootfsPath: "/",
		},
		Logger: slog.Default(),
	}
}

// TestBondingCollector tests the bonding collector.
func TestBondingCollector(t *testing.T) {
	// Create mock sysfs structure
	tmpDir := t.TempDir()
	sysPath := filepath.Join(tmpDir, "sys")

	// Create bonding interface mock
	bondPath := filepath.Join(sysPath, "class/net/bond0/bonding")
	if err := os.MkdirAll(bondPath, 0755); err != nil {
		t.Fatalf("failed to create mock bonding path: %v", err)
	}

	// Write mock slaves file
	slavesFile := filepath.Join(bondPath, "slaves")
	if err := os.WriteFile(slavesFile, []byte("eth0 eth1\n"), 0644); err != nil {
		t.Fatalf("failed to write slaves file: %v", err)
	}

	cfg := testCollectorConfig("/proc", sysPath)
	collector, err := NewBondingCollector(cfg)
	if err != nil {
		t.Fatalf("NewBondingCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	_ = collector.Update(ch)
	close(ch)

	// Count metrics
	count := 0
	for range ch {
		count++
	}

	if count < 1 {
		t.Errorf("expected at least 1 metric, got %d", count)
	}
}

// TestEdacCollector tests the EDAC collector.
func TestEdacCollector(t *testing.T) {
	// Create mock sysfs structure
	tmpDir := t.TempDir()
	sysPath := filepath.Join(tmpDir, "sys")

	// Create EDAC memory controller mock
	mcPath := filepath.Join(sysPath, "devices/system/edac/mc/mc0")
	if err := os.MkdirAll(mcPath, 0755); err != nil {
		t.Fatalf("failed to create mock EDAC path: %v", err)
	}

	// Write mock error counts
	if err := os.WriteFile(filepath.Join(mcPath, "ce_count"), []byte("5\n"), 0644); err != nil {
		t.Fatalf("failed to write ce_count: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mcPath, "ue_count"), []byte("0\n"), 0644); err != nil {
		t.Fatalf("failed to write ue_count: %v", err)
	}

	cfg := testCollectorConfig("/proc", sysPath)
	collector, err := NewEdacCollector(cfg)
	if err != nil {
		t.Fatalf("NewEdacCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	_ = collector.Update(ch)
	close(ch)

	// Count metrics
	count := 0
	for range ch {
		count++
	}

	if count < 2 {
		t.Errorf("expected at least 2 metrics (ce_count and ue_count), got %d", count)
	}
}

// TestMdadmCollector tests the mdadm collector.
func TestMdadmCollector(t *testing.T) {
	// This test requires /proc/mdstat which may not exist
	// We test that the collector initializes correctly
	cfg := testCollectorConfig("/proc", "/sys")
	collector, err := NewMdadmCollector(cfg)
	if err != nil {
		t.Fatalf("NewMdadmCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	// This may return ErrNoData if no RAID arrays exist
	_ = collector.Update(ch)
	close(ch)
}

// TestZFSCollector tests the ZFS collector.
func TestZFSCollector(t *testing.T) {
	// Create mock procfs structure
	tmpDir := t.TempDir()
	procPath := filepath.Join(tmpDir, "proc")

	// Create ZFS arcstats mock
	arcPath := filepath.Join(procPath, "spl/kstat/zfs")
	if err := os.MkdirAll(arcPath, 0755); err != nil {
		t.Fatalf("failed to create mock ZFS path: %v", err)
	}

	// Write mock arcstats
	arcstats := `1 0 0x01 86 3456 7654321 765432
name                            type data
hits                            4    12345678
misses                          4    123456
size                            4    1073741824
`
	if err := os.WriteFile(filepath.Join(arcPath, "arcstats"), []byte(arcstats), 0644); err != nil {
		t.Fatalf("failed to write arcstats: %v", err)
	}

	cfg := testCollectorConfig(procPath, "/sys")
	collector, err := NewZFSCollector(cfg)
	if err != nil {
		t.Fatalf("NewZFSCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	err = collector.Update(ch)
	if err != nil {
		t.Errorf("ZFS Update failed: %v", err)
	}
	close(ch)

	// Count metrics
	count := 0
	for range ch {
		count++
	}

	if count < 1 {
		t.Errorf("expected at least 1 metric, got %d", count)
	}
}

// TestNFSCollector tests the NFS client collector.
func TestNFSCollector(t *testing.T) {
	// This test requires /proc/net/rpc/nfs which may not exist
	cfg := testCollectorConfig("/proc", "/sys")
	collector, err := NewNFSCollector(cfg)
	if err != nil {
		t.Fatalf("NewNFSCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	// This may return ErrNoData if NFS is not available
	_ = collector.Update(ch)
	close(ch)
}

// TestNFSdCollector tests the NFS server collector.
func TestNFSdCollector(t *testing.T) {
	// This test requires /proc/net/rpc/nfsd which may not exist
	cfg := testCollectorConfig("/proc", "/sys")
	collector, err := NewNFSdCollector(cfg)
	if err != nil {
		t.Fatalf("NewNFSdCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	// This may return ErrNoData if NFSd is not available
	_ = collector.Update(ch)
	close(ch)
}

// TestCPUCollector tests the CPU collector.
func TestCPUCollector(t *testing.T) {
	cfg := testCollectorConfig("/proc", "/sys")
	collector, err := NewCPUCollector(cfg)
	if err != nil {
		t.Fatalf("NewCPUCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 1000)
	if err := collector.Update(ch); err != nil {
		t.Errorf("CPU Update failed: %v", err)
	}
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count == 0 {
		t.Error("expected CPU metrics, got none")
	}
}

// TestMemInfoCollector tests the meminfo collector.
func TestMemInfoCollector(t *testing.T) {
	cfg := testCollectorConfig("/proc", "/sys")
	collector, err := NewMeminfoCollector(cfg)
	if err != nil {
		t.Fatalf("NewMeminfoCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 1000)
	if err := collector.Update(ch); err != nil {
		t.Errorf("MemInfo Update failed: %v", err)
	}
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count == 0 {
		t.Error("expected meminfo metrics, got none")
	}
}

// TestLoadavgCollector tests the loadavg collector.
func TestLoadavgCollector(t *testing.T) {
	cfg := testCollectorConfig("/proc", "/sys")
	collector, err := NewLoadavgCollector(cfg)
	if err != nil {
		t.Fatalf("NewLoadavgCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	if err := collector.Update(ch); err != nil {
		t.Errorf("Loadavg Update failed: %v", err)
	}
	close(ch)

	count := 0
	for range ch {
		count++
	}

	// Should have at least load1, load5, load15
	if count < 3 {
		t.Errorf("expected at least 3 loadavg metrics, got %d", count)
	}
}

// TestUnameCollector tests the uname collector.
func TestUnameCollector(t *testing.T) {
	cfg := testCollectorConfig("/proc", "/sys")
	collector, err := NewUnameCollector(cfg)
	if err != nil {
		t.Fatalf("NewUnameCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	if err := collector.Update(ch); err != nil {
		t.Errorf("Uname Update failed: %v", err)
	}
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count == 0 {
		t.Error("expected uname metrics, got none")
	}
}

// TestTimeCollector tests the time collector.
func TestTimeCollector(t *testing.T) {
	cfg := testCollectorConfig("/proc", "/sys")
	collector, err := NewTimeCollector(cfg)
	if err != nil {
		t.Fatalf("NewTimeCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 100)
	if err := collector.Update(ch); err != nil {
		t.Errorf("Time Update failed: %v", err)
	}
	close(ch)

	count := 0
	for range ch {
		count++
	}

	// Should have at least node_time_seconds
	if count < 1 {
		t.Errorf("expected at least 1 time metric, got %d", count)
	}
}
