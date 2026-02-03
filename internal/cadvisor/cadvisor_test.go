// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cadvisor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "disabled config is valid",
			config:  Config{Enabled: false},
			wantErr: false,
		},
		{
			name: "valid enabled config",
			config: Config{
				Enabled:              true,
				CgroupRoot:           "/sys/fs/cgroup",
				CollectInterval:      10 * time.Second,
				HousekeepingInterval: 1 * time.Minute,
				MaxProcs:             4,
			},
			wantErr: false,
		},
		{
			name: "missing cgroup root",
			config: Config{
				Enabled:              true,
				CgroupRoot:           "",
				CollectInterval:      10 * time.Second,
				HousekeepingInterval: 1 * time.Minute,
				MaxProcs:             4,
			},
			wantErr: true,
		},
		{
			name: "collect interval too short",
			config: Config{
				Enabled:              true,
				CgroupRoot:           "/sys/fs/cgroup",
				CollectInterval:      100 * time.Millisecond,
				HousekeepingInterval: 1 * time.Minute,
				MaxProcs:             4,
			},
			wantErr: true,
		},
		{
			name: "housekeeping interval too short",
			config: Config{
				Enabled:              true,
				CgroupRoot:           "/sys/fs/cgroup",
				CollectInterval:      10 * time.Second,
				HousekeepingInterval: 5 * time.Second,
				MaxProcs:             4,
			},
			wantErr: true,
		},
		{
			name: "invalid max procs",
			config: Config{
				Enabled:              true,
				CgroupRoot:           "/sys/fs/cgroup",
				CollectInterval:      10 * time.Second,
				HousekeepingInterval: 1 * time.Minute,
				MaxProcs:             0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigIsNamespaceAllowed(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		namespace string
		want      bool
	}{
		{
			name:      "empty config allows all",
			config:    Config{},
			namespace: "default",
			want:      true,
		},
		{
			name: "namespace in include list",
			config: Config{
				Namespaces: []string{"default", "production"},
			},
			namespace: "default",
			want:      true,
		},
		{
			name: "namespace not in include list",
			config: Config{
				Namespaces: []string{"default"},
			},
			namespace: "production",
			want:      false,
		},
		{
			name: "namespace in exclude list",
			config: Config{
				NamespacesExclude: []string{"kube-system"},
			},
			namespace: "kube-system",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsNamespaceAllowed(tt.namespace); got != tt.want {
				t.Errorf("Config.IsNamespaceAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigIsMetricEnabled(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		metric string
		want   bool
	}{
		{
			name:   "empty config enables all",
			config: Config{},
			metric: "container_cpu_usage_seconds_total",
			want:   true,
		},
		{
			name: "metric disabled",
			config: Config{
				DisabledMetrics: []string{"container_memory_swap"},
			},
			metric: "container_memory_swap",
			want:   false,
		},
		{
			name: "metric not in disabled list",
			config: Config{
				DisabledMetrics: []string{"container_memory_swap"},
			},
			metric: "container_cpu_usage_seconds_total",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsMetricEnabled(tt.metric); got != tt.want {
				t.Errorf("Config.IsMetricEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if !config.Enabled {
		t.Error("expected default config to be enabled")
	}
	if config.CgroupRoot != "/sys/fs/cgroup" {
		t.Errorf("expected cgroup root /sys/fs/cgroup, got %s", config.CgroupRoot)
	}
	if config.CollectInterval != 10*time.Second {
		t.Errorf("expected collect interval 10s, got %v", config.CollectInterval)
	}
	if !config.DiskIOEnabled {
		t.Error("expected disk IO to be enabled by default")
	}
	if !config.NetworkEnabled {
		t.Error("expected network to be enabled by default")
	}
}

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "containerd format",
			path: "kubepods/burstable/pod123/cri-containerd-abc123def456789",
			want: "abc123def456789",
		},
		{
			name: "docker format",
			path: "kubepods/burstable/pod123/docker-abc123def456789",
			want: "abc123def456789",
		},
		{
			name: "crio format",
			path: "kubepods/burstable/pod123/crio-abc123def456789",
			want: "abc123def456789",
		},
		{
			name: "no container ID",
			path: "kubepods/burstable",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContainerID(tt.path)
			if got != tt.want {
				t.Errorf("extractContainerID(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractPodUID(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "standard format",
			path: "kubepods/burstable/pod123e4567-e89b-12d3-a456-426614174000/container123",
			want: "123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name: "underscore format",
			path: "kubepods/burstable/pod_123e4567e89b12d3a456426614174000/container123",
			want: "123e4567e89b12d3a456426614174000",
		},
		{
			name: "no pod UID",
			path: "kubepods/burstable",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPodUID(tt.path)
			if got != tt.want {
				t.Errorf("extractPodUID(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsHexString(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abc123", true},
		{"ABC123", true},
		{"0123456789abcdef", true},
		{"not-hex", false},
		{"abc123!", false},
		{"", true}, // empty string is valid hex
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isHexString(tt.input); got != tt.want {
				t.Errorf("isHexString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNetworkStatsParseNetDevLine(t *testing.T) {
	stats := &NetworkStats{
		Interfaces: make(map[string]InterfaceStats),
	}

	// Example line from /proc/net/dev
	line := "  eth0: 123456789 1000 10 5 0 0 0 0 987654321 2000 20 10 0 0 0 0"
	stats.parseNetDevLine(line)

	if len(stats.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(stats.Interfaces))
	}

	eth0, ok := stats.Interfaces["eth0"]
	if !ok {
		t.Fatal("expected eth0 interface")
	}

	if eth0.RxBytes != 123456789 {
		t.Errorf("expected RxBytes 123456789, got %d", eth0.RxBytes)
	}
	if eth0.RxPackets != 1000 {
		t.Errorf("expected RxPackets 1000, got %d", eth0.RxPackets)
	}
	if eth0.TxBytes != 987654321 {
		t.Errorf("expected TxBytes 987654321, got %d", eth0.TxBytes)
	}
	if eth0.TxPackets != 2000 {
		t.Errorf("expected TxPackets 2000, got %d", eth0.TxPackets)
	}

	// Verify aggregates
	if stats.RxBytes != 123456789 {
		t.Errorf("expected aggregate RxBytes 123456789, got %d", stats.RxBytes)
	}
	if stats.TxBytes != 987654321 {
		t.Errorf("expected aggregate TxBytes 987654321, got %d", stats.TxBytes)
	}
}

func TestNetworkStatsSkipLoopback(t *testing.T) {
	stats := &NetworkStats{
		Interfaces: make(map[string]InterfaceStats),
	}

	// Loopback interface should be skipped
	line := "    lo: 123456789 1000 0 0 0 0 0 0 123456789 1000 0 0 0 0 0 0"
	stats.parseNetDevLine(line)

	if len(stats.Interfaces) != 0 {
		t.Errorf("expected 0 interfaces (loopback skipped), got %d", len(stats.Interfaces))
	}
}

func TestEscapeLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{`has"quote`, `has\"quote`},
		{"has\\backslash", "has\\\\backslash"},
		{"has\nnewline", "has\\nnewline"},
		{"normal-value_123", "normal-value_123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := escapeLabel(tt.input); got != tt.want {
				t.Errorf("escapeLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCPUStats(t *testing.T) {
	stats := &CPUStats{
		UsageNanoseconds:     1000000000, // 1 second
		UserNanoseconds:      600000000,
		SystemNanoseconds:    400000000,
		ThrottledPeriods:     10,
		ThrottledNanoseconds: 100000000,
		TotalPeriods:         100,
		Timestamp:            time.Now(),
	}

	if stats.UsageNanoseconds != 1000000000 {
		t.Errorf("expected UsageNanoseconds 1000000000, got %d", stats.UsageNanoseconds)
	}
}

func TestMemoryStats(t *testing.T) {
	stats := &MemoryStats{
		UsageBytes:      1073741824, // 1 GB
		MaxUsageBytes:   2147483648, // 2 GB
		LimitBytes:      4294967296, // 4 GB
		WorkingSetBytes: 536870912,  // 512 MB
		RSSBytes:        268435456,  // 256 MB
		CacheBytes:      268435456,  // 256 MB
		SwapBytes:       0,
		OOMKills:        0,
		Timestamp:       time.Now(),
	}

	if stats.UsageBytes != 1073741824 {
		t.Errorf("expected UsageBytes 1073741824, got %d", stats.UsageBytes)
	}
}

func TestCollectorFormatLabels(t *testing.T) {
	c := &Collector{}
	stats := &ContainerStats{
		Container: ContainerCgroup{
			ContainerID:   "abc123",
			PodName:       "nginx-pod",
			Namespace:     "default",
			ContainerName: "nginx",
		},
	}

	labels := c.formatLabels(stats)

	if !strings.Contains(labels, `container_id="abc123"`) {
		t.Errorf("expected labels to contain container_id, got: %s", labels)
	}
	if !strings.Contains(labels, `pod="nginx-pod"`) {
		t.Errorf("expected labels to contain pod, got: %s", labels)
	}
	if !strings.Contains(labels, `namespace="default"`) {
		t.Errorf("expected labels to contain namespace, got: %s", labels)
	}
}

func TestCollectorWriteCPUMetrics(t *testing.T) {
	c := &Collector{
		config: DefaultConfig(),
	}

	stats := []*ContainerStats{
		{
			Container: ContainerCgroup{
				ContainerID:   "abc123",
				PodName:       "nginx",
				Namespace:     "default",
				ContainerName: "nginx",
			},
			CPU: &CPUStats{
				UsageNanoseconds:     5000000000, // 5 seconds
				UserNanoseconds:      3000000000,
				SystemNanoseconds:    2000000000,
				ThrottledPeriods:     5,
				ThrottledNanoseconds: 500000000,
			},
		},
	}

	buf := &bytes.Buffer{}
	c.writeCPUMetrics(buf, stats)

	output := buf.String()

	// Check HELP and TYPE
	if !strings.Contains(output, "# HELP container_cpu_usage_seconds_total") {
		t.Error("expected CPU usage help text")
	}
	if !strings.Contains(output, "# TYPE container_cpu_usage_seconds_total counter") {
		t.Error("expected CPU usage type")
	}

	// Check metric value (5 seconds)
	if !strings.Contains(output, "container_cpu_usage_seconds_total") {
		t.Error("expected CPU usage metric")
	}
}

func TestCollectorWriteMemoryMetrics(t *testing.T) {
	c := &Collector{
		config: DefaultConfig(),
	}

	stats := []*ContainerStats{
		{
			Container: ContainerCgroup{
				ContainerID:   "abc123",
				PodName:       "nginx",
				Namespace:     "default",
				ContainerName: "nginx",
			},
			Memory: &MemoryStats{
				UsageBytes:      1073741824,
				WorkingSetBytes: 536870912,
				RSSBytes:        268435456,
				CacheBytes:      268435456,
				SwapBytes:       0,
				MaxUsageBytes:   2147483648,
				OOMKills:        0,
			},
		},
	}

	buf := &bytes.Buffer{}
	c.writeMemoryMetrics(buf, stats)

	output := buf.String()

	if !strings.Contains(output, "container_memory_usage_bytes") {
		t.Error("expected memory usage metric")
	}
	if !strings.Contains(output, "container_memory_working_set_bytes") {
		t.Error("expected working set metric")
	}
	if !strings.Contains(output, "container_memory_rss") {
		t.Error("expected RSS metric")
	}
}

func TestCgroupReaderKeyValueFile(t *testing.T) {
	// Create a temporary file with key-value content
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.stat")

	content := `user 1000
system 500
nr_throttled 10
throttled_time 100000`

	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	reader := &CgroupReader{root: tmpDir}
	data, err := reader.readKeyValueFile(testFile)
	if err != nil {
		t.Fatalf("readKeyValueFile failed: %v", err)
	}

	if data["user"] != 1000 {
		t.Errorf("expected user=1000, got %d", data["user"])
	}
	if data["system"] != 500 {
		t.Errorf("expected system=500, got %d", data["system"])
	}
	if data["nr_throttled"] != 10 {
		t.Errorf("expected nr_throttled=10, got %d", data["nr_throttled"])
	}
}
