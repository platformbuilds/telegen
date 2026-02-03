// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cadvisor

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CgroupVersion represents the cgroup version
type CgroupVersion int

const (
	CgroupV1 CgroupVersion = 1
	CgroupV2 CgroupVersion = 2
)

// CgroupReader reads metrics from cgroup filesystem
type CgroupReader struct {
	root    string
	version CgroupVersion
}

// NewCgroupReader creates a new cgroup reader
func NewCgroupReader(root string) (*CgroupReader, error) {
	version, err := detectCgroupVersion(root)
	if err != nil {
		return nil, fmt.Errorf("failed to detect cgroup version: %w", err)
	}

	return &CgroupReader{
		root:    root,
		version: version,
	}, nil
}

// detectCgroupVersion determines if the system uses cgroups v1 or v2
func detectCgroupVersion(root string) (CgroupVersion, error) {
	// cgroups v2 has a "cgroup.controllers" file at the root
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err == nil {
		return CgroupV2, nil
	}

	// cgroups v1 has separate controller directories
	if _, err := os.Stat(filepath.Join(root, "memory")); err == nil {
		return CgroupV1, nil
	}

	return 0, errors.New("unable to detect cgroup version")
}

// Version returns the detected cgroup version
func (r *CgroupReader) Version() CgroupVersion {
	return r.version
}

// ContainerCgroup represents a container's cgroup path
type ContainerCgroup struct {
	Path          string
	ContainerID   string
	PodUID        string
	Namespace     string
	PodName       string
	ContainerName string
}

// CPUStats holds CPU metrics
type CPUStats struct {
	// Total CPU time consumed in nanoseconds
	UsageNanoseconds uint64

	// CPU time consumed per core (if available)
	PerCPUUsage []uint64

	// User and system CPU time
	UserNanoseconds   uint64
	SystemNanoseconds uint64

	// Number of periods with throttling active
	ThrottledPeriods uint64

	// Aggregated time throttled in nanoseconds
	ThrottledNanoseconds uint64

	// Total number of periods
	TotalPeriods uint64

	// Timestamp of the reading
	Timestamp time.Time
}

// MemoryStats holds memory metrics
type MemoryStats struct {
	// Current memory usage in bytes
	UsageBytes uint64

	// Maximum memory usage in bytes (highwater mark)
	MaxUsageBytes uint64

	// Memory limit in bytes
	LimitBytes uint64

	// Working set size (approximation)
	WorkingSetBytes uint64

	// RSS (Resident Set Size) in bytes
	RSSBytes uint64

	// Cache in bytes
	CacheBytes uint64

	// Swap usage in bytes
	SwapBytes uint64

	// Page faults
	PageFaults uint64

	// Major page faults
	MajorPageFaults uint64

	// OOM kill count
	OOMKills uint64

	// Timestamp of the reading
	Timestamp time.Time
}

// DiskIOStats holds disk I/O metrics
type DiskIOStats struct {
	// Read bytes
	ReadBytes uint64

	// Write bytes
	WriteBytes uint64

	// Read operations
	ReadOps uint64

	// Write operations
	WriteOps uint64

	// Per-device stats
	PerDevice map[string]DeviceIOStats

	// Timestamp of the reading
	Timestamp time.Time
}

// DeviceIOStats holds per-device I/O stats
type DeviceIOStats struct {
	DeviceMajor uint64
	DeviceMinor uint64
	ReadBytes   uint64
	WriteBytes  uint64
	ReadOps     uint64
	WriteOps    uint64
}

// NetworkStats holds network I/O metrics
type NetworkStats struct {
	// Bytes received
	RxBytes uint64

	// Bytes transmitted
	TxBytes uint64

	// Packets received
	RxPackets uint64

	// Packets transmitted
	TxPackets uint64

	// Receive errors
	RxErrors uint64

	// Transmit errors
	TxErrors uint64

	// Receive drops
	RxDropped uint64

	// Transmit drops
	TxDropped uint64

	// Per-interface stats
	Interfaces map[string]InterfaceStats

	// Timestamp of the reading
	Timestamp time.Time
}

// InterfaceStats holds per-interface network stats
type InterfaceStats struct {
	Name      string
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
	RxErrors  uint64
	TxErrors  uint64
	RxDropped uint64
	TxDropped uint64
}

// ContainerStats holds all stats for a container
type ContainerStats struct {
	Container ContainerCgroup
	CPU       *CPUStats
	Memory    *MemoryStats
	DiskIO    *DiskIOStats
	Network   *NetworkStats
	Timestamp time.Time
}

// ReadCPUStats reads CPU metrics for a cgroup
func (r *CgroupReader) ReadCPUStats(cgroupPath string) (*CPUStats, error) {
	stats := &CPUStats{
		Timestamp: time.Now(),
	}

	if r.version == CgroupV2 {
		return r.readCPUStatsV2(cgroupPath, stats)
	}
	return r.readCPUStatsV1(cgroupPath, stats)
}

func (r *CgroupReader) readCPUStatsV2(cgroupPath string, stats *CPUStats) (*CPUStats, error) {
	// Read cpu.stat
	cpuStatPath := filepath.Join(r.root, cgroupPath, "cpu.stat")
	data, err := r.readKeyValueFile(cpuStatPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cpu.stat: %w", err)
	}

	if v, ok := data["usage_usec"]; ok {
		stats.UsageNanoseconds = v * 1000 // Convert microseconds to nanoseconds
	}
	if v, ok := data["user_usec"]; ok {
		stats.UserNanoseconds = v * 1000
	}
	if v, ok := data["system_usec"]; ok {
		stats.SystemNanoseconds = v * 1000
	}
	if v, ok := data["nr_throttled"]; ok {
		stats.ThrottledPeriods = v
	}
	if v, ok := data["throttled_usec"]; ok {
		stats.ThrottledNanoseconds = v * 1000
	}
	if v, ok := data["nr_periods"]; ok {
		stats.TotalPeriods = v
	}

	return stats, nil
}

func (r *CgroupReader) readCPUStatsV1(cgroupPath string, stats *CPUStats) (*CPUStats, error) {
	// Read cpuacct.usage
	usagePath := filepath.Join(r.root, "cpuacct", cgroupPath, "cpuacct.usage")
	usageData, err := os.ReadFile(usagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cpuacct.usage: %w", err)
	}
	stats.UsageNanoseconds, _ = strconv.ParseUint(strings.TrimSpace(string(usageData)), 10, 64)

	// Read cpuacct.stat
	statPath := filepath.Join(r.root, "cpuacct", cgroupPath, "cpuacct.stat")
	data, err := r.readKeyValueFile(statPath)
	if err == nil {
		if v, ok := data["user"]; ok {
			stats.UserNanoseconds = v * 10000000 // Convert jiffies to nanoseconds (assuming 100 Hz)
		}
		if v, ok := data["system"]; ok {
			stats.SystemNanoseconds = v * 10000000
		}
	}

	// Read cpu.stat for throttling
	throttlePath := filepath.Join(r.root, "cpu", cgroupPath, "cpu.stat")
	throttleData, err := r.readKeyValueFile(throttlePath)
	if err == nil {
		stats.ThrottledPeriods = throttleData["nr_throttled"]
		stats.ThrottledNanoseconds = throttleData["throttled_time"]
		stats.TotalPeriods = throttleData["nr_periods"]
	}

	return stats, nil
}

// ReadMemoryStats reads memory metrics for a cgroup
func (r *CgroupReader) ReadMemoryStats(cgroupPath string) (*MemoryStats, error) {
	stats := &MemoryStats{
		Timestamp: time.Now(),
	}

	if r.version == CgroupV2 {
		return r.readMemoryStatsV2(cgroupPath, stats)
	}
	return r.readMemoryStatsV1(cgroupPath, stats)
}

func (r *CgroupReader) readMemoryStatsV2(cgroupPath string, stats *MemoryStats) (*MemoryStats, error) {
	basePath := filepath.Join(r.root, cgroupPath)

	// Read memory.current
	currentPath := filepath.Join(basePath, "memory.current")
	if data, err := os.ReadFile(currentPath); err == nil {
		stats.UsageBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}

	// Read memory.max
	maxPath := filepath.Join(basePath, "memory.max")
	if data, err := os.ReadFile(maxPath); err == nil {
		val := strings.TrimSpace(string(data))
		if val != "max" {
			stats.LimitBytes, _ = strconv.ParseUint(val, 10, 64)
		}
	}

	// Read memory.peak (max usage)
	peakPath := filepath.Join(basePath, "memory.peak")
	if data, err := os.ReadFile(peakPath); err == nil {
		stats.MaxUsageBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}

	// Read memory.swap.current
	swapPath := filepath.Join(basePath, "memory.swap.current")
	if data, err := os.ReadFile(swapPath); err == nil {
		stats.SwapBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}

	// Read memory.stat for detailed stats
	statPath := filepath.Join(basePath, "memory.stat")
	if data, err := r.readKeyValueFile(statPath); err == nil {
		stats.RSSBytes = data["anon"] + data["anon_thp"]
		stats.CacheBytes = data["file"]
		stats.PageFaults = data["pgfault"]
		stats.MajorPageFaults = data["pgmajfault"]

		// Working set = usage - inactive_file
		inactiveFile := data["inactive_file"]
		if stats.UsageBytes > inactiveFile {
			stats.WorkingSetBytes = stats.UsageBytes - inactiveFile
		} else {
			stats.WorkingSetBytes = stats.UsageBytes
		}
	}

	// Read memory.events for OOM kills
	eventsPath := filepath.Join(basePath, "memory.events")
	if data, err := r.readKeyValueFile(eventsPath); err == nil {
		stats.OOMKills = data["oom_kill"]
	}

	return stats, nil
}

func (r *CgroupReader) readMemoryStatsV1(cgroupPath string, stats *MemoryStats) (*MemoryStats, error) {
	basePath := filepath.Join(r.root, "memory", cgroupPath)

	// Read memory.usage_in_bytes
	usagePath := filepath.Join(basePath, "memory.usage_in_bytes")
	if data, err := os.ReadFile(usagePath); err == nil {
		stats.UsageBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}

	// Read memory.limit_in_bytes
	limitPath := filepath.Join(basePath, "memory.limit_in_bytes")
	if data, err := os.ReadFile(limitPath); err == nil {
		stats.LimitBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}

	// Read memory.max_usage_in_bytes
	maxUsagePath := filepath.Join(basePath, "memory.max_usage_in_bytes")
	if data, err := os.ReadFile(maxUsagePath); err == nil {
		stats.MaxUsageBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}

	// Read memory.stat
	statPath := filepath.Join(basePath, "memory.stat")
	if data, err := r.readKeyValueFile(statPath); err == nil {
		stats.RSSBytes = data["rss"]
		stats.CacheBytes = data["cache"]
		stats.PageFaults = data["pgfault"]
		stats.MajorPageFaults = data["pgmajfault"]

		inactiveFile := data["inactive_file"]
		if stats.UsageBytes > inactiveFile {
			stats.WorkingSetBytes = stats.UsageBytes - inactiveFile
		} else {
			stats.WorkingSetBytes = stats.UsageBytes
		}
	}

	// Read swap
	swapPath := filepath.Join(basePath, "memory.memsw.usage_in_bytes")
	if data, err := os.ReadFile(swapPath); err == nil {
		swapPlusMem, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if swapPlusMem > stats.UsageBytes {
			stats.SwapBytes = swapPlusMem - stats.UsageBytes
		}
	}

	return stats, nil
}

// ReadDiskIOStats reads disk I/O metrics for a cgroup
func (r *CgroupReader) ReadDiskIOStats(cgroupPath string) (*DiskIOStats, error) {
	stats := &DiskIOStats{
		Timestamp: time.Now(),
		PerDevice: make(map[string]DeviceIOStats),
	}

	if r.version == CgroupV2 {
		return r.readDiskIOStatsV2(cgroupPath, stats)
	}
	return r.readDiskIOStatsV1(cgroupPath, stats)
}

func (r *CgroupReader) readDiskIOStatsV2(cgroupPath string, stats *DiskIOStats) (*DiskIOStats, error) {
	ioStatPath := filepath.Join(r.root, cgroupPath, "io.stat")
	file, err := os.Open(ioStatPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open io.stat: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: 8:0 rbytes=1234 wbytes=5678 rios=10 wios=20 dbytes=0 dios=0
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		deviceID := fields[0]
		deviceStats := DeviceIOStats{}

		// Parse major:minor
		parts := strings.Split(deviceID, ":")
		if len(parts) == 2 {
			deviceStats.DeviceMajor, _ = strconv.ParseUint(parts[0], 10, 64)
			deviceStats.DeviceMinor, _ = strconv.ParseUint(parts[1], 10, 64)
		}

		for _, field := range fields[1:] {
			kv := strings.Split(field, "=")
			if len(kv) != 2 {
				continue
			}
			val, _ := strconv.ParseUint(kv[1], 10, 64)
			switch kv[0] {
			case "rbytes":
				deviceStats.ReadBytes = val
				stats.ReadBytes += val
			case "wbytes":
				deviceStats.WriteBytes = val
				stats.WriteBytes += val
			case "rios":
				deviceStats.ReadOps = val
				stats.ReadOps += val
			case "wios":
				deviceStats.WriteOps = val
				stats.WriteOps += val
			}
		}

		stats.PerDevice[deviceID] = deviceStats
	}

	return stats, nil
}

func (r *CgroupReader) readDiskIOStatsV1(cgroupPath string, stats *DiskIOStats) (*DiskIOStats, error) {
	basePath := filepath.Join(r.root, "blkio", cgroupPath)

	// Read blkio.throttle.io_service_bytes
	bytesPath := filepath.Join(basePath, "blkio.throttle.io_service_bytes")
	if file, err := os.Open(bytesPath); err == nil {
		defer func() { _ = file.Close() }()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 3 {
				continue
			}
			val, _ := strconv.ParseUint(fields[2], 10, 64)
			switch fields[1] {
			case "Read":
				stats.ReadBytes += val
			case "Write":
				stats.WriteBytes += val
			}
		}
	}

	// Read blkio.throttle.io_serviced
	opsPath := filepath.Join(basePath, "blkio.throttle.io_serviced")
	if file, err := os.Open(opsPath); err == nil {
		defer func() { _ = file.Close() }()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 3 {
				continue
			}
			val, _ := strconv.ParseUint(fields[2], 10, 64)
			switch fields[1] {
			case "Read":
				stats.ReadOps += val
			case "Write":
				stats.WriteOps += val
			}
		}
	}

	return stats, nil
}

// readKeyValueFile reads a file with "key value" format
func (r *CgroupReader) readKeyValueFile(path string) (map[string]uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	result := make(map[string]uint64)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			result[fields[0]] = val
		}
	}

	return result, scanner.Err()
}

// ListContainerCgroups finds all container cgroups in the system
func (r *CgroupReader) ListContainerCgroups() ([]ContainerCgroup, error) {
	var cgroups []ContainerCgroup

	// Pattern for container cgroups varies by container runtime
	// Kubernetes uses: /kubepods/burstable/pod<uid>/<container-id>
	//                  /kubepods/besteffort/pod<uid>/<container-id>
	//                  /kubepods/guaranteed/pod<uid>/<container-id>
	// Or with slices: /kubepods.slice/kubepods-burstable.slice/...

	var searchPath string
	if r.version == CgroupV2 {
		searchPath = r.root
	} else {
		searchPath = filepath.Join(r.root, "memory")
	}

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() {
			return nil
		}

		// Look for container directories
		relPath, _ := filepath.Rel(searchPath, path)
		containerID := extractContainerID(relPath)
		if containerID == "" {
			return nil
		}

		podUID := extractPodUID(relPath)
		cgroups = append(cgroups, ContainerCgroup{
			Path:        relPath,
			ContainerID: containerID,
			PodUID:      podUID,
		})

		return nil
	})

	return cgroups, err
}

// extractContainerID extracts container ID from cgroup path
func extractContainerID(path string) string {
	// Container IDs are typically 64 hex characters
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		// Remove common prefixes
		part = strings.TrimPrefix(part, "cri-containerd-")
		part = strings.TrimPrefix(part, "docker-")
		part = strings.TrimPrefix(part, "crio-")

		// Check if it looks like a container ID
		if len(part) >= 12 && isHexString(part[:12]) {
			return part
		}
	}
	return ""
}

// extractPodUID extracts pod UID from cgroup path
func extractPodUID(path string) string {
	// Pod UIDs are in format pod<uid> or pod_<uid>
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "pod") {
			uid := strings.TrimPrefix(part, "pod")
			uid = strings.TrimPrefix(uid, "_")
			// UIDs are typically 36 characters with dashes, but may be without dashes
			if len(uid) >= 32 {
				return uid
			}
		}
	}
	return ""
}

// isHexString checks if a string contains only hex characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
