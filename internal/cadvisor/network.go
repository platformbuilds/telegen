// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cadvisor

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ReadNetworkStats reads network I/O metrics for a container
// Network stats require reading from /proc/<pid>/net/dev for the container
func (r *CgroupReader) ReadNetworkStats(pid int) (*NetworkStats, error) {
	stats := &NetworkStats{
		Interfaces: make(map[string]InterfaceStats),
	}

	netDevPath := filepath.Join("/proc", strconv.Itoa(pid), "net", "dev")
	file, err := os.Open(netDevPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", netDevPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		// Skip header lines
		if lineNum <= 2 {
			continue
		}

		line := scanner.Text()
		stats.parseNetDevLine(line)
	}

	return stats, scanner.Err()
}

// parseNetDevLine parses a line from /proc/net/dev
// Format: iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets tx_errs tx_drop ...
func (stats *NetworkStats) parseNetDevLine(line string) {
	// Split on colon to get interface name
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return
	}

	ifaceName := strings.TrimSpace(parts[0])
	// Skip loopback
	if ifaceName == "lo" {
		return
	}

	fields := strings.Fields(parts[1])
	if len(fields) < 16 {
		return
	}

	ifaceStats := InterfaceStats{Name: ifaceName}

	// Parse receive stats (first 8 fields)
	ifaceStats.RxBytes, _ = strconv.ParseUint(fields[0], 10, 64)
	ifaceStats.RxPackets, _ = strconv.ParseUint(fields[1], 10, 64)
	ifaceStats.RxErrors, _ = strconv.ParseUint(fields[2], 10, 64)
	ifaceStats.RxDropped, _ = strconv.ParseUint(fields[3], 10, 64)

	// Parse transmit stats (fields 8-15)
	ifaceStats.TxBytes, _ = strconv.ParseUint(fields[8], 10, 64)
	ifaceStats.TxPackets, _ = strconv.ParseUint(fields[9], 10, 64)
	ifaceStats.TxErrors, _ = strconv.ParseUint(fields[10], 10, 64)
	ifaceStats.TxDropped, _ = strconv.ParseUint(fields[11], 10, 64)

	// Aggregate totals
	stats.RxBytes += ifaceStats.RxBytes
	stats.RxPackets += ifaceStats.RxPackets
	stats.RxErrors += ifaceStats.RxErrors
	stats.RxDropped += ifaceStats.RxDropped
	stats.TxBytes += ifaceStats.TxBytes
	stats.TxPackets += ifaceStats.TxPackets
	stats.TxErrors += ifaceStats.TxErrors
	stats.TxDropped += ifaceStats.TxDropped

	stats.Interfaces[ifaceName] = ifaceStats
}

// GetContainerPID gets the PID of a container's init process
func GetContainerPID(cgroupPath string) (int, error) {
	// Read from cgroup.procs to get PIDs in the cgroup
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	file, err := os.Open(procsPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open cgroup.procs: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		pid, err := strconv.Atoi(scanner.Text())
		if err != nil {
			return 0, fmt.Errorf("failed to parse PID: %w", err)
		}
		return pid, nil
	}

	return 0, fmt.Errorf("no PIDs found in cgroup")
}

// ReadFilesystemStats reads filesystem stats for a container
// This reads from /proc/<pid>/mountinfo to get filesystem usage
type FilesystemStats struct {
	Device          string
	MountPoint      string
	FSType          string
	TotalBytes      uint64
	UsedBytes       uint64
	AvailableBytes  uint64
	InodesFree      uint64
	InodesUsed      uint64
	InodesTotal     uint64
	ReadOnly        bool
	ContainerDevice string // Device from container's perspective
}

// ReadFilesystemStats reads filesystem stats from /proc
func ReadFilesystemStats(pid int, rootfs string) ([]FilesystemStats, error) {
	var stats []FilesystemStats

	// Read mountinfo to get mount points
	mountInfoPath := filepath.Join("/proc", strconv.Itoa(pid), "mountinfo")
	file, err := os.Open(mountInfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open mountinfo: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fs := parseMountInfoLine(line)
		if fs.MountPoint != "" && shouldIncludeFS(fs) {
			// Get usage from statfs
			getFilesystemUsage(&fs)
			stats = append(stats, fs)
		}
	}

	return stats, scanner.Err()
}

// parseMountInfoLine parses a line from /proc/<pid>/mountinfo
func parseMountInfoLine(line string) FilesystemStats {
	var fs FilesystemStats

	// mountinfo format is complex with variable number of optional fields
	// Example: 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext4 /dev/root rw
	// Fields: id parent_id major:minor root mount_point options [optional]* - fs_type source super_options

	fields := strings.Fields(line)
	if len(fields) < 10 {
		return fs
	}

	// Find the separator "-"
	sepIdx := -1
	for i, f := range fields {
		if f == "-" {
			sepIdx = i
			break
		}
	}
	if sepIdx == -1 || sepIdx+2 >= len(fields) {
		return fs
	}

	fs.MountPoint = fields[4]
	fs.FSType = fields[sepIdx+1]
	fs.Device = fields[sepIdx+2]

	// Check for read-only
	options := fields[5]
	fs.ReadOnly = strings.HasPrefix(options, "ro")

	return fs
}

// shouldIncludeFS determines if a filesystem should be included in stats
func shouldIncludeFS(fs FilesystemStats) bool {
	// Only include real filesystems
	realFSTypes := map[string]bool{
		"ext4":    true,
		"ext3":    true,
		"ext2":    true,
		"xfs":     true,
		"btrfs":   true,
		"overlay": true,
		"tmpfs":   true,
	}

	if !realFSTypes[fs.FSType] {
		return false
	}

	// Skip system mounts
	if strings.HasPrefix(fs.MountPoint, "/proc") ||
		strings.HasPrefix(fs.MountPoint, "/sys") ||
		fs.MountPoint == "/dev" ||
		strings.HasPrefix(fs.MountPoint, "/dev/") {
		return false
	}

	return true
}

// getFilesystemUsage gets usage stats via syscall
// Note: This is a simplified version - full implementation would use syscall.Statfs
func getFilesystemUsage(fs *FilesystemStats) {
	// This would use syscall.Statfs in a real implementation
	// For now, we'll leave it as a placeholder
	// The actual metrics would be populated via statfs syscall
}
