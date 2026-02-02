// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package collector

// CPUCollectorConfig holds CPU collector specific configuration.
// This is shared across platforms.
type CPUCollectorConfig struct {
	EnableGuest  bool
	EnableInfo   bool
	FlagsInclude string
	BugsInclude  string
}

// DefaultCPUCollectorConfig returns default CPU collector configuration.
func DefaultCPUCollectorConfig() CPUCollectorConfig {
	return CPUCollectorConfig{
		EnableGuest:  true,
		EnableInfo:   false,
		FlagsInclude: "",
		BugsInclude:  "",
	}
}

// DiskstatsCollectorConfig holds diskstats collector specific configuration.
type DiskstatsCollectorConfig struct {
	DeviceExclude     string
	DeviceInclude     string
	EnableDeviceIndex bool
}

// DefaultDiskstatsCollectorConfig returns default diskstats collector configuration.
func DefaultDiskstatsCollectorConfig() DiskstatsCollectorConfig {
	return DiskstatsCollectorConfig{
		DeviceExclude:     "^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$",
		DeviceInclude:     "",
		EnableDeviceIndex: false,
	}
}

// FilesystemCollectorConfig holds filesystem collector specific configuration.
type FilesystemCollectorConfig struct {
	MountPointsExclude string
	MountPointsInclude string
	FSTypesExclude     string
	FSTypesInclude     string
	MountTimeout       int
	StatWorkerCount    int
	EnableMountInfo    bool
}

// DefaultFilesystemCollectorConfig returns default filesystem collector configuration.
func DefaultFilesystemCollectorConfig() FilesystemCollectorConfig {
	return FilesystemCollectorConfig{
		MountPointsExclude: "^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)",
		MountPointsInclude: "",
		FSTypesExclude:     "^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$",
		FSTypesInclude:     "",
		MountTimeout:       5,
		StatWorkerCount:    4,
		EnableMountInfo:    true,
	}
}

// NetdevCollectorConfig holds netdev collector specific configuration.
type NetdevCollectorConfig struct {
	DeviceExclude string
	DeviceInclude string
	AddressInfo   bool
	Netlink       bool
}

// DefaultNetdevCollectorConfig returns default netdev collector configuration.
func DefaultNetdevCollectorConfig() NetdevCollectorConfig {
	return NetdevCollectorConfig{
		DeviceExclude: "^$",
		DeviceInclude: "",
		AddressInfo:   false,
		Netlink:       true,
	}
}

// StatCollectorConfig holds stat collector specific configuration.
type StatCollectorConfig struct {
	EnableSoftirq bool
}

// DefaultStatCollectorConfig returns default stat collector configuration.
func DefaultStatCollectorConfig() StatCollectorConfig {
	return StatCollectorConfig{
		EnableSoftirq: true,
	}
}

// TextfileCollectorConfig holds textfile collector specific configuration.
type TextfileCollectorConfig struct {
	Directory string
}

// DefaultTextfileCollectorConfig returns default textfile collector configuration.
func DefaultTextfileCollectorConfig() TextfileCollectorConfig {
	return TextfileCollectorConfig{
		Directory: "",
	}
}
