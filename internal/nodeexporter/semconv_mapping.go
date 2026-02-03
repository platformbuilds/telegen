// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package nodeexporter

// MetricMapping defines a mapping from node_exporter metrics to OTEL semantic conventions.
type MetricMapping struct {
	// NodeExporterName is the original node_exporter metric name
	NodeExporterName string

	// OTELName is the OTEL semantic convention metric name
	OTELName string

	// Description is a human-readable description of the metric
	Description string

	// Unit is the OTEL-compliant unit (s, By, 1, %, etc.)
	Unit string

	// Type is the metric type (counter, gauge, histogram, summary)
	Type string

	// Labels describes the expected labels/attributes
	Labels []LabelMapping
}

// LabelMapping defines a mapping from node_exporter labels to OTEL attributes.
type LabelMapping struct {
	// NodeExporterLabel is the original label name
	NodeExporterLabel string

	// OTELAttribute is the OTEL semantic convention attribute name
	OTELAttribute string

	// Description describes the label
	Description string
}

// MetricCategory groups related metrics.
type MetricCategory struct {
	Name        string
	Description string
	Metrics     []MetricMapping
}

// GetAllMetricMappings returns all node_exporter to OTEL metric mappings.
func GetAllMetricMappings() []MetricCategory {
	return []MetricCategory{
		cpuMetrics(),
		memoryMetrics(),
		diskMetrics(),
		filesystemMetrics(),
		networkMetrics(),
		loadMetrics(),
		processMetrics(),
		systemMetrics(),
	}
}

// GetMetricMapping returns the OTEL mapping for a given node_exporter metric name.
// Returns nil if no mapping exists.
func GetMetricMapping(nodeExporterName string) *MetricMapping {
	for _, category := range GetAllMetricMappings() {
		for _, m := range category.Metrics {
			if m.NodeExporterName == nodeExporterName {
				return &m
			}
		}
	}
	return nil
}

// GetMetricDescription returns a description for a node_exporter metric.
func GetMetricDescription(name string) string {
	if m := GetMetricMapping(name); m != nil {
		return m.Description
	}
	return ""
}

func cpuMetrics() MetricCategory {
	return MetricCategory{
		Name:        "CPU",
		Description: "CPU time and utilization metrics",
		Metrics: []MetricMapping{
			{
				NodeExporterName: "node_cpu_seconds_total",
				OTELName:         "system.cpu.time",
				Description:      "Seconds the CPUs spent in each mode",
				Unit:             "s",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "cpu", OTELAttribute: "cpu", Description: "CPU core identifier"},
					{NodeExporterLabel: "mode", OTELAttribute: "cpu.mode", Description: "CPU mode (user, system, idle, iowait, etc.)"},
				},
			},
			{
				NodeExporterName: "node_cpu_info",
				OTELName:         "system.cpu.info",
				Description:      "CPU information including model and features",
				Unit:             "1",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "cpu", OTELAttribute: "cpu", Description: "CPU core identifier"},
					{NodeExporterLabel: "model_name", OTELAttribute: "cpu.model", Description: "CPU model name"},
					{NodeExporterLabel: "vendor_id", OTELAttribute: "cpu.vendor", Description: "CPU vendor ID"},
				},
			},
			{
				NodeExporterName: "node_cpu_frequency_hertz",
				OTELName:         "system.cpu.frequency",
				Description:      "Current CPU frequency in hertz",
				Unit:             "Hz",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "cpu", OTELAttribute: "cpu", Description: "CPU core identifier"},
				},
			},
			{
				NodeExporterName: "node_cpu_scaling_frequency_hertz",
				OTELName:         "system.cpu.frequency.scaling",
				Description:      "Current scaled CPU frequency in hertz",
				Unit:             "Hz",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "cpu", OTELAttribute: "cpu", Description: "CPU core identifier"},
				},
			},
		},
	}
}

func memoryMetrics() MetricCategory {
	return MetricCategory{
		Name:        "Memory",
		Description: "System memory metrics",
		Metrics: []MetricMapping{
			{
				NodeExporterName: "node_memory_MemTotal_bytes",
				OTELName:         "system.memory.limit",
				Description:      "Total system memory in bytes",
				Unit:             "By",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_memory_MemFree_bytes",
				OTELName:         "system.memory.usage",
				Description:      "Free system memory in bytes (state=free)",
				Unit:             "By",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_memory_MemAvailable_bytes",
				OTELName:         "system.memory.usage",
				Description:      "Available system memory in bytes (state=available)",
				Unit:             "By",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_memory_Buffers_bytes",
				OTELName:         "system.memory.usage",
				Description:      "Memory used for buffers (state=buffers)",
				Unit:             "By",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_memory_Cached_bytes",
				OTELName:         "system.memory.usage",
				Description:      "Memory used for cache (state=cached)",
				Unit:             "By",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_memory_SwapTotal_bytes",
				OTELName:         "system.memory.swap.limit",
				Description:      "Total swap space in bytes",
				Unit:             "By",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_memory_SwapFree_bytes",
				OTELName:         "system.memory.swap.usage",
				Description:      "Free swap space in bytes",
				Unit:             "By",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_memory_HugePages_Total",
				OTELName:         "system.memory.hugepages.limit",
				Description:      "Total number of huge pages",
				Unit:             "{page}",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_memory_HugePages_Free",
				OTELName:         "system.memory.hugepages.usage",
				Description:      "Number of free huge pages",
				Unit:             "{page}",
				Type:             "gauge",
			},
		},
	}
}

func diskMetrics() MetricCategory {
	return MetricCategory{
		Name:        "Disk",
		Description: "Disk I/O metrics",
		Metrics: []MetricMapping{
			{
				NodeExporterName: "node_disk_read_bytes_total",
				OTELName:         "system.disk.io",
				Description:      "Total bytes read from disk (direction=read)",
				Unit:             "By",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Disk device name"},
				},
			},
			{
				NodeExporterName: "node_disk_written_bytes_total",
				OTELName:         "system.disk.io",
				Description:      "Total bytes written to disk (direction=write)",
				Unit:             "By",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Disk device name"},
				},
			},
			{
				NodeExporterName: "node_disk_reads_completed_total",
				OTELName:         "system.disk.operations",
				Description:      "Total read operations completed (direction=read)",
				Unit:             "{operation}",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Disk device name"},
				},
			},
			{
				NodeExporterName: "node_disk_writes_completed_total",
				OTELName:         "system.disk.operations",
				Description:      "Total write operations completed (direction=write)",
				Unit:             "{operation}",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Disk device name"},
				},
			},
			{
				NodeExporterName: "node_disk_read_time_seconds_total",
				OTELName:         "system.disk.operation_time",
				Description:      "Total time spent reading from disk (direction=read)",
				Unit:             "s",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Disk device name"},
				},
			},
			{
				NodeExporterName: "node_disk_write_time_seconds_total",
				OTELName:         "system.disk.operation_time",
				Description:      "Total time spent writing to disk (direction=write)",
				Unit:             "s",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Disk device name"},
				},
			},
			{
				NodeExporterName: "node_disk_io_time_seconds_total",
				OTELName:         "system.disk.io_time",
				Description:      "Total time spent doing I/O operations",
				Unit:             "s",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Disk device name"},
				},
			},
			{
				NodeExporterName: "node_disk_io_now",
				OTELName:         "system.disk.pending_operations",
				Description:      "Number of I/O operations currently in progress",
				Unit:             "{operation}",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Disk device name"},
				},
			},
		},
	}
}

func filesystemMetrics() MetricCategory {
	return MetricCategory{
		Name:        "Filesystem",
		Description: "Filesystem space and inode metrics",
		Metrics: []MetricMapping{
			{
				NodeExporterName: "node_filesystem_size_bytes",
				OTELName:         "system.filesystem.limit",
				Description:      "Total filesystem size in bytes",
				Unit:             "By",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Filesystem device"},
					{NodeExporterLabel: "fstype", OTELAttribute: "filesystem.type", Description: "Filesystem type"},
					{NodeExporterLabel: "mountpoint", OTELAttribute: "filesystem.mountpoint", Description: "Mount point"},
				},
			},
			{
				NodeExporterName: "node_filesystem_avail_bytes",
				OTELName:         "system.filesystem.usage",
				Description:      "Available filesystem space in bytes (state=free)",
				Unit:             "By",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Filesystem device"},
					{NodeExporterLabel: "fstype", OTELAttribute: "filesystem.type", Description: "Filesystem type"},
					{NodeExporterLabel: "mountpoint", OTELAttribute: "filesystem.mountpoint", Description: "Mount point"},
				},
			},
			{
				NodeExporterName: "node_filesystem_free_bytes",
				OTELName:         "system.filesystem.usage",
				Description:      "Free filesystem space in bytes including reserved (state=reserved)",
				Unit:             "By",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Filesystem device"},
					{NodeExporterLabel: "fstype", OTELAttribute: "filesystem.type", Description: "Filesystem type"},
					{NodeExporterLabel: "mountpoint", OTELAttribute: "filesystem.mountpoint", Description: "Mount point"},
				},
			},
			{
				NodeExporterName: "node_filesystem_files",
				OTELName:         "system.filesystem.inodes.limit",
				Description:      "Total number of inodes",
				Unit:             "{inode}",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Filesystem device"},
					{NodeExporterLabel: "fstype", OTELAttribute: "filesystem.type", Description: "Filesystem type"},
					{NodeExporterLabel: "mountpoint", OTELAttribute: "filesystem.mountpoint", Description: "Mount point"},
				},
			},
			{
				NodeExporterName: "node_filesystem_files_free",
				OTELName:         "system.filesystem.inodes.usage",
				Description:      "Number of free inodes (state=free)",
				Unit:             "{inode}",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "disk.device", Description: "Filesystem device"},
					{NodeExporterLabel: "fstype", OTELAttribute: "filesystem.type", Description: "Filesystem type"},
					{NodeExporterLabel: "mountpoint", OTELAttribute: "filesystem.mountpoint", Description: "Mount point"},
				},
			},
		},
	}
}

func networkMetrics() MetricCategory {
	return MetricCategory{
		Name:        "Network",
		Description: "Network I/O metrics",
		Metrics: []MetricMapping{
			{
				NodeExporterName: "node_network_receive_bytes_total",
				OTELName:         "system.network.io",
				Description:      "Total bytes received (direction=receive)",
				Unit:             "By",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "network.device", Description: "Network interface name"},
				},
			},
			{
				NodeExporterName: "node_network_transmit_bytes_total",
				OTELName:         "system.network.io",
				Description:      "Total bytes transmitted (direction=transmit)",
				Unit:             "By",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "network.device", Description: "Network interface name"},
				},
			},
			{
				NodeExporterName: "node_network_receive_packets_total",
				OTELName:         "system.network.packets",
				Description:      "Total packets received (direction=receive)",
				Unit:             "{packet}",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "network.device", Description: "Network interface name"},
				},
			},
			{
				NodeExporterName: "node_network_transmit_packets_total",
				OTELName:         "system.network.packets",
				Description:      "Total packets transmitted (direction=transmit)",
				Unit:             "{packet}",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "network.device", Description: "Network interface name"},
				},
			},
			{
				NodeExporterName: "node_network_receive_errs_total",
				OTELName:         "system.network.errors",
				Description:      "Total receive errors (direction=receive)",
				Unit:             "{error}",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "network.device", Description: "Network interface name"},
				},
			},
			{
				NodeExporterName: "node_network_transmit_errs_total",
				OTELName:         "system.network.errors",
				Description:      "Total transmit errors (direction=transmit)",
				Unit:             "{error}",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "network.device", Description: "Network interface name"},
				},
			},
			{
				NodeExporterName: "node_network_receive_drop_total",
				OTELName:         "system.network.dropped",
				Description:      "Total received packets dropped (direction=receive)",
				Unit:             "{packet}",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "network.device", Description: "Network interface name"},
				},
			},
			{
				NodeExporterName: "node_network_transmit_drop_total",
				OTELName:         "system.network.dropped",
				Description:      "Total transmitted packets dropped (direction=transmit)",
				Unit:             "{packet}",
				Type:             "counter",
				Labels: []LabelMapping{
					{NodeExporterLabel: "device", OTELAttribute: "network.device", Description: "Network interface name"},
				},
			},
		},
	}
}

func loadMetrics() MetricCategory {
	return MetricCategory{
		Name:        "Load",
		Description: "System load average metrics",
		Metrics: []MetricMapping{
			{
				NodeExporterName: "node_load1",
				OTELName:         "system.cpu.load_average.1m",
				Description:      "1-minute load average",
				Unit:             "1",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_load5",
				OTELName:         "system.cpu.load_average.5m",
				Description:      "5-minute load average",
				Unit:             "1",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_load15",
				OTELName:         "system.cpu.load_average.15m",
				Description:      "15-minute load average",
				Unit:             "1",
				Type:             "gauge",
			},
		},
	}
}

func processMetrics() MetricCategory {
	return MetricCategory{
		Name:        "Process",
		Description: "System process metrics",
		Metrics: []MetricMapping{
			{
				NodeExporterName: "node_procs_running",
				OTELName:         "system.processes.running",
				Description:      "Number of processes in running state",
				Unit:             "{process}",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_procs_blocked",
				OTELName:         "system.processes.blocked",
				Description:      "Number of processes blocked waiting for I/O",
				Unit:             "{process}",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_forks_total",
				OTELName:         "system.processes.created",
				Description:      "Total number of processes and threads created",
				Unit:             "{process}",
				Type:             "counter",
			},
			{
				NodeExporterName: "node_context_switches_total",
				OTELName:         "system.cpu.context_switches",
				Description:      "Total number of context switches",
				Unit:             "{switch}",
				Type:             "counter",
			},
			{
				NodeExporterName: "node_intr_total",
				OTELName:         "system.cpu.interrupts",
				Description:      "Total number of interrupts serviced",
				Unit:             "{interrupt}",
				Type:             "counter",
			},
		},
	}
}

func systemMetrics() MetricCategory {
	return MetricCategory{
		Name:        "System",
		Description: "General system metrics",
		Metrics: []MetricMapping{
			{
				NodeExporterName: "node_boot_time_seconds",
				OTELName:         "system.boot.time",
				Description:      "System boot time as Unix timestamp",
				Unit:             "s",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_time_seconds",
				OTELName:         "system.time",
				Description:      "System time as Unix timestamp",
				Unit:             "s",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_uname_info",
				OTELName:         "system.uname",
				Description:      "System uname information",
				Unit:             "1",
				Type:             "gauge",
				Labels: []LabelMapping{
					{NodeExporterLabel: "sysname", OTELAttribute: "os.type", Description: "Operating system name"},
					{NodeExporterLabel: "release", OTELAttribute: "os.version", Description: "Kernel release"},
					{NodeExporterLabel: "version", OTELAttribute: "os.build_id", Description: "Kernel version"},
					{NodeExporterLabel: "machine", OTELAttribute: "host.arch", Description: "Machine hardware name"},
					{NodeExporterLabel: "nodename", OTELAttribute: "host.name", Description: "Network node hostname"},
				},
			},
			{
				NodeExporterName: "node_entropy_available_bits",
				OTELName:         "system.entropy.available",
				Description:      "Bits of available entropy",
				Unit:             "{bit}",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_entropy_pool_size_bits",
				OTELName:         "system.entropy.pool_size",
				Description:      "Size of the entropy pool",
				Unit:             "{bit}",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_filefd_allocated",
				OTELName:         "system.filedescriptors.open",
				Description:      "Number of allocated file descriptors",
				Unit:             "{fd}",
				Type:             "gauge",
			},
			{
				NodeExporterName: "node_filefd_maximum",
				OTELName:         "system.filedescriptors.limit",
				Description:      "Maximum number of file descriptors",
				Unit:             "{fd}",
				Type:             "gauge",
			},
		},
	}
}
