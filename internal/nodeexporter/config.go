// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nodeexporter provides Prometheus node_exporter compatible system metrics
// collection for telegen. This package reuses the proven node_exporter collector
// architecture while integrating with telegen's configuration system.
package nodeexporter

import (
	"time"
)

// Config represents the node exporter configuration.
type Config struct {
	// Enabled controls whether node_exporter metrics are collected
	Enabled bool `yaml:"enabled"`

	// Namespace for metrics (default: "node")
	Namespace string `yaml:"namespace"`

	// Paths configuration
	Paths PathsConfig `yaml:"paths"`

	// Endpoint configuration
	Endpoint EndpointConfig `yaml:"endpoint"`

	// Scrape configuration
	Scrape ScrapeConfig `yaml:"scrape"`

	// Export configuration for streaming metrics to OTLP
	Export ExportConfig `yaml:"export"`

	// Environment configuration for deployment awareness
	Environment EnvironmentConfig `yaml:"environment"`

	// Collectors configuration
	Collectors CollectorsConfig `yaml:"collectors"`
}

// PathsConfig holds path configuration for reading system metrics.
type PathsConfig struct {
	// ProcPath is the path to the proc filesystem
	ProcPath string `yaml:"procfs"`

	// SysPath is the path to the sys filesystem
	SysPath string `yaml:"sysfs"`

	// RootPath is the path to the root filesystem
	RootPath string `yaml:"rootfs"`

	// UdevDataPath is the path to udev data
	UdevDataPath string `yaml:"udev_data"`
}

// EndpointConfig holds HTTP endpoint configuration.
type EndpointConfig struct {
	// Port for the metrics endpoint
	Port int `yaml:"port"`

	// Path for the metrics endpoint
	Path string `yaml:"path"`

	// TLS configuration
	TLS *TLSConfig `yaml:"tls,omitempty"`
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	// Enabled controls whether TLS is enabled
	Enabled bool `yaml:"enabled"`

	// CertFile is the path to the certificate file
	CertFile string `yaml:"cert_file"`

	// KeyFile is the path to the key file
	KeyFile string `yaml:"key_file"`

	// ClientCAFile is the path to the client CA file for mTLS
	ClientCAFile string `yaml:"client_ca_file,omitempty"`
}

// ScrapeConfig holds scrape configuration.
type ScrapeConfig struct {
	// Timeout for individual collector scrapes
	Timeout time.Duration `yaml:"timeout"`

	// Cardinality holds configuration for controlling metric cardinality
	Cardinality CardinalityConfig `yaml:"cardinality"`
}

// CardinalityConfig holds configuration for controlling metric cardinality.
type CardinalityConfig struct {
	// Enabled enables cardinality controls
	Enabled bool `yaml:"enabled"`

	// MaxMetrics is the maximum number of metrics per scrape (0 = unlimited)
	MaxMetrics int `yaml:"max_metrics"`

	// MaxLabels is the maximum number of labels per metric (0 = unlimited)
	MaxLabels int `yaml:"max_labels"`

	// MaxLabelValueLength is the maximum length of label values (0 = unlimited)
	MaxLabelValueLength int `yaml:"max_label_value_length"`

	// DropLabels is a list of label names to drop from all metrics
	DropLabels []string `yaml:"drop_labels"`

	// IncludeMetrics is a list of metric name patterns to include (regex)
	// If empty, all metrics are included
	IncludeMetrics []string `yaml:"include_metrics"`

	// ExcludeMetrics is a list of metric name patterns to exclude (regex)
	ExcludeMetrics []string `yaml:"exclude_metrics"`
}

// ExportConfig holds configuration for streaming metrics export.
type ExportConfig struct {
	// Enabled controls whether metrics are streamed to OTLP endpoint
	Enabled bool `yaml:"enabled"`

	// Interval at which metrics are collected and exported
	Interval time.Duration `yaml:"interval"`

	// UseOTLP controls whether to use the main telegen OTLP exporter
	// If true, metrics are sent via telegen's configured OTLP endpoint
	// If false, metrics are only exposed via the /metrics HTTP endpoint
	UseOTLP bool `yaml:"use_otlp"`

	// BatchSize is the number of metrics to batch before sending
	BatchSize int `yaml:"batch_size"`

	// FlushTimeout is the maximum time to wait before flushing a partial batch
	FlushTimeout time.Duration `yaml:"flush_timeout"`

	// Cache configuration for metric collection
	Cache CacheConfig `yaml:"cache"`

	// AdaptiveBatching enables dynamic batch size adjustment based on export latency
	AdaptiveBatching bool `yaml:"adaptive_batching"`

	// TargetLatency is the target export latency for adaptive batching
	TargetLatency time.Duration `yaml:"target_latency"`
}

// CacheConfig holds configuration for the metric cache.
type CacheConfig struct {
	// Enabled controls whether caching is active
	Enabled bool `yaml:"enabled"`

	// TTL is the time-to-live for cached metrics
	TTL time.Duration `yaml:"ttl"`
}

// EnvironmentConfig holds environment detection configuration.
type EnvironmentConfig struct {
	// Type is the detected or configured environment type
	// Values: "auto", "bare_metal", "virtual_machine", "kubernetes", "container"
	Type string `yaml:"type"`

	// AutoDetect enables automatic environment detection
	AutoDetect bool `yaml:"auto_detect"`

	// Kubernetes-specific configuration (when running in K8s)
	Kubernetes K8sEnvironmentConfig `yaml:"kubernetes"`

	// Labels to add to all metrics based on environment
	Labels map[string]string `yaml:"labels"`
}

// K8sEnvironmentConfig holds Kubernetes-specific environment configuration.
type K8sEnvironmentConfig struct {
	// NodeName is the Kubernetes node name (auto-detected from NODE_NAME env)
	NodeName string `yaml:"node_name"`

	// Namespace is the Kubernetes namespace (auto-detected from POD_NAMESPACE env)
	Namespace string `yaml:"namespace"`

	// PodName is the Kubernetes pod name (auto-detected from POD_NAME or HOSTNAME env)
	PodName string `yaml:"pod_name"`

	// ClusterName is the Kubernetes cluster name (from CLUSTER_NAME env)
	ClusterName string `yaml:"cluster_name"`

	// IncludeNodeLabels includes Kubernetes node labels as metric labels
	IncludeNodeLabels bool `yaml:"include_node_labels"`

	// IncludePodLabels includes pod labels as metric labels
	IncludePodLabels bool `yaml:"include_pod_labels"`
}

// EnvironmentType represents the detected deployment environment.
type EnvironmentType string

const (
	// EnvironmentAuto means auto-detect the environment
	EnvironmentAuto EnvironmentType = "auto"
	// EnvironmentBareMetal represents bare metal servers
	EnvironmentBareMetal EnvironmentType = "bare_metal"
	// EnvironmentVirtualMachine represents virtual machines
	EnvironmentVirtualMachine EnvironmentType = "virtual_machine"
	// EnvironmentKubernetes represents Kubernetes pods
	EnvironmentKubernetes EnvironmentType = "kubernetes"
	// EnvironmentContainer represents standalone containers
	EnvironmentContainer EnvironmentType = "container"
)

// CollectorsConfig holds collector enable/disable configuration.
type CollectorsConfig struct {
	// Core collectors
	CPU        CPUConfig        `yaml:"cpu"`
	Meminfo    bool             `yaml:"meminfo"`
	Loadavg    bool             `yaml:"loadavg"`
	Diskstats  DiskstatsConfig  `yaml:"diskstats"`
	Filesystem FilesystemConfig `yaml:"filesystem"`
	Netdev     NetdevConfig     `yaml:"netdev"`
	Netstat    bool             `yaml:"netstat"`
	Stat       StatConfig       `yaml:"stat"`
	Uname      bool             `yaml:"uname"`
	Time       bool             `yaml:"time"`
	Conntrack  bool             `yaml:"conntrack"`
	VMstat     bool             `yaml:"vmstat"`

	// Hardware collectors
	Hwmon       bool `yaml:"hwmon"`
	Thermal     bool `yaml:"thermal"`
	PowerSupply bool `yaml:"power_supply"`

	// Extended collectors
	Pressure     bool           `yaml:"pressure"`
	Processes    bool           `yaml:"processes"`
	Arp          bool           `yaml:"arp"`
	Entropy      bool           `yaml:"entropy"`
	Edac         bool           `yaml:"edac"`
	Fibrechannel bool           `yaml:"fibrechannel"`
	Infiniband   bool           `yaml:"infiniband"`
	IPVS         bool           `yaml:"ipvs"`
	NFS          bool           `yaml:"nfs"`
	NFSd         bool           `yaml:"nfsd"`
	NVME         bool           `yaml:"nvme"`
	Rapl         bool           `yaml:"rapl"`
	Schedstat    bool           `yaml:"schedstat"`
	Sockstat     bool           `yaml:"sockstat"`
	Softnet      bool           `yaml:"softnet"`
	Tapestats    bool           `yaml:"tapestats"`
	Textfile     TextfileConfig `yaml:"textfile"`
	XFS          bool           `yaml:"xfs"`
	ZFS          bool           `yaml:"zfs"`
}

// CPUConfig holds CPU collector configuration.
type CPUConfig struct {
	Enabled      bool   `yaml:"enabled"`
	EnableGuest  bool   `yaml:"enable_guest"`
	EnableInfo   bool   `yaml:"enable_info"`
	FlagsInclude string `yaml:"flags_include"`
	BugsInclude  string `yaml:"bugs_include"`
}

// DiskstatsConfig holds diskstats collector configuration.
type DiskstatsConfig struct {
	Enabled        bool   `yaml:"enabled"`
	IgnoredDevices string `yaml:"ignored_devices"`
	AcceptDevices  string `yaml:"accept_devices"`
}

// FilesystemConfig holds filesystem collector configuration.
type FilesystemConfig struct {
	Enabled            bool          `yaml:"enabled"`
	MountPointsExclude string        `yaml:"mount_points_exclude"`
	MountPointsInclude string        `yaml:"mount_points_include"`
	FSTypesExclude     string        `yaml:"fs_types_exclude"`
	FSTypesInclude     string        `yaml:"fs_types_include"`
	MountTimeout       time.Duration `yaml:"mount_timeout"`
	StatWorkers        int           `yaml:"stat_workers"`
}

// NetdevConfig holds netdev collector configuration.
type NetdevConfig struct {
	Enabled         bool   `yaml:"enabled"`
	DeviceInclude   string `yaml:"device_include"`
	DeviceExclude   string `yaml:"device_exclude"`
	AddressInfo     bool   `yaml:"address_info"`
	DetailedMetrics bool   `yaml:"detailed_metrics"`
	UseNetlink      bool   `yaml:"use_netlink"`
}

// StatConfig holds stat collector configuration.
type StatConfig struct {
	Enabled bool `yaml:"enabled"`
	Softirq bool `yaml:"softirq"`
}

// TextfileConfig holds textfile collector configuration.
type TextfileConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Directory string `yaml:"directory"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Enabled:   true,
		Namespace: "node",
		Paths: PathsConfig{
			ProcPath:     "/proc",
			SysPath:      "/sys",
			RootPath:     "/",
			UdevDataPath: "/run/udev/data",
		},
		Endpoint: EndpointConfig{
			Port: 9100,
			Path: "/metrics",
		},
		Scrape: ScrapeConfig{
			Timeout: 10 * time.Second,
		},
		Export: ExportConfig{
			Enabled:      false,
			Interval:     15 * time.Second,
			UseOTLP:      true,
			BatchSize:    1000,
			FlushTimeout: 5 * time.Second,
		},
		Environment: EnvironmentConfig{
			Type:       "auto",
			AutoDetect: true,
			Labels:     make(map[string]string),
		},
		Collectors: CollectorsConfig{
			// Core collectors - enabled by default
			CPU: CPUConfig{
				Enabled:     true,
				EnableGuest: true,
				EnableInfo:  false,
			},
			Meminfo: true,
			Loadavg: true,
			Diskstats: DiskstatsConfig{
				Enabled:        true,
				IgnoredDevices: "^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$",
			},
			Filesystem: FilesystemConfig{
				Enabled:            true,
				MountPointsExclude: "^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)",
				FSTypesExclude:     "^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|erofs|sysfs|tracefs)$",
				MountTimeout:       5 * time.Second,
				StatWorkers:        4,
			},
			Netdev: NetdevConfig{
				Enabled:    true,
				UseNetlink: true,
			},
			Netstat: true,
			Stat: StatConfig{
				Enabled: true,
				Softirq: false,
			},
			Uname:     true,
			Time:      true,
			Conntrack: false,
			VMstat:    true,

			// Hardware collectors - disabled by default
			Hwmon:       false,
			Thermal:     false,
			PowerSupply: false,

			// Extended collectors - mostly disabled by default
			Pressure:     true, // PSI is useful
			Processes:    false,
			Arp:          false,
			Entropy:      false,
			Edac:         false,
			Fibrechannel: false,
			Infiniband:   false,
			IPVS:         false,
			NFS:          false,
			NFSd:         false,
			NVME:         false,
			Rapl:         false,
			Schedstat:    false,
			Sockstat:     true,
			Softnet:      false,
			Tapestats:    false,
			Textfile: TextfileConfig{
				Enabled:   false,
				Directory: "/var/lib/node_exporter/textfile_collector",
			},
			XFS: false,
			ZFS: false,
		},
	}
}

// IsCollectorEnabled checks if a collector is enabled.
func (c *Config) IsCollectorEnabled(name string, defaultEnabled bool) bool {
	switch name {
	case "cpu":
		return c.Collectors.CPU.Enabled
	case "meminfo":
		return c.Collectors.Meminfo
	case "loadavg":
		return c.Collectors.Loadavg
	case "diskstats":
		return c.Collectors.Diskstats.Enabled
	case "filesystem":
		return c.Collectors.Filesystem.Enabled
	case "netdev":
		return c.Collectors.Netdev.Enabled
	case "netstat":
		return c.Collectors.Netstat
	case "stat":
		return c.Collectors.Stat.Enabled
	case "uname":
		return c.Collectors.Uname
	case "time":
		return c.Collectors.Time
	case "conntrack":
		return c.Collectors.Conntrack
	case "vmstat":
		return c.Collectors.VMstat
	case "hwmon":
		return c.Collectors.Hwmon
	case "thermal":
		return c.Collectors.Thermal
	case "power_supply":
		return c.Collectors.PowerSupply
	case "pressure":
		return c.Collectors.Pressure
	case "processes":
		return c.Collectors.Processes
	case "arp":
		return c.Collectors.Arp
	case "entropy":
		return c.Collectors.Entropy
	case "edac":
		return c.Collectors.Edac
	case "fibrechannel":
		return c.Collectors.Fibrechannel
	case "infiniband":
		return c.Collectors.Infiniband
	case "ipvs":
		return c.Collectors.IPVS
	case "nfs":
		return c.Collectors.NFS
	case "nfsd":
		return c.Collectors.NFSd
	case "nvme":
		return c.Collectors.NVME
	case "rapl":
		return c.Collectors.Rapl
	case "schedstat":
		return c.Collectors.Schedstat
	case "sockstat":
		return c.Collectors.Sockstat
	case "softnet":
		return c.Collectors.Softnet
	case "tapestats":
		return c.Collectors.Tapestats
	case "textfile":
		return c.Collectors.Textfile.Enabled
	case "xfs":
		return c.Collectors.XFS
	case "zfs":
		return c.Collectors.ZFS
	default:
		return defaultEnabled
	}
}
