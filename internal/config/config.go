package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"gopkg.in/yaml.v3"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/services"
	"github.com/mirastacklabs-ai/telegen/internal/netinfra"
	"github.com/mirastacklabs-ai/telegen/internal/nodeexporter"
	obiconfig "github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/internal/profiler"
	"github.com/mirastacklabs-ai/telegen/internal/snmp"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
	"github.com/mirastacklabs-ai/telegen/internal/transform"
	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/otelcfg"
	"github.com/mirastacklabs-ai/telegen/pkg/export/prom"
	"github.com/mirastacklabs-ai/telegen/pkg/filter"
)

type TLS struct {
	Enable             bool   `yaml:"enable"`
	CAFile             string `yaml:"ca_file"`
	CertFile           string `yaml:"cert_file"`
	KeyFile            string `yaml:"key_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type Config struct {
	Agent struct {
		ServiceName     string        `yaml:"service_name"`
		InstanceID      string        `yaml:"instance_id"`
		Mode            string        `yaml:"mode"`
		LogLevel        string        `yaml:"log_level"`
		LogFormat       string        `yaml:"log_format"`
		ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
		EnforceSysCaps  bool          `yaml:"enforce_sys_caps"`
	} `yaml:"agent"`
	SelfTelemetry struct {
		Listen       string `yaml:"listen"`
		HealthListen string `yaml:"health_listen"`
		NS           string `yaml:"prometheus_namespace"`
		PprofEnabled bool   `yaml:"pprof_enabled"`
		PprofPort    int    `yaml:"pprof_port"`
		// MemoryLimitBytes sets a soft process heap ceiling for Go's runtime.
		// Keep 0 to leave the memory limit unset.
		MemoryLimitBytes int64 `yaml:"memory_limit_bytes"`
	} `yaml:"selfTelemetry"`
	Cloud struct {
		AutoDetect        bool          `yaml:"auto_detect"`
		DetectionTimeout  time.Duration `yaml:"detection_timeout"`
		DetectionInterval time.Duration `yaml:"detection_interval"`
		CollectMetrics    bool          `yaml:"collect_metrics"`
		MetricsInterval   time.Duration `yaml:"metrics_interval"`
		DiscoverResources bool          `yaml:"discover_resources"`
		ResourceInterval  time.Duration `yaml:"resource_interval"`
		AWS               AWS           `yaml:"aws"`
		GCP               GCP           `yaml:"gcp"`
		Azure             Azure         `yaml:"azure"`
	} `yaml:"cloud"`
	Queues struct {
		Metrics Q `yaml:"metrics"`
		Traces  Q `yaml:"traces"`
		Logs    Q `yaml:"logs"`
	} `yaml:"queues"`
	Backoff struct {
		Initial    string  `yaml:"initial"`
		Max        string  `yaml:"max"`
		Multiplier float64 `yaml:"multiplier"`
		Jitter     float64 `yaml:"jitter"`
	} `yaml:"backoff"`
	Exports struct {
		RemoteWrite RemoteWrite `yaml:"remoteWrite"`
		OTLP        OTLP        `yaml:"otlp"`
	} `yaml:"exports"`
	Pipelines struct {
		Metrics struct {
			AlsoExposeProm   bool `yaml:"also_expose_prometheus"`
			CardinalityLimit int  `yaml:"cardinality_limit"`
		} `yaml:"metrics"`
		Traces struct{ Enabled bool } `yaml:"traces"`
		Logs   struct {
			Enabled bool          `yaml:"enabled"`
			Filelog FilelogConfig `yaml:"filelog"`
		} `yaml:"logs"`
		JFR   JFRConfig       `yaml:"jfr"`
		Kafka KafkaLogsConfig `yaml:"kafka"`
	} `yaml:"pipelines"`

	// eBPF instrumentation configuration (OBI integration)
	EBPF EBPFConfig `yaml:"ebpf"`

	// eBPF Profiling configuration
	Profiling profiler.RunnerConfig `yaml:"profiling"`

	// NodeExporter provides Prometheus node_exporter compatible system metrics
	NodeExporter nodeexporter.Config `yaml:"node_exporter"`

	// KubeMetrics provides native kube-state-metrics + cAdvisor equivalent
	// Auto-enabled when running in a Kubernetes cluster
	KubeMetrics KubeMetricsConfig `yaml:"kube_metrics"`

	// Kubernetes configures Kubernetes metadata decoration
	Kubernetes KubernetesConfig `yaml:"kubernetes"`

	// Storage configures storage array metric collection (Pure, Dell, HPE, NetApp).
	// Activated when storage.enabled: true in the config file or --mode collector is used.
	Storage storagedef.Config `yaml:"storage"`

	// VMware configures VMware vSphere (vCenter) metric + event collection.
	// Activated when vmware.enabled: true or --mode collector/unified is used.
	VMware vmwaredef.Config `yaml:"vmware"`

	// NetInfra configures network infrastructure metric collection
	// (Cisco ACI, Arista CloudVision, Palo Alto, FortiGate).
	NetInfra netinfra.Config `yaml:"netinfra"`

	// SNMPReceiver configures SNMP polling/traps collection.
	SNMPReceiver snmp.Config `yaml:"snmp_receiver"`
}

// FilelogConfig configures the file-based log collection pipeline.
type FilelogConfig struct {
	// Include is a list of file glob patterns to tail (e.g., /var/log/*.log).
	// Used for both K8s and non-K8s environments.
	Include []string `yaml:"include"`

	// Exclude is a list of file glob patterns to skip, even if matched by Include
	// or discovered via the Kubernetes section. Example: /var/log/containers/*telegen*.log
	Exclude []string `yaml:"exclude"`

	// PositionFile stores file read positions for resuming after restart.
	PositionFile string `yaml:"position_file"`

	// PollInterval controls how often to check for new log content (default: 500ms).
	PollInterval string `yaml:"poll_interval"`

	// ShipHistoricalEvents controls whether to ship log entries that existed before Telegen started.
	// When false (default), only new log entries written after Telegen's start time are shipped.
	// Set to true to ship all existing log content (useful for backfilling).
	ShipHistoricalEvents bool `yaml:"ship_historical_events"`

	// Kubernetes enables K8s-aware log discovery using informers.
	// When set, telegen discovers pod log files dynamically based on
	// namespace, deployment, app name, or labels — instead of (or in addition to) static globs.
	// The discovered paths are merged with Include paths (both work together).
	Kubernetes *K8sLogDiscovery `yaml:"kubernetes,omitempty"`
}

// PollIntervalDuration returns the poll interval as a time.Duration.
func (f FilelogConfig) PollIntervalDuration() time.Duration {
	if f.PollInterval == "" {
		return 500 * time.Millisecond
	}
	d, err := time.ParseDuration(f.PollInterval)
	if err != nil {
		return 500 * time.Millisecond
	}
	return d
}

// K8sLogDiscovery configures Kubernetes-aware log file discovery.
// Telegen subscribes to its kube.Store (the same informer infrastructure used
// by eBPF discovery) and dynamically resolves log paths for matching pods.
// All string fields support glob wildcards (*, ?).
type K8sLogDiscovery struct {
	// Namespaces to include. Glob patterns. Example: ["prod*", "staging"]
	// If empty, all namespaces are included (subject to ExcludeNamespaces).
	Namespaces []string `yaml:"namespaces"`

	// ExcludeNamespaces to skip. Glob patterns. Example: ["kube-system"]
	ExcludeNamespaces []string `yaml:"exclude_namespaces"`

	// Deployments to include. Glob patterns. Matches against the top-level owner
	// name (resolves through ReplicaSet → Deployment). Example: ["payment-*"]
	Deployments []string `yaml:"deployments"`

	// DaemonSets to include. Glob patterns.
	DaemonSets []string `yaml:"daemonsets"`

	// StatefulSets to include. Glob patterns.
	StatefulSets []string `yaml:"statefulsets"`

	// AppNames matches the app.kubernetes.io/name pod label. Glob patterns.
	// Example: ["my-service-*", "frontend"]
	AppNames []string `yaml:"app_names"`

	// PodLabels matches pods by label key→glob value. All entries must match (AND logic).
	// Example: {"team": "platform*", "env": "prod"}
	PodLabels map[string]string `yaml:"pod_labels"`

	// PodAnnotations matches pods by annotation key→glob value. All entries must match (AND logic).
	// Example: {"telegen.io/logs": "true"}
	PodAnnotations map[string]string `yaml:"pod_annotations"`

	// ContainerNames filters to specific containers within matched pods.
	// Glob patterns. If empty, all containers in the pod are tailed.
	ContainerNames []string `yaml:"container_names"`

	// LogPath is the base directory for K8s pod logs on the node.
	// Default: /var/log/pods
	LogPath string `yaml:"log_path"`
}

// KubernetesConfig holds Kubernetes discovery/decoration settings
type KubernetesConfig struct {
	// Enable Kubernetes metadata decoration
	Enable bool `yaml:"enable"`

	// ClusterName overrides the cluster name. If empty, the module will try to retrieve
	// it from the Cloud Provider Metadata (EC2, GCP, and Azure), and leave it empty if it fails.
	ClusterName string `yaml:"cluster_name" env:"OTEL_EBPF_KUBE_CLUSTER_NAME"`

	// InformersSyncTimeout is the timeout for informers sync
	InformersSyncTimeout string `yaml:"informers_sync_timeout"`

	// InformersResyncPeriod is the resync period for informers
	InformersResyncPeriod string `yaml:"informers_resync_period"`

	// ResourceLabels are the resource labels to include
	ResourceLabels []string `yaml:"resource_labels"`
}

// EBPFConfig holds configuration for eBPF-based auto-instrumentation (from OBI)
type EBPFConfig struct {
	// Enabled controls whether eBPF instrumentation is active
	Enabled bool `yaml:"enabled"`

	// Tracer holds eBPF tracer settings
	Tracer obiconfig.EBPFTracer `yaml:"tracer"`

	// Discovery configuration for finding processes to instrument
	Discovery services.DiscoveryConfig `yaml:"discovery"`

	// NameResolver configuration for resolving service names
	NameResolver *transform.NameResolverConfig `yaml:"name_resolver"`

	// Routes for request path aggregation
	Routes *transform.RoutesConfig `yaml:"routes"`

	// Filters for attribute-based filtering
	Filters filter.AttributesConfig `yaml:"filter"`

	// OTELMetrics configures OpenTelemetry metrics export
	OTELMetrics otelcfg.MetricsConfig `yaml:"otel_metrics_export"`

	// Traces configures OpenTelemetry traces export
	Traces otelcfg.TracesConfig `yaml:"otel_traces_export"`

	// Prometheus configures Prometheus metrics endpoint
	Prometheus prom.PrometheusConfig `yaml:"prometheus_export"`

	// InternalMetrics configures OBI internal metrics reporter export.
	InternalMetrics imetrics.Config `yaml:"internal_metrics"`

	// NetworkFlows configures network observability
	NetworkFlows NetworkFlowsConfig `yaml:"network"`
}

// NetworkFlowsConfig holds configuration for network flow observability
type NetworkFlowsConfig struct {
	Enabled bool `yaml:"enabled"`
	// Additional network config fields can be added as needed
}

// JFRConfig holds Java Flight Recorder pipeline configuration
type JFRConfig struct {
	Enabled          bool     `yaml:"enabled"`
	InputDirs        []string `yaml:"input_dirs"` // Directories to watch for JFR files
	Recursive        *bool    `yaml:"recursive"`  // Watch subdirectories recursively (default: true)
	OutputDir        string   `yaml:"output_dir"`
	PollInterval     string   `yaml:"poll_interval"`
	SampleIntervalMs int      `yaml:"sample_interval_ms"`
	// UseNativeParser uses the built-in Go JFR parser instead of external jfr command.
	// This eliminates the JDK dependency. Default: true
	UseNativeParser bool   `yaml:"use_native_parser"`
	JFRCommand      string `yaml:"jfr_command"`
	Workers         int    `yaml:"workers"`
	PrettyJSON      bool   `yaml:"pretty_json"`
	// ShipHistoricalEvents controls whether to ship events that occurred before Telegen started.
	// When false (default), only events with timestamps after Telegen's start time are shipped.
	// Set to true to ship all events including historical data (useful for backfilling).
	ShipHistoricalEvents bool `yaml:"ship_historical_events"`
	// Direct OTLP export configuration
	DirectExport DirectExportConfig `yaml:"direct_export"`
}

// IsRecursive returns whether recursive scanning is enabled (defaults to true)
func (j JFRConfig) IsRecursive() bool {
	if j.Recursive == nil {
		return true // Default to true
	}
	return *j.Recursive
}

// GetInputDirs returns all configured input directories
func (j JFRConfig) GetInputDirs() []string {
	var dirs []string
	for _, d := range j.InputDirs {
		if d != "" {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// DirectExportConfig holds configuration for direct OTLP profile export
type DirectExportConfig struct {
	// Enabled enables streaming profiles directly to OTLP endpoint
	Enabled bool `yaml:"enabled"`
	// Endpoint is the OTLP profiles endpoint (e.g., http://localhost:4318/v1/profiles)
	Endpoint string `yaml:"endpoint"`
	// Headers to include in OTLP requests
	Headers map[string]string `yaml:"headers"`
	// Compression type (gzip, none)
	Compression string `yaml:"compression"`
	// Timeout for OTLP requests
	Timeout string `yaml:"timeout"`
	// BatchSize is the number of profiles to batch before sending
	BatchSize int `yaml:"batch_size"`
	// FlushInterval is how often to flush profiles even if batch is not full
	FlushInterval string `yaml:"flush_interval"`
	// SkipFileOutput skips writing JSON files when direct export is enabled
	SkipFileOutput bool `yaml:"skip_file_output"`

	// LogExport configures exporting JFR data as OTLP Logs
	LogExport LogExportConfig `yaml:"log_export"`
}

// LogExportConfig holds configuration for exporting JFR data as OTLP Logs
type LogExportConfig struct {
	// Enabled enables exporting JFR profile data as OTLP Logs
	Enabled bool `yaml:"enabled"`

	// Output destinations (can enable multiple simultaneously)
	// StdoutEnabled prints JFR logs to stdout in JSON format
	StdoutEnabled bool `yaml:"stdout_enabled"`
	// StdoutFormat is the format for stdout output (json, text)
	StdoutFormat string `yaml:"stdout_format"`

	// DiskEnabled writes JFR logs to a file on disk
	DiskEnabled bool `yaml:"disk_enabled"`
	// DiskPath is the path to write log files (e.g., /var/log/telegen/jfr-logs.json)
	DiskPath string `yaml:"disk_path"`
	// DiskRotateSize is the max file size before rotation (e.g., 100MB)
	DiskRotateSize string `yaml:"disk_rotate_size"`
	// DiskMaxFiles is the maximum number of rotated files to keep
	DiskMaxFiles int `yaml:"disk_max_files"`

	// OTLPEnabled enables shipping logs to OTLP collector (default: true when Enabled is true)
	OTLPEnabled bool `yaml:"otlp_enabled"`
	// Endpoint is the OTLP logs endpoint (e.g., http://localhost:4318/v1/logs)
	// If empty, uses the main OTLP endpoint with /v1/logs path
	Endpoint string `yaml:"endpoint"`
	// Headers to include in OTLP log requests
	Headers map[string]string `yaml:"headers"`
	// Compression type (gzip, none)
	Compression string `yaml:"compression"`
	// Timeout for OTLP log requests
	Timeout string `yaml:"timeout"`
	// BatchSize is the number of log records to batch before sending
	BatchSize int `yaml:"batch_size"`
	// FlushInterval is how often to flush logs even if batch is not full
	FlushInterval string `yaml:"flush_interval"`
	// IncludeStackTrace includes full stack trace in log body
	IncludeStackTrace bool `yaml:"include_stack_trace"`
	// IncludeRawJSON includes the full JSON representation in log body
	IncludeRawJSON bool `yaml:"include_raw_json"`
}

// IsOTLPEnabled returns true if OTLP export should be enabled
// For backward compatibility: if OTLPEnabled is not explicitly set but Enabled is true, OTLP is enabled
func (l LogExportConfig) IsOTLPEnabled() bool {
	// Explicit setting takes precedence
	if l.OTLPEnabled {
		return true
	}
	// Backward compat: if none of the new outputs are explicitly enabled, default to OTLP
	if l.Enabled && !l.StdoutEnabled && !l.DiskEnabled {
		return true
	}
	return false
}

// DiskRotateSizeBytes returns the disk rotation size in bytes
func (l LogExportConfig) DiskRotateSizeBytes() int64 {
	if l.DiskRotateSize == "" {
		return 100 * 1024 * 1024 // 100MB default
	}
	size := l.DiskRotateSize
	var multiplier int64 = 1
	if len(size) > 2 {
		suffix := size[len(size)-2:]
		switch suffix {
		case "KB", "kb":
			multiplier = 1024
			size = size[:len(size)-2]
		case "MB", "mb":
			multiplier = 1024 * 1024
			size = size[:len(size)-2]
		case "GB", "gb":
			multiplier = 1024 * 1024 * 1024
			size = size[:len(size)-2]
		}
	}
	var val int64
	if _, err := fmt.Sscanf(size, "%d", &val); err != nil {
		return 100 * 1024 * 1024
	}
	if val <= 0 {
		return 100 * 1024 * 1024
	}
	return val * multiplier
}

// TimeoutDuration returns the log export timeout as a time.Duration
func (l LogExportConfig) TimeoutDuration() time.Duration {
	if l.Timeout == "" {
		return 30 * time.Second
	}
	dur, err := time.ParseDuration(l.Timeout)
	if err != nil {
		return 30 * time.Second
	}
	return dur
}

// FlushIntervalDuration returns the log export flush interval as a time.Duration
func (l LogExportConfig) FlushIntervalDuration() time.Duration {
	if l.FlushInterval == "" {
		return 10 * time.Second
	}
	dur, err := time.ParseDuration(l.FlushInterval)
	if err != nil {
		return 10 * time.Second
	}
	return dur
}

// TimeoutDuration returns the timeout as a time.Duration
func (d DirectExportConfig) TimeoutDuration() time.Duration {
	if d.Timeout == "" {
		return 30 * time.Second
	}
	dur, err := time.ParseDuration(d.Timeout)
	if err != nil {
		return 30 * time.Second
	}
	return dur
}

// FlushIntervalDuration returns the flush interval as a time.Duration
func (d DirectExportConfig) FlushIntervalDuration() time.Duration {
	if d.FlushInterval == "" {
		return 10 * time.Second
	}
	dur, err := time.ParseDuration(d.FlushInterval)
	if err != nil {
		return 10 * time.Second
	}
	return dur
}

// PollIntervalDuration returns the poll interval as a time.Duration
func (j JFRConfig) PollIntervalDuration() time.Duration {
	if j.PollInterval == "" {
		return 5 * time.Second
	}
	d, err := time.ParseDuration(j.PollInterval)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

// KafkaClusterConfig holds configuration for a single Kafka cluster
type KafkaClusterConfig struct {
	// Name is a unique identifier for this cluster (required for multi-cluster)
	Name string `yaml:"name"`

	// Brokers is a list of Kafka broker addresses
	Brokers []string `yaml:"brokers"`

	// GroupID is the consumer group identifier for coordinated consumption
	GroupID string `yaml:"group_id"`

	// ClientID is the unique client identifier (auto-generated if empty)
	ClientID string `yaml:"client_id"`

	// Topics is a list of topic names to consume from
	Topics []string `yaml:"topics"`

	// ExcludeTopics is a regex pattern for topics to exclude
	ExcludeTopics []string `yaml:"exclude_topics"`

	// InitialOffset is the starting position: "latest" or "earliest"
	InitialOffset string `yaml:"initial_offset"`

	// SessionTimeout is the broker's heartbeat detection timeout
	SessionTimeout string `yaml:"session_timeout"`

	// HeartbeatInterval is the frequency of heartbeats
	HeartbeatInterval string `yaml:"heartbeat_interval"`

	// RebalanceTimeout is the maximum time for rebalance completion
	RebalanceTimeout string `yaml:"rebalance_timeout"`

	// GroupRebalanceStrategy for partition assignment
	// Valid: "range", "roundrobin", "sticky", "cooperative-sticky"
	GroupRebalanceStrategy string `yaml:"group_rebalance_strategy"`

	// MessageMarking controls offset commit behavior
	MessageMarking struct {
		After            bool `yaml:"after"`
		OnError          bool `yaml:"on_error"`
		OnPermanentError bool `yaml:"on_permanent_error"`
	} `yaml:"message_marking"`

	// Batch configuration
	Batch struct {
		Size              int    `yaml:"size"`
		Timeout           string `yaml:"timeout"`
		MaxPartitionBytes int64  `yaml:"max_partition_bytes"`
	} `yaml:"batch"`

	// Parser configuration for log format detection and parsing
	Parser struct {
		EnableRuntimeParsing         bool     `yaml:"enable_runtime_parsing"`
		EnableApplicationParsing     bool     `yaml:"enable_application_parsing"`
		EnableK8sEnrichment          bool     `yaml:"enable_k8s_enrichment"`
		EnableTraceContextEnrichment bool     `yaml:"enable_trace_context_enrichment"`
		TraceContextTolerance        string   `yaml:"trace_context_tolerance"`
		ApplicationParsers           []string `yaml:"application_parsers"`
		DefaultSeverity              string   `yaml:"default_severity"`
	} `yaml:"parser"`

	// Telemetry configuration
	Telemetry struct {
		KafkaReceiverRecords      bool `yaml:"kafka_receiver_records"`
		KafkaReceiverOffsetLag    bool `yaml:"kafka_receiver_offset_lag"`
		KafkaReceiverRecordsDelay bool `yaml:"kafka_receiver_records_delay"`
		KafkaBrokerConnects       bool `yaml:"kafka_broker_connects"`
		KafkaBrokerDisconnects    bool `yaml:"kafka_broker_disconnects"`
		KafkaBrokerReadLatency    bool `yaml:"kafka_broker_read_latency"`
		KafkaFetchBatchMetrics    bool `yaml:"kafka_fetch_batch_metrics"`
	} `yaml:"telemetry"`

	// Authentication via SASL
	Auth struct {
		Enabled   bool   `yaml:"enabled"`
		Mechanism string `yaml:"mechanism"`
		Username  string `yaml:"username"`
		Password  string `yaml:"password"`
	} `yaml:"auth"`

	// TLS configuration
	TLS struct {
		Enable             bool   `yaml:"enable"`
		CAFile             string `yaml:"ca_file"`
		CertFile           string `yaml:"cert_file"`
		KeyFile            string `yaml:"key_file"`
		InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	} `yaml:"tls"`

	// Error handling with exponential backoff retry
	ErrorBackoff struct {
		Enabled         bool    `yaml:"enabled"`
		InitialInterval string  `yaml:"initial_interval"`
		MaxInterval     string  `yaml:"max_interval"`
		Multiplier      float64 `yaml:"multiplier"`
		Jitter          float64 `yaml:"jitter"`
	} `yaml:"error_backoff"`

	// UseLeaderEpoch enables leader epoch for offset validation (requires Kafka >= 2.1.0)
	UseLeaderEpoch bool `yaml:"use_leader_epoch"`

	// HeaderExtraction controls extraction of Kafka message headers as resource attributes
	HeaderExtraction struct {
		ExtractHeaders bool     `yaml:"extract_headers"`
		Headers        []string `yaml:"headers"`
	} `yaml:"header_extraction"`
}

// KafkaLogsConfig holds Kafka receiver configuration for log streaming.
// Supports both single-cluster (backward compatible) and multi-cluster configurations.
type KafkaLogsConfig struct {
	// Enabled enables the Kafka logs receiver pipeline
	Enabled bool `yaml:"enabled"`

	// ========================================================================
	// AUTO-DISCOVERY MODE (simplest configuration)
	// Just specify namespace and topics - everything else is auto-detected
	// ========================================================================
	AutoDiscovery struct {
		// Enabled enables automatic Kafka cluster discovery from K8s CRDs
		// When enabled, you only need to specify Namespace and Topics
		// Telegen will automatically detect Strimzi/Confluent clusters,
		// extract connection details, and fetch credentials from secrets
		Enabled bool `yaml:"enabled"`

		// Namespace to scan for Kafka deployments
		// Supports wildcards: "kafka-*" for prefix match, "*" for all namespaces
		Namespace string `yaml:"namespace"`

		// Topics to subscribe to (required)
		Topics []string `yaml:"topics"`

		// GroupID for the consumer group (optional, auto-generated if empty)
		GroupID string `yaml:"group_id"`

		// InitialOffset: "latest" or "earliest" (default: "latest")
		InitialOffset string `yaml:"initial_offset"`
	} `yaml:"auto_discovery"`

	// Clusters contains multi-cluster configurations (takes precedence over single-cluster fields)
	// When Clusters is non-empty, the single-cluster fields below are ignored.
	Clusters []KafkaClusterConfig `yaml:"clusters"`

	// ========================================================================
	// Single-cluster configuration (backward compatible)
	// These fields are used when Clusters is empty
	// ========================================================================

	// Brokers is a list of Kafka broker addresses
	Brokers []string `yaml:"brokers"`

	// GroupID is the consumer group identifier for coordinated consumption
	GroupID string `yaml:"group_id"`

	// ClientID is the unique client identifier (auto-generated if empty)
	ClientID string `yaml:"client_id"`

	// Topics is a list of topic names to consume from
	Topics []string `yaml:"topics"`

	// ExcludeTopics is a regex pattern for topics to exclude
	ExcludeTopics []string `yaml:"exclude_topics"`

	// InitialOffset is the starting position: "latest" or "earliest"
	InitialOffset string `yaml:"initial_offset"`

	// SessionTimeout is the broker's heartbeat detection timeout
	SessionTimeout string `yaml:"session_timeout"`

	// HeartbeatInterval is the frequency of heartbeats
	HeartbeatInterval string `yaml:"heartbeat_interval"`

	// RebalanceTimeout is the maximum time for rebalance completion
	RebalanceTimeout string `yaml:"rebalance_timeout"`

	// GroupRebalanceStrategy for partition assignment
	// Valid: "range", "roundrobin", "sticky", "cooperative-sticky"
	GroupRebalanceStrategy string `yaml:"group_rebalance_strategy"`

	// MessageMarking controls offset commit behavior
	MessageMarking struct {
		After            bool `yaml:"after"`              // Commit after processing
		OnError          bool `yaml:"on_error"`           // Commit on transient errors
		OnPermanentError bool `yaml:"on_permanent_error"` // Commit on permanent errors
	} `yaml:"message_marking"`

	// Batch configuration
	Batch struct {
		Size              int    `yaml:"size"`                // Max messages per batch
		Timeout           string `yaml:"timeout"`             // Max batch wait time
		MaxPartitionBytes int64  `yaml:"max_partition_bytes"` // Max bytes per partition
	} `yaml:"batch"`

	// Parser configuration for log format detection and parsing
	Parser struct {
		EnableRuntimeParsing         bool     `yaml:"enable_runtime_parsing"`          // Docker JSON, CRI-O, containerd
		EnableApplicationParsing     bool     `yaml:"enable_application_parsing"`      // Spring Boot, Log4j, JSON
		EnableK8sEnrichment          bool     `yaml:"enable_k8s_enrichment"`           // K8s metadata extraction
		EnableTraceContextEnrichment bool     `yaml:"enable_trace_context_enrichment"` // eBPF trace correlation
		TraceContextTolerance        string   `yaml:"trace_context_tolerance"`         // Timestamp skew window
		ApplicationParsers           []string `yaml:"application_parsers"`             // Specific parsers to enable
		DefaultSeverity              string   `yaml:"default_severity"`                // Default log level
	} `yaml:"parser"`

	// Telemetry configuration
	Telemetry struct {
		KafkaReceiverRecords      bool `yaml:"kafka_receiver_records"`
		KafkaReceiverOffsetLag    bool `yaml:"kafka_receiver_offset_lag"`
		KafkaReceiverRecordsDelay bool `yaml:"kafka_receiver_records_delay"`
		KafkaBrokerConnects       bool `yaml:"kafka_broker_connects"`
		KafkaBrokerDisconnects    bool `yaml:"kafka_broker_disconnects"`
		KafkaBrokerReadLatency    bool `yaml:"kafka_broker_read_latency"`
		KafkaFetchBatchMetrics    bool `yaml:"kafka_fetch_batch_metrics"`
	} `yaml:"telemetry"`

	// Authentication via SASL
	Auth struct {
		Enabled   bool   `yaml:"enabled"`
		Mechanism string `yaml:"mechanism"` // PLAIN, SCRAM-SHA-256, SCRAM-SHA-512
		Username  string `yaml:"username"`
		Password  string `yaml:"password"`
	} `yaml:"auth"`

	// TLS configuration
	TLS struct {
		Enable             bool   `yaml:"enable"`
		CAFile             string `yaml:"ca_file"`
		CertFile           string `yaml:"cert_file"`
		KeyFile            string `yaml:"key_file"`
		InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	} `yaml:"tls"`

	// Error handling with exponential backoff retry
	ErrorBackoff struct {
		Enabled         bool    `yaml:"enabled"`
		InitialInterval string  `yaml:"initial_interval"`
		MaxInterval     string  `yaml:"max_interval"`
		Multiplier      float64 `yaml:"multiplier"`
		Jitter          float64 `yaml:"jitter"`
	} `yaml:"error_backoff"`

	// UseLeaderEpoch enables leader epoch for offset validation (requires Kafka >= 2.1.0)
	// Disable for compatibility with older Kafka versions
	UseLeaderEpoch bool `yaml:"use_leader_epoch"`

	// HeaderExtraction controls extraction of Kafka message headers as resource attributes
	HeaderExtraction struct {
		ExtractHeaders bool     `yaml:"extract_headers"` // Enable header extraction
		Headers        []string `yaml:"headers"`         // Specific headers to extract (empty = all)
	} `yaml:"header_extraction"`

	// Discovery configures automatic discovery of Kafka clusters from Kubernetes CRDs
	// (Strimzi and Confluent for Kubernetes operators)
	Discovery struct {
		// Enabled enables automatic cluster discovery from Kubernetes CRDs
		Enabled bool `yaml:"enabled"`

		// Namespaces to watch for Kafka CRDs (empty = all namespaces)
		Namespaces []string `yaml:"namespaces"`

		// LabelSelector filters which Kafka CRs to discover (standard k8s label selector)
		LabelSelector string `yaml:"label_selector"`

		// ResyncInterval is how often to re-list all CRDs (default: 5m)
		ResyncInterval string `yaml:"resync_interval"`

		// Strimzi configures Strimzi Kafka operator discovery
		Strimzi struct {
			// Enabled enables discovery of Strimzi Kafka CRs (kafka.strimzi.io/v1beta2)
			Enabled bool `yaml:"enabled"`

			// ListenerName is the listener to use for broker addresses (e.g., "plain", "tls")
			ListenerName string `yaml:"listener_name"`

			// UseInternalListener prefers internal/cluster-local addresses (default: true)
			UseInternalListener bool `yaml:"use_internal_listener"`
		} `yaml:"strimzi"`

		// Confluent configures Confluent for Kubernetes discovery
		Confluent struct {
			// Enabled enables discovery of Confluent Kafka CRs (platform.confluent.io/v1beta1)
			Enabled bool `yaml:"enabled"`

			// UseInternalEndpoint prefers internal/cluster-local addresses (default: true)
			UseInternalEndpoint bool `yaml:"use_internal_endpoint"`
		} `yaml:"confluent"`

		// DefaultConfig provides default values applied to all discovered clusters
		DefaultConfig struct {
			// GroupIDPrefix is prepended to cluster name for consumer group ID
			GroupIDPrefix string `yaml:"group_id_prefix"`

			// Topics to consume from all discovered clusters
			Topics []string `yaml:"topics"`

			// InitialOffset for discovered clusters: "latest" or "earliest"
			InitialOffset string `yaml:"initial_offset"`

			// UseLeaderEpoch for discovered clusters
			UseLeaderEpoch bool `yaml:"use_leader_epoch"`

			// SessionTimeout for discovered clusters
			SessionTimeout string `yaml:"session_timeout"`
		} `yaml:"default_config"`
	} `yaml:"discovery"`
}

type Q struct {
	MemLimit  string `yaml:"mem_limit"`
	MaxAgeStr string `yaml:"max_age"`
}

func (q Q) MaxAge() time.Duration {
	d, err := time.ParseDuration(q.MaxAgeStr)
	if err != nil {
		return 0
	}
	return d
}

type RemoteWrite struct {
	Mode      string       `yaml:"mode"`
	TLS       TLS          `yaml:"tls"`
	Endpoints []RWEndpoint `yaml:"endpoints"`
}
type RWEndpoint struct {
	URL         string            `yaml:"url"`
	Timeout     string            `yaml:"timeout"`
	Headers     map[string]string `yaml:"headers"`
	Tenant      string            `yaml:"tenant"`
	Compression string            `yaml:"compression"`
}

type OTLP struct {
	SendMode string `yaml:"send_mode"`
	TLS      TLS    `yaml:"tls"`
	GRPC     struct {
		Enabled  bool              `yaml:"enabled"`
		Endpoint string            `yaml:"endpoint"`
		Headers  map[string]string `yaml:"headers"`
		Insecure bool              `yaml:"insecure"`
		Gzip     bool              `yaml:"gzip"`
		Timeout  string            `yaml:"timeout"`
	} `yaml:"grpc"`
	HTTP struct {
		Enabled     bool              `yaml:"enabled"`
		Endpoint    string            `yaml:"endpoint"`
		Insecure    bool              `yaml:"insecure"`
		TracesPath  string            `yaml:"traces_path"`
		LogsPath    string            `yaml:"logs_path"`
		MetricsPath string            `yaml:"metrics_path"`
		Headers     map[string]string `yaml:"headers"`
		Gzip        bool              `yaml:"gzip"`
		Timeout     string            `yaml:"timeout"`
	} `yaml:"http"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Expand environment variables in config (e.g., ${OTLP_ENDPOINT})
	expanded := os.ExpandEnv(string(b))
	var c Config
	c.Profiling = profiler.DefaultRunnerConfig()
	c.SelfTelemetry.Listen = ":19090"
	c.SelfTelemetry.HealthListen = ":8080"
	c.Pipelines.Metrics.CardinalityLimit = 2000
	c.EBPF.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
	c.EBPF.InternalMetrics.Prometheus.Path = "/metrics"

	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	// Parse environment variables from struct tags (e.g., env:"OTEL_EBPF_KUBE_CLUSTER_NAME")
	// This allows environment variables to override YAML config values
	if err := env.Parse(&c); err != nil {
		return nil, fmt.Errorf("parsing env vars: %w", err)
	}
	if c.SelfTelemetry.Listen == "" {
		c.SelfTelemetry.Listen = ":19090"
	}
	if c.SelfTelemetry.HealthListen == "" {
		c.SelfTelemetry.HealthListen = ":8080"
	}
	if c.Pipelines.Metrics.CardinalityLimit <= 0 {
		c.Pipelines.Metrics.CardinalityLimit = 2000
	}
	applyInternalMetricsDefaults(&c)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

func applyInternalMetricsDefaults(c *Config) {
	if c == nil {
		return
	}
	if c.EBPF.InternalMetrics.Exporter == "" {
		c.EBPF.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
	}
	if c.EBPF.InternalMetrics.Exporter != imetrics.InternalMetricsExporterPrometheus {
		return
	}
	if c.EBPF.InternalMetrics.Prometheus.Path == "" {
		c.EBPF.InternalMetrics.Prometheus.Path = "/metrics"
	}
	if c.EBPF.InternalMetrics.Prometheus.Port != 0 {
		return
	}
	if _, port, err := net.SplitHostPort(c.SelfTelemetry.Listen); err == nil {
		if parsedPort, convErr := strconv.Atoi(port); convErr == nil && parsedPort > 0 {
			c.EBPF.InternalMetrics.Prometheus.Port = parsedPort
			return
		}
	}
	c.EBPF.InternalMetrics.Prometheus.Port = 19090
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}

	var errs []error
	validateConfigValue(reflect.ValueOf(c).Elem(), "config", &errs)

	validateListen := func(fieldName, addr string) {
		if addr == "" {
			errs = append(errs, fmt.Errorf("%s must not be empty", fieldName))
			return
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			errs = append(errs, fmt.Errorf("%s is not host:port parseable: %w", fieldName, err))
		}
	}

	validateListen("selfTelemetry.listen", c.SelfTelemetry.Listen)
	validateListen("selfTelemetry.health_listen", c.SelfTelemetry.HealthListen)
	if c.SelfTelemetry.MemoryLimitBytes < 0 {
		errs = append(errs, fmt.Errorf("selfTelemetry.memory_limit_bytes must be >= 0"))
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func validateConfigValue(v reflect.Value, fieldPath string, errs *[]error) {
	if !v.IsValid() {
		return
	}

	durationType := reflect.TypeOf(time.Duration(0))
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		validateConfigValue(v.Elem(), fieldPath, errs)
		return
	case reflect.Struct:
		if v.Type() == durationType {
			if v.Int() < 0 {
				*errs = append(*errs, fmt.Errorf("%s must be >= 0", fieldPath))
			}
			return
		}

		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			sf := t.Field(i)
			if sf.PkgPath != "" {
				continue
			}

			fv := v.Field(i)
			nextPath := fieldPath + "." + sf.Name
			if fieldPath == "" {
				nextPath = sf.Name
			}

			if sf.Type == durationType {
				if fv.Int() < 0 {
					*errs = append(*errs, fmt.Errorf("%s must be >= 0", nextPath))
				}
				continue
			}

			if shouldValidateQueueBatchBufferSize(sf, nextPath) && isSignedIntKind(fv.Kind()) && fv.Int() < 0 {
				*errs = append(*errs, fmt.Errorf("%s must be >= 0", nextPath))
			}

			validateConfigValue(fv, nextPath, errs)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			validateConfigValue(v.Index(i), fmt.Sprintf("%s[%d]", fieldPath, i), errs)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			validateConfigValue(iter.Value(), fmt.Sprintf("%s[%v]", fieldPath, iter.Key().Interface()), errs)
		}
	}
}

func shouldValidateQueueBatchBufferSize(sf reflect.StructField, fieldPath string) bool {
	kind := sf.Type.Kind()
	if !isSignedIntKind(kind) {
		return false
	}

	name := strings.ToLower(sf.Name)
	tag := strings.ToLower(sf.Tag.Get("yaml"))
	path := strings.ToLower(fieldPath)
	joined := name + " " + tag + " " + path
	return strings.Contains(joined, "queue") ||
		strings.Contains(joined, "batch") ||
		strings.Contains(joined, "buffer")
}

func isSignedIntKind(kind reflect.Kind) bool {
	return kind == reflect.Int ||
		kind == reflect.Int8 ||
		kind == reflect.Int16 ||
		kind == reflect.Int32 ||
		kind == reflect.Int64
}

type AWS struct {
	Enabled         bool          `yaml:"enabled"`
	Timeout         string        `yaml:"timeout"`
	RefreshInterval string        `yaml:"refresh_interval"`
	CollectTags     bool          `yaml:"collect_tags"`
	TagAllowlist    []string      `yaml:"tag_allowlist"`
	IMDSBaseURL     string        `yaml:"imds_base_url"`
	DisableProbe    bool          `yaml:"disable_probe"`
	Region          string        `yaml:"region"`
	IMDSv2Only      bool          `yaml:"imdsv2_only"`
	IMDSEndpoint    string        `yaml:"imds_endpoint"`
	IMDSTimeout     time.Duration `yaml:"imds_timeout"`
}

type GCP struct {
	Enabled          bool          `yaml:"enabled"`
	Project          string        `yaml:"project"`
	Zone             string        `yaml:"zone"`
	MetadataEndpoint string        `yaml:"metadata_endpoint"`
	MetadataTimeout  time.Duration `yaml:"metadata_timeout"`
}

type Azure struct {
	Enabled        bool          `yaml:"enabled"`
	SubscriptionID string        `yaml:"subscription_id"`
	ResourceGroup  string        `yaml:"resource_group"`
	IMDSEndpoint   string        `yaml:"imds_endpoint"`
	IMDSTimeout    time.Duration `yaml:"imds_timeout"`
}
