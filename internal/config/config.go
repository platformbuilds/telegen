package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/platformbuilds/telegen/internal/appolly/services"
	"github.com/platformbuilds/telegen/internal/nodeexporter"
	obiconfig "github.com/platformbuilds/telegen/internal/obiconfig"
	"github.com/platformbuilds/telegen/internal/transform"
	"github.com/platformbuilds/telegen/pkg/export/otel/otelcfg"
	"github.com/platformbuilds/telegen/pkg/export/prom"
	"github.com/platformbuilds/telegen/pkg/filter"
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
		ServiceName string `yaml:"service_name"`
	} `yaml:"agent"`
	SelfTelemetry struct {
		Listen string `yaml:"listen"`
		NS     string `yaml:"prometheus_namespace"`
	} `yaml:"selfTelemetry"`
	Cloud struct {
		AWS AWS `yaml:"aws"`
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
			AlsoExposeProm bool `yaml:"also_expose_prometheus"`
		} `yaml:"metrics"`
		Traces struct{ Enabled bool } `yaml:"traces"`
		Logs   struct {
			Enabled bool
			Filelog struct {
				Include      []string `yaml:"include"`
				PositionFile string   `yaml:"position_file"`
				// ShipHistoricalEvents controls whether to ship log entries that existed before Telegen started.
				// When false (default), only new log entries written after Telegen's start time are shipped.
				// Set to true to ship all existing log content (useful for backfilling).
				ShipHistoricalEvents bool `yaml:"ship_historical_events"`
			} `yaml:"filelog"`
		} `yaml:"logs"`
		JFR JFRConfig `yaml:"jfr"`
	} `yaml:"pipelines"`

	// eBPF instrumentation configuration (OBI integration)
	EBPF EBPFConfig `yaml:"ebpf"`

	// NodeExporter provides Prometheus node_exporter compatible system metrics
	NodeExporter nodeexporter.Config `yaml:"node_exporter"`
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
	_, _ = fmt.Sscanf(size, "%d", &val)
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

type Q struct {
	MemLimit  string `yaml:"mem_limit"`
	MaxAgeStr string `yaml:"max_age"`
}

func (q Q) MaxAge() time.Duration { d, _ := time.ParseDuration(q.MaxAgeStr); return d }

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
		Enabled    bool              `yaml:"enabled"`
		Endpoint   string            `yaml:"endpoint"`
		TracesPath string            `yaml:"traces_path"`
		LogsPath   string            `yaml:"logs_path"`
		Headers    map[string]string `yaml:"headers"`
		Gzip       bool              `yaml:"gzip"`
		Timeout    string            `yaml:"timeout"`
	} `yaml:"http"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.SelfTelemetry.Listen == "" {
		c.SelfTelemetry.Listen = ":19090"
	}
	return &c, nil
}

type AWS struct {
	Enabled         bool     `yaml:"enabled"`
	Timeout         string   `yaml:"timeout"`
	RefreshInterval string   `yaml:"refresh_interval"`
	CollectTags     bool     `yaml:"collect_tags"`
	TagAllowlist    []string `yaml:"tag_allowlist"`
	IMDSBaseURL     string   `yaml:"imds_base_url"`
	DisableProbe    bool     `yaml:"disable_probe"`
}
