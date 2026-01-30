package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/platformbuilds/telegen/internal/appolly/services"
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
			} `yaml:"filelog"`
		} `yaml:"logs"`
		JFR JFRConfig `yaml:"jfr"`
	} `yaml:"pipelines"`

	// eBPF instrumentation configuration (OBI integration)
	EBPF EBPFConfig `yaml:"ebpf"`
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
	Enabled          bool   `yaml:"enabled"`
	InputDir         string `yaml:"input_dir"`
	OutputDir        string `yaml:"output_dir"`
	PollInterval     string `yaml:"poll_interval"`
	SampleIntervalMs int    `yaml:"sample_interval_ms"`
	JFRCommand       string `yaml:"jfr_command"`
	Workers          int    `yaml:"workers"`
	PrettyJSON       bool   `yaml:"pretty_json"`
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
