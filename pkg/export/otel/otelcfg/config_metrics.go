// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "github.com/mirastacklabs-ai/telegen/pkg/export/otel/otelcfg"

import (
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/consumer"

	"github.com/mirastacklabs-ai/telegen/pkg/export"
	"github.com/mirastacklabs-ai/telegen/pkg/export/instrumentations"
)

func mlog() *slog.Logger {
	return slog.With("component", "otelcfg.MetricsConfig")
}

type MetricsConfig struct {
	// MetricsConsumer is the collector consumer to send metrics to.
	// When set, metrics will be sent directly to this consumer instead of via HTTP/gRPC.
	MetricsConsumer consumer.Metrics `yaml:"-"`

	Interval time.Duration `yaml:"interval" env:"OTEL_EBPF_METRICS_INTERVAL"`
	// OTELIntervalMS supports metric intervals as specified by the standard OTEL definition.
	// OTEL_EBPF_METRICS_INTERVAL takes precedence over it.
	OTELIntervalMS int `env:"OTEL_METRIC_EXPORT_INTERVAL"`

	CommonEndpoint  string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`

	Protocol        Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	MetricsProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"`

	// Insecure disables TLS for gRPC/HTTP connections (plain text)
	Insecure bool `yaml:"insecure" env:"OTEL_EXPORTER_OTLP_INSECURE"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_EBPF_INSECURE_SKIP_VERIFY"`

	Buckets              export.Buckets `yaml:"buckets"`
	HistogramAggregation string         `yaml:"histogram_aggregation" env:"OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION"`

	ReportersCacheLen int `yaml:"reporters_cache_len" env:"OTEL_EBPF_METRICS_REPORT_CACHE_LEN"`

	// SDKLogLevel works independently from the global LogLevel because it prints GBs of logs in Debug mode
	// and the Info messages leak internal details that are not usually valuable for the final user.
	SDKLogLevel string `yaml:"otel_sdk_log_level" env:"OTEL_EBPF_SDK_LOG_LEVEL"`

	// Features of metrics that can be exported. Accepted values: application, network,
	// application_span, application_service_graph, ...
	// envDefault is provided to avoid breaking changes
	// Deprecated: use top-level MetricsConfig.Features instead.
	DeprFeatures export.Features `yaml:"features"`

	// Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql...
	Instrumentations []instrumentations.Instrumentation `yaml:"instrumentations" env:"OTEL_EBPF_METRICS_INSTRUMENTATIONS" envSeparator:","`

	// TTL is the time since a metric was updated for the last time until it is
	// removed from the metrics set.
	TTL time.Duration `yaml:"ttl" env:"OTEL_EBPF_METRICS_TTL"`

	AllowServiceGraphSelfReferences bool `yaml:"allow_service_graph_self_references" env:"OTEL_EBPF_ALLOW_SERVICE_GRAPH_SELF_REFERENCES"`

	// OTLPEndpointProvider allows overriding the OTLP Endpoint. It needs to return an endpoint and
	// a boolean indicating if the endpoint is common for both traces and metrics
	OTLPEndpointProvider func() (string, bool) `yaml:"-" env:"-"`

	// InjectHeaders allows injecting custom headers to the HTTP OTLP exporter
	InjectHeaders func(dst map[string]string) `yaml:"-" env:"-"`

	// ExtraSpanResourceLabels adds extra metadata labels to OTEL span metrics from sources whose availability can't be known
	// beforehand. For example, to add the OTEL deployment.environment resource attribute as a OTEL resource attribute,
	// you should add `deployment.environment`.
	ExtraSpanResourceLabels []string `yaml:"extra_span_resource_attributes" env:"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES" envSeparator:","`
}

func (m MetricsConfig) MarshalYAML() (any, error) {
	omit := map[string]struct{}{
		"endpoint": {},
	}
	return omitFieldsForYAML(m, omit), nil
}

func (m *MetricsConfig) GetProtocol() Protocol {
	// When using a consumer, protocol is not needed
	if m.MetricsConsumer != nil {
		return ProtocolUnset
	}
	if m.MetricsProtocol != "" {
		return m.MetricsProtocol
	}
	if m.Protocol != "" {
		return m.Protocol
	}
	return m.GuessProtocol()
}

func (m *MetricsConfig) GetInterval() time.Duration {
	if m.Interval == 0 {
		return time.Duration(m.OTELIntervalMS) * time.Millisecond
	}
	return m.Interval
}

func (m *MetricsConfig) GuessProtocol() Protocol {
	// If no explicit protocol is set, we guess it from the endpoint port
	// (assuming it uses a standard port or a development-like form like 14317, 24317, 14318...)
	port := extractPortFromEndpoint(m.MetricsEndpoint, m.CommonEndpoint)
	if port != "" {
		if strings.HasSuffix(port, UsualPortGRPC) {
			return ProtocolGRPC
		} else if strings.HasSuffix(port, UsualPortHTTP) {
			return ProtocolHTTPProtobuf
		}
	}
	// Otherwise we return default protocol according to the latest specification:
	// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md?plain=1#L53
	return ProtocolHTTPProtobuf
}

func (m *MetricsConfig) OTLPMetricsEndpoint() (string, bool) {
	if m.OTLPEndpointProvider != nil {
		return m.OTLPEndpointProvider()
	}
	return ResolveOTLPEndpoint(m.MetricsEndpoint, m.CommonEndpoint)
}

// EndpointEnabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint, OTEL metrics endpoint, or a MetricsConsumer is defined.
// If not enabled, this node won't be instantiated
// Reason to disable linting: it requires to be a value despite it is considered a "heavy struct".
// This method is invoked only once during startup time so it doesn't have a noticeable performance impact.
func (m *MetricsConfig) EndpointEnabled() bool {
	if m.MetricsConsumer != nil {
		return true
	}
	ep, _ := m.OTLPMetricsEndpoint()
	return ep != ""
}

func httpMetricEndpointOptions(cfg *MetricsConfig) (OTLPOptions, error) {
	opts := OTLPOptions{Headers: map[string]string{}}
	log := mlog().With("transport", "http")
	murl, isCommon, err := parseMetricsEndpoint(cfg)
	if err != nil {
		return opts, err
	}
	log.Debug("Configuring exporter",
		"protocol", cfg.Protocol, "metricsProtocol", cfg.MetricsProtocol, "endpoint", murl.Host)

	setMetricsProtocol(cfg)
	opts.Endpoint = murl.Host
	// Insecure can be set via config field or inferred from URL scheme (http://)
	if cfg.Insecure || murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "fromConfig", cfg.Insecure, "scheme", murl.Scheme)
		opts.Insecure = true
	}
	// If the value is set from the OTEL_EXPORTER_OTLP_ENDPOINT common property, we need to add /v1/metrics to the path
	// otherwise, we leave the path that is explicitly set by the user
	opts.URLPath = murl.Path
	if isCommon {
		if strings.HasSuffix(opts.URLPath, "/") {
			opts.URLPath += "v1/metrics"
		} else {
			opts.URLPath += "/v1/metrics"
		}
	}
	log.Debug("Specifying path", "path", opts.URLPath)

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = cfg.InsecureSkipVerify
	}

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envMetricsHeaders))

	return opts, nil
}

func grpcMetricEndpointOptions(cfg *MetricsConfig) (OTLPOptions, error) {
	opts := OTLPOptions{Headers: map[string]string{}}
	log := mlog().With("transport", "grpc")

	// Use gRPC-specific parser that accepts host:port format
	endpoint, insecureFromScheme, _, err := parseGRPCMetricsEndpoint(cfg)
	if err != nil {
		return opts, err
	}
	log.Debug("Configuring exporter",
		"protocol", cfg.Protocol, "metricsProtocol", cfg.MetricsProtocol, "endpoint", endpoint)

	setMetricsProtocol(cfg)
	opts.Endpoint = endpoint
	// Insecure can be set via config field or inferred from URL scheme (http://)
	if cfg.Insecure || insecureFromScheme {
		log.Debug("Specifying insecure connection", "fromConfig", cfg.Insecure, "fromScheme", insecureFromScheme)
		opts.Insecure = true
	}
	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envMetricsHeaders))

	return opts, nil
}

// parseMetricsEndpoint parses an HTTP metrics endpoint.
// The HTTP path will be defined from one of the following sources, from highest to lowest priority
// - the result from any overridden OTLP Provider function
// - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
// NOTE: This function is for HTTP endpoints which require a scheme (http:// or https://).
func parseMetricsEndpoint(cfg *MetricsConfig) (*url.URL, bool, error) {
	endpoint, isCommon := cfg.OTLPMetricsEndpoint()

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, isCommon, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}
	if murl.Scheme == "" || murl.Host == "" {
		return nil, isCommon, fmt.Errorf("HTTP URL %q must have a scheme and a host", endpoint)
	}
	return murl, isCommon, nil
}

// parseGRPCMetricsEndpoint parses a gRPC endpoint which can be in either:
// - host:port format (e.g., "otel-collector.svc:4317") - used by gRPC SDK
// - URL format with scheme (e.g., "http://otel-collector.svc:4317") - scheme used for insecure detection
// gRPC endpoints do NOT require a URL scheme - the gRPC SDK expects just host:port.
func parseGRPCMetricsEndpoint(cfg *MetricsConfig) (endpoint string, insecure bool, isCommon bool, err error) {
	ep, isCommon := cfg.OTLPMetricsEndpoint()
	if ep == "" {
		return "", false, isCommon, fmt.Errorf("no metrics endpoint configured")
	}

	// Try parsing as URL first
	murl, parseErr := url.Parse(ep)
	if parseErr == nil && murl.Scheme != "" && murl.Host != "" {
		// Valid URL with scheme - extract host:port and check if insecure
		return murl.Host, murl.Scheme == "http" || murl.Scheme == "unix", isCommon, nil
	}

	// Not a URL with scheme - treat as host:port (standard gRPC format)
	// Validate it looks like host:port
	if !strings.Contains(ep, ":") {
		return "", false, isCommon, fmt.Errorf("gRPC endpoint %q must be in host:port format", ep)
	}

	// For plain host:port, default to secure (TLS) unless insecure_skip_verify is set
	return ep, false, isCommon, nil
}

// HACK: at the time of writing this, the otelpmetrichttp API does not support explicitly
// setting the protocol. They should be properly set via environment variables, but
// if the user supplied the value via configuration file (and not via env vars), we override the environment.
// To be as least intrusive as possible, we will change the variables if strictly needed
// TODO: remove this once otelpmetrichttp.WithProtocol is supported
func setMetricsProtocol(cfg *MetricsConfig) {
	if _, ok := os.LookupEnv(envMetricsProtocol); ok {
		return
	}
	if _, ok := os.LookupEnv(envProtocol); ok {
		return
	}
	if cfg.MetricsProtocol != "" {
		_ = os.Setenv(envMetricsProtocol, string(cfg.MetricsProtocol))
		return
	}
	if cfg.Protocol != "" {
		_ = os.Setenv(envProtocol, string(cfg.Protocol))
		return
	}
	// unset. Guessing it
	_ = os.Setenv(envMetricsProtocol, string(cfg.GuessProtocol()))
}
