// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package snmp implements an SNMP receiver for integrating legacy infrastructure
// (network devices, storage systems, UPS, printers, HVAC, industrial equipment)
// into modern observability stacks.
package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// SNMPVersion represents the SNMP protocol version
type SNMPVersion string

const (
	SNMPv1  SNMPVersion = "v1"
	SNMPv2c SNMPVersion = "v2c"
	SNMPv3  SNMPVersion = "v3"
)

// SecurityLevel represents SNMPv3 security levels
type SecurityLevel string

const (
	NoAuthNoPriv SecurityLevel = "noAuthNoPriv"
	AuthNoPriv   SecurityLevel = "authNoPriv"
	AuthPriv     SecurityLevel = "authPriv"
)

// AuthProtocol represents SNMPv3 authentication protocols
type AuthProtocol string

const (
	AuthMD5    AuthProtocol = "MD5"
	AuthSHA    AuthProtocol = "SHA"
	AuthSHA256 AuthProtocol = "SHA256"
	AuthSHA512 AuthProtocol = "SHA512"
)

// PrivProtocol represents SNMPv3 privacy protocols
type PrivProtocol string

const (
	PrivDES    PrivProtocol = "DES"
	PrivAES    PrivProtocol = "AES"
	PrivAES192 PrivProtocol = "AES192"
	PrivAES256 PrivProtocol = "AES256"
)

// Target represents an SNMP device target configuration
type Target struct {
	Name          string            `mapstructure:"name" yaml:"name"`
	Address       string            `mapstructure:"address" yaml:"address"`
	Version       SNMPVersion       `mapstructure:"version" yaml:"version"`
	Community     string            `mapstructure:"community" yaml:"community"`
	SecurityLevel SecurityLevel     `mapstructure:"security_level" yaml:"security_level"`
	Username      string            `mapstructure:"username" yaml:"username"`
	AuthProtocol  AuthProtocol      `mapstructure:"auth_protocol" yaml:"auth_protocol"`
	AuthPassword  string            `mapstructure:"auth_password" yaml:"auth_password"`
	PrivProtocol  PrivProtocol      `mapstructure:"priv_protocol" yaml:"priv_protocol"`
	PrivPassword  string            `mapstructure:"priv_password" yaml:"priv_password"`
	Interval      time.Duration     `mapstructure:"interval" yaml:"interval"`
	Timeout       time.Duration     `mapstructure:"timeout" yaml:"timeout"`
	Retries       int               `mapstructure:"retries" yaml:"retries"`
	Modules       []string          `mapstructure:"modules" yaml:"modules"`
	Labels        map[string]string `mapstructure:"labels" yaml:"labels"`
}

// V3User represents an SNMPv3 user configuration for trap receiver
type V3User struct {
	Username     string       `mapstructure:"username" yaml:"username"`
	AuthProtocol AuthProtocol `mapstructure:"auth_protocol" yaml:"auth_protocol"`
	AuthPassword string       `mapstructure:"auth_password" yaml:"auth_password"`
	PrivProtocol PrivProtocol `mapstructure:"priv_protocol" yaml:"priv_protocol"`
	PrivPassword string       `mapstructure:"priv_password" yaml:"priv_password"`
}

// TrapReceiverConfig configures the SNMP trap receiver
type TrapReceiverConfig struct {
	Enabled          bool     `mapstructure:"enabled" yaml:"enabled"`
	ListenAddress    string   `mapstructure:"listen_address" yaml:"listen_address"`
	CommunityStrings []string `mapstructure:"community_strings" yaml:"community_strings"`
	V3Users          []V3User `mapstructure:"v3_users" yaml:"v3_users"`
}

// PollingConfig configures SNMP polling behavior
type PollingConfig struct {
	Enabled         bool          `mapstructure:"enabled" yaml:"enabled"`
	DefaultInterval time.Duration `mapstructure:"default_interval" yaml:"default_interval"`
	Timeout         time.Duration `mapstructure:"timeout" yaml:"timeout"`
	Retries         int           `mapstructure:"retries" yaml:"retries"`
	MaxConcurrent   int           `mapstructure:"max_concurrent" yaml:"max_concurrent"`
}

// DiscoveryConfig configures SNMP auto-discovery
type DiscoveryConfig struct {
	Enabled          bool          `mapstructure:"enabled" yaml:"enabled"`
	Networks         []string      `mapstructure:"networks" yaml:"networks"`
	Interval         time.Duration `mapstructure:"interval" yaml:"interval"`
	CommunityStrings []string      `mapstructure:"community_strings" yaml:"community_strings"`
}

// MIBConfig configures MIB loading and resolution
type MIBConfig struct {
	SearchPaths  []string `mapstructure:"search_paths" yaml:"search_paths"`
	LoadStandard bool     `mapstructure:"load_standard" yaml:"load_standard"`
	CustomMIBs   []string `mapstructure:"custom_mibs" yaml:"custom_mibs"`
}

// PrometheusOutputConfig configures Prometheus metrics endpoint
type PrometheusOutputConfig struct {
	Enabled       bool   `mapstructure:"enabled" yaml:"enabled"`
	ListenAddress string `mapstructure:"listen_address" yaml:"listen_address"`
	Path          string `mapstructure:"path" yaml:"path"`
}

// RemoteWriteEndpointConfig configures a single remote write endpoint
type RemoteWriteEndpointConfig struct {
	URL       string            `mapstructure:"url" yaml:"url"`
	Timeout   time.Duration     `mapstructure:"timeout" yaml:"timeout"`
	BatchSize int               `mapstructure:"batch_size" yaml:"batch_size"`
	Headers   map[string]string `mapstructure:"headers" yaml:"headers"`
	BasicAuth *BasicAuthConfig  `mapstructure:"basic_auth" yaml:"basic_auth"`
}

// BasicAuthConfig configures basic authentication
type BasicAuthConfig struct {
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}

// RemoteWriteConfig configures Prometheus remote write output
type RemoteWriteConfig struct {
	Enabled   bool                        `mapstructure:"enabled" yaml:"enabled"`
	Endpoints []RemoteWriteEndpointConfig `mapstructure:"endpoints" yaml:"endpoints"`
}

// OTLPOutputConfig configures OTLP metrics export
type OTLPOutputConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`
	Protocol string `mapstructure:"protocol" yaml:"protocol"` // grpc or http
	Insecure bool   `mapstructure:"insecure" yaml:"insecure"`
}

// OutputConfig configures all output options
type OutputConfig struct {
	Prometheus  PrometheusOutputConfig `mapstructure:"prometheus" yaml:"prometheus"`
	RemoteWrite RemoteWriteConfig      `mapstructure:"remote_write" yaml:"remote_write"`
	OTLP        OTLPOutputConfig       `mapstructure:"otlp" yaml:"otlp"`
}

// Config holds all SNMP receiver configuration
type Config struct {
	Enabled      bool               `mapstructure:"enabled" yaml:"enabled"`
	TrapReceiver TrapReceiverConfig `mapstructure:"trap_receiver" yaml:"trap_receiver"`
	Polling      PollingConfig      `mapstructure:"polling" yaml:"polling"`
	Targets      []Target           `mapstructure:"targets" yaml:"targets"`
	Discovery    DiscoveryConfig    `mapstructure:"discovery" yaml:"discovery"`
	MIBs         MIBConfig          `mapstructure:"mibs" yaml:"mibs"`
	Output       OutputConfig       `mapstructure:"output" yaml:"output"`
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() Config {
	return Config{
		Enabled: true,
		TrapReceiver: TrapReceiverConfig{
			Enabled:          false,
			ListenAddress:    "0.0.0.0:162",
			CommunityStrings: []string{"public"},
		},
		Polling: PollingConfig{
			Enabled:         true,
			DefaultInterval: 60 * time.Second,
			Timeout:         10 * time.Second,
			Retries:         3,
			MaxConcurrent:   100,
		},
		Discovery: DiscoveryConfig{
			Enabled:  false,
			Interval: time.Hour,
		},
		MIBs: MIBConfig{
			SearchPaths:  []string{"/usr/share/snmp/mibs"},
			LoadStandard: true,
		},
		Output: OutputConfig{
			Prometheus: PrometheusOutputConfig{
				Enabled:       true,
				ListenAddress: ":9116",
				Path:          "/metrics",
			},
		},
	}
}

// Receiver is the main SNMP receiver that orchestrates polling, trap reception,
// and metric export
type Receiver struct {
	config       Config
	log          *slog.Logger
	poller       *Poller
	trapReceiver *TrapReceiver
	mibResolver  *MIBResolver
	converter    *MetricConverter
	remoteWriter *RemoteWriteClient
	otlpExporter *OTLPExporter
	promEndpoint *PrometheusEndpoint

	// State management
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
	metrics chan []Metric
}

// NewReceiver creates a new SNMP receiver
func NewReceiver(cfg Config, log *slog.Logger) (*Receiver, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "snmp-receiver")

	r := &Receiver{
		config:  cfg,
		log:     log,
		stopCh:  make(chan struct{}),
		metrics: make(chan []Metric, 1000),
	}

	// Initialize MIB resolver
	var err error
	r.mibResolver, err = NewMIBResolver(cfg.MIBs, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create MIB resolver: %w", err)
	}

	// Initialize metric converter
	r.converter = NewMetricConverter(r.mibResolver, log)

	// Initialize poller if enabled
	if cfg.Polling.Enabled {
		r.poller, err = NewPoller(cfg.Polling, r.mibResolver, r.converter, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create poller: %w", err)
		}
	}

	// Initialize trap receiver if enabled
	if cfg.TrapReceiver.Enabled {
		r.trapReceiver, err = NewTrapReceiver(cfg.TrapReceiver, r.mibResolver, r.converter, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create trap receiver: %w", err)
		}
	}

	// Initialize remote write client if enabled
	if cfg.Output.RemoteWrite.Enabled {
		r.remoteWriter, err = NewRemoteWriteClient(cfg.Output.RemoteWrite, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create remote write client: %w", err)
		}
	}

	// Initialize OTLP exporter if enabled
	if cfg.Output.OTLP.Enabled {
		r.otlpExporter, err = NewOTLPExporter(cfg.Output.OTLP, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
	}

	// Initialize Prometheus endpoint if enabled
	if cfg.Output.Prometheus.Enabled {
		r.promEndpoint, err = NewPrometheusEndpoint(cfg.Output.Prometheus, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create Prometheus endpoint: %w", err)
		}
	}

	return r, nil
}

// Start starts the SNMP receiver and all its components
func (r *Receiver) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return nil
	}

	r.log.Info("starting SNMP receiver")

	// Load MIBs
	if err := r.mibResolver.LoadMIBs(r.config.MIBs.SearchPaths); err != nil {
		r.log.Warn("failed to load some MIBs", "error", err)
	}

	// Start metric distribution goroutine
	r.wg.Add(1)
	go r.distributeMetrics(ctx)

	// Start trap receiver
	if r.trapReceiver != nil {
		if err := r.trapReceiver.Start(ctx); err != nil {
			return fmt.Errorf("failed to start trap receiver: %w", err)
		}
		r.log.Info("trap receiver started", "address", r.config.TrapReceiver.ListenAddress)
	}

	// Start pollers for each target
	if r.poller != nil {
		for _, target := range r.config.Targets {
			r.wg.Add(1)
			go func(t Target) {
				defer r.wg.Done()
				r.pollTarget(ctx, t)
			}(target)
		}
		r.log.Info("started polling targets", "count", len(r.config.Targets))
	}

	// Start remote write client
	if r.remoteWriter != nil {
		if err := r.remoteWriter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start remote write client: %w", err)
		}
	}

	// Start OTLP exporter
	if r.otlpExporter != nil {
		if err := r.otlpExporter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start OTLP exporter: %w", err)
		}
	}

	// Start Prometheus endpoint
	if r.promEndpoint != nil {
		if err := r.promEndpoint.Start(ctx); err != nil {
			return fmt.Errorf("failed to start Prometheus endpoint: %w", err)
		}
	}

	r.running = true
	r.log.Info("SNMP receiver started successfully")
	return nil
}

// Stop stops the SNMP receiver and all its components
func (r *Receiver) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	r.log.Info("stopping SNMP receiver")

	close(r.stopCh)

	// Stop trap receiver
	if r.trapReceiver != nil {
		if err := r.trapReceiver.Stop(ctx); err != nil {
			r.log.Warn("error stopping trap receiver", "error", err)
		}
	}

	// Stop remote write client
	if r.remoteWriter != nil {
		if err := r.remoteWriter.Stop(ctx); err != nil {
			r.log.Warn("error stopping remote write client", "error", err)
		}
	}

	// Stop OTLP exporter
	if r.otlpExporter != nil {
		if err := r.otlpExporter.Stop(ctx); err != nil {
			r.log.Warn("error stopping OTLP exporter", "error", err)
		}
	}

	// Stop Prometheus endpoint
	if r.promEndpoint != nil {
		if err := r.promEndpoint.Stop(ctx); err != nil {
			r.log.Warn("error stopping Prometheus endpoint", "error", err)
		}
	}

	// Wait for goroutines to finish
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		r.log.Warn("context cancelled while waiting for goroutines")
	}

	close(r.metrics)

	r.running = false
	r.log.Info("SNMP receiver stopped")
	return nil
}

// pollTarget continuously polls a single target at its configured interval
func (r *Receiver) pollTarget(ctx context.Context, target Target) {
	interval := target.Interval
	if interval == 0 {
		interval = r.config.Polling.DefaultInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	r.log.Info("starting target polling", "target", target.Name, "interval", interval)

	// Initial poll
	r.doPoll(ctx, target)

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.doPoll(ctx, target)
		}
	}
}

// doPoll performs a single poll of a target
func (r *Receiver) doPoll(ctx context.Context, target Target) {
	metrics, err := r.poller.Poll(ctx, target)
	if err != nil {
		r.log.Error("failed to poll target", "target", target.Name, "error", err)
		return
	}

	// Add target labels to metrics
	for i := range metrics {
		if metrics[i].Labels == nil {
			metrics[i].Labels = make(map[string]string)
		}
		metrics[i].Labels["snmp_target"] = target.Name
		for k, v := range target.Labels {
			metrics[i].Labels[k] = v
		}
	}

	// Send metrics to distribution channel
	select {
	case r.metrics <- metrics:
	default:
		r.log.Warn("metrics channel full, dropping metrics", "target", target.Name, "count", len(metrics))
	}
}

// distributeMetrics sends metrics to all configured outputs
func (r *Receiver) distributeMetrics(ctx context.Context) {
	defer r.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case metrics, ok := <-r.metrics:
			if !ok {
				return
			}

			// Send to remote write
			if r.remoteWriter != nil {
				if err := r.remoteWriter.Send(ctx, metrics); err != nil {
					r.log.Error("failed to send metrics via remote write", "error", err)
				}
			}

			// Send to OTLP
			if r.otlpExporter != nil {
				if err := r.otlpExporter.Export(ctx, metrics); err != nil {
					r.log.Error("failed to export metrics via OTLP", "error", err)
				}
			}

			// Update Prometheus endpoint
			if r.promEndpoint != nil {
				r.promEndpoint.Update(metrics)
			}
		}
	}
}

// AddTarget dynamically adds a new target for polling
func (r *Receiver) AddTarget(target Target) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.config.Targets = append(r.config.Targets, target)

	if r.running && r.poller != nil {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			ctx := context.Background()
			r.pollTarget(ctx, target)
		}()
	}
}

// RemoveTarget removes a target by name
func (r *Receiver) RemoveTarget(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, t := range r.config.Targets {
		if t.Name == name {
			r.config.Targets = append(r.config.Targets[:i], r.config.Targets[i+1:]...)
			return true
		}
	}
	return false
}

// Targets returns the current list of targets
func (r *Receiver) Targets() []Target {
	r.mu.RLock()
	defer r.mu.RUnlock()

	targets := make([]Target, len(r.config.Targets))
	copy(targets, r.config.Targets)
	return targets
}
