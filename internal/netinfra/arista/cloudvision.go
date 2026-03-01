// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package arista provides Arista CloudVision integration for network observability.
package arista

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/netinfra/types"
)

// CloudVisionCollector collects metrics from Arista CloudVision Platform
type CloudVisionCollector struct {
	config     Config
	auth       *Authenticator
	client     *http.Client
	log        *slog.Logger
	inventory  *InventoryCollector
	interfaces *InterfaceCollector
	bgp        *BGPCollector
	system     *SystemCollector
	gnmi       *GNMIClient
	events     *EventSubscriber
	mu         sync.RWMutex
	running    bool
}

// Config holds CloudVision collector configuration
type Config struct {
	// Name is a unique identifier for this CVP instance
	Name string `mapstructure:"name" yaml:"name"`
	// CVPURL is the CloudVision Portal URL
	CVPURL string `mapstructure:"cvp_url" yaml:"cvp_url"`
	// Username for CVP authentication (on-prem)
	Username string `mapstructure:"username" yaml:"username"`
	// Password for CVP authentication (on-prem)
	Password string `mapstructure:"password" yaml:"password"`
	// Token for CVaaS service account authentication
	Token string `mapstructure:"token" yaml:"token"`
	// VerifySSL controls TLS certificate verification
	VerifySSL bool `mapstructure:"verify_ssl" yaml:"verify_ssl"`
	// Timeout for API requests
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`
	// Collect specifies which metrics to collect
	Collect []string `mapstructure:"collect" yaml:"collect"`
	// Labels to add to all metrics
	Labels map[string]string `mapstructure:"labels" yaml:"labels"`
	// CollectInterval is how often to collect metrics
	CollectInterval time.Duration `mapstructure:"collect_interval" yaml:"collect_interval"`
	// GNMI configuration for streaming telemetry
	GNMI GNMIConfig `mapstructure:"gnmi" yaml:"gnmi"`
}

// GNMIConfig holds gNMI streaming configuration
type GNMIConfig struct {
	// Enabled controls whether gNMI streaming is active
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// Address is the gNMI server address (host:port)
	Address string `mapstructure:"address" yaml:"address"`
	// SubscribePaths are the gNMI paths to subscribe to
	SubscribePaths []string `mapstructure:"subscribe_paths" yaml:"subscribe_paths"`
	// SampleInterval for streaming subscriptions
	SampleInterval time.Duration `mapstructure:"sample_interval" yaml:"sample_interval"`
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() Config {
	return Config{
		VerifySSL:       true,
		Timeout:         30 * time.Second,
		CollectInterval: 30 * time.Second,
		Collect: []string{
			"inventory",
			"interfaces",
			"bgp",
			"system",
		},
		Labels: make(map[string]string),
		GNMI: GNMIConfig{
			Enabled:        false,
			SampleInterval: 10 * time.Second,
			SubscribePaths: []string{
				"/interfaces/interface/state/counters",
				"/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state",
			},
		},
	}
}

// NewCloudVisionCollector creates a new CloudVision collector
func NewCloudVisionCollector(cfg Config, log *slog.Logger) (*CloudVisionCollector, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "cloudvision", "instance", cfg.Name)

	if cfg.CVPURL == "" {
		return nil, fmt.Errorf("cvp_url is required")
	}

	// Create HTTP client with TLS config
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.VerifySSL,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	c := &CloudVisionCollector{
		config: cfg,
		client: client,
		log:    log,
	}

	// Initialize authenticator
	c.auth = NewAuthenticator(cfg, client, log)

	// Initialize sub-collectors
	c.inventory = NewInventoryCollector(c)
	c.interfaces = NewInterfaceCollector(c)
	c.bgp = NewBGPCollector(c)
	c.system = NewSystemCollector(c)
	c.events = NewEventSubscriber(c)

	// Initialize gNMI if enabled
	if cfg.GNMI.Enabled {
		gnmiClient, err := NewGNMIClient(cfg, log)
		if err != nil {
			log.Warn("failed to create gNMI client", "error", err)
		} else {
			c.gnmi = gnmiClient
		}
	}

	return c, nil
}

// Name returns the collector name
func (c *CloudVisionCollector) Name() string {
	return fmt.Sprintf("cloudvision-%s", c.config.Name)
}

// Collect gathers metrics from CloudVision
func (c *CloudVisionCollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	c.mu.RLock()
	running := c.running
	c.mu.RUnlock()

	if !running {
		return nil, fmt.Errorf("collector not started")
	}

	// Ensure we have a valid token
	if err := c.auth.EnsureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	var allMetrics []*types.NetworkMetric

	for _, collectType := range c.config.Collect {
		var metrics []*types.NetworkMetric
		var err error

		switch collectType {
		case "inventory":
			metrics, err = c.inventory.Collect(ctx)
		case "interfaces":
			metrics, err = c.interfaces.Collect(ctx)
		case "bgp":
			metrics, err = c.bgp.Collect(ctx)
		case "system":
			metrics, err = c.system.Collect(ctx)
		default:
			c.log.Warn("unknown collect type", "type", collectType)
			continue
		}

		if err != nil {
			c.log.Warn("failed to collect metrics", "type", collectType, "error", err)
			continue
		}

		allMetrics = append(allMetrics, metrics...)
	}

	return allMetrics, nil
}

// Start starts the collector
func (c *CloudVisionCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.log.Info("starting CloudVision collector", "url", c.config.CVPURL)

	// Authenticate
	if err := c.auth.Authenticate(ctx); err != nil {
		return fmt.Errorf("initial authentication failed: %w", err)
	}

	// Start gNMI if enabled
	if c.gnmi != nil {
		if err := c.gnmi.Start(ctx); err != nil {
			c.log.Warn("failed to start gNMI client", "error", err)
		}
	}

	// Start event subscriber
	if err := c.events.Start(ctx); err != nil {
		c.log.Warn("failed to start event subscriber", "error", err)
	}

	c.running = true
	return nil
}

// Close stops the collector and releases resources
func (c *CloudVisionCollector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.log.Info("stopping CloudVision collector")

	// Stop gNMI
	if c.gnmi != nil {
		c.gnmi.Stop()
	}

	// Stop event subscriber
	c.events.Stop()

	c.running = false
	return nil
}

// GetClient returns the HTTP client
func (c *CloudVisionCollector) GetClient() *http.Client {
	return c.client
}

// GetToken returns the current authentication token
func (c *CloudVisionCollector) GetToken() string {
	return c.auth.GetToken()
}

// GetBaseURL returns the CVP base URL
func (c *CloudVisionCollector) GetBaseURL() string {
	return c.config.CVPURL
}

// BaseLabels returns the base labels for all metrics
func (c *CloudVisionCollector) BaseLabels() map[string]string {
	labels := map[string]string{
		"cvp":    c.config.Name,
		"vendor": "arista",
		"type":   "cloudvision",
	}
	for k, v := range c.config.Labels {
		labels[k] = v
	}
	return labels
}
