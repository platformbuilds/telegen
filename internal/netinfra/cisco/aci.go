// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package cisco provides Cisco ACI integration for network observability.
package cisco

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/netinfra/types"
)

// ACICollector collects metrics from Cisco ACI fabric
type ACICollector struct {
	config     Config
	auth       *Authenticator
	client     *http.Client
	log        *slog.Logger
	nodes      *NodeCollector
	tenant     *TenantCollector
	interfaces *InterfaceCollector
	health     *HealthCollector
	faults     *FaultCollector
	contracts  *ContractCollector
	mu         sync.RWMutex
	running    bool
}

// Config holds Cisco ACI collector configuration
type Config struct {
	// Name is a unique identifier for this ACI fabric
	Name string `mapstructure:"name" yaml:"name"`
	// APICURL is the APIC controller URL
	APICURL string `mapstructure:"apic_url" yaml:"apic_url"`
	// Username for APIC authentication
	Username string `mapstructure:"username" yaml:"username"`
	// Password for APIC authentication
	Password string `mapstructure:"password" yaml:"password"`
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
	// Domain for authentication (optional)
	Domain string `mapstructure:"domain" yaml:"domain"`
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() Config {
	return Config{
		VerifySSL:       true,
		Timeout:         30 * time.Second,
		CollectInterval: 30 * time.Second,
		Collect: []string{
			"fabric_health",
			"node_health",
			"tenant_health",
			"epg_health",
			"interface_stats",
		},
		Labels: make(map[string]string),
	}
}

// NewACICollector creates a new ACI collector
func NewACICollector(cfg Config, log *slog.Logger) (*ACICollector, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "aci", "fabric", cfg.Name)

	if cfg.APICURL == "" {
		return nil, fmt.Errorf("apic_url is required")
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

	c := &ACICollector{
		config: cfg,
		client: client,
		log:    log,
	}

	// Initialize authenticator
	c.auth = NewAuthenticator(cfg, client, log)

	// Initialize sub-collectors
	c.nodes = NewNodeCollector(c)
	c.tenant = NewTenantCollector(c)
	c.interfaces = NewInterfaceCollector(c)
	c.health = NewHealthCollector(c)
	c.faults = NewFaultCollector(c)
	c.contracts = NewContractCollector(c)

	return c, nil
}

// Name returns the collector name
func (c *ACICollector) Name() string {
	return fmt.Sprintf("aci-%s", c.config.Name)
}

// Collect gathers metrics from ACI
func (c *ACICollector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
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
		case "fabric_health":
			metrics, err = c.health.CollectFabricHealth(ctx)
		case "node_health":
			metrics, err = c.nodes.Collect(ctx)
		case "tenant_health":
			metrics, err = c.tenant.CollectTenantHealth(ctx)
		case "epg_health":
			metrics, err = c.tenant.CollectEPGHealth(ctx)
		case "interface_stats":
			metrics, err = c.interfaces.Collect(ctx)
		case "faults":
			metrics, err = c.faults.Collect(ctx)
		case "contracts":
			metrics, err = c.contracts.Collect(ctx)
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
func (c *ACICollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.log.Info("starting ACI collector", "url", c.config.APICURL)

	// Authenticate
	if err := c.auth.Authenticate(ctx); err != nil {
		return fmt.Errorf("initial authentication failed: %w", err)
	}

	c.running = true
	return nil
}

// Close stops the collector and releases resources
func (c *ACICollector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.log.Info("stopping ACI collector")
	c.running = false

	return nil
}

// GetClient returns the HTTP client
func (c *ACICollector) GetClient() *http.Client {
	return c.client
}

// GetToken returns the current authentication token
func (c *ACICollector) GetToken() string {
	return c.auth.GetToken()
}

// GetBaseURL returns the APIC base URL
func (c *ACICollector) GetBaseURL() string {
	return c.config.APICURL
}

// BaseLabels returns the base labels for all metrics
func (c *ACICollector) BaseLabels() map[string]string {
	labels := map[string]string{
		"apic":   c.config.Name,
		"vendor": "cisco",
		"type":   "aci",
	}
	for k, v := range c.config.Labels {
		labels[k] = v
	}
	return labels
}
