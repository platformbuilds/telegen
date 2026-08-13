// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package fortigate provides FortiGate FortiOS integration for network observability.
package fortigate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/netinfra/types"
)

// Config holds FortiGate collector configuration.
type Config struct {
	Name            string            `mapstructure:"name" yaml:"name"`
	BaseURL         string            `mapstructure:"base_url" yaml:"base_url"`
	Token           string            `mapstructure:"token" yaml:"token"`
	VerifySSL       bool              `mapstructure:"verify_ssl" yaml:"verify_ssl"`
	Timeout         time.Duration     `mapstructure:"timeout" yaml:"timeout"`
	Collect         []string          `mapstructure:"collect" yaml:"collect"`
	Labels          map[string]string `mapstructure:"labels" yaml:"labels"`
	CollectInterval time.Duration     `mapstructure:"collect_interval" yaml:"collect_interval"`
}

// DefaultConfig returns sensible default configuration.
func DefaultConfig() Config {
	return Config{
		VerifySSL:       true,
		Timeout:         30 * time.Second,
		CollectInterval: 30 * time.Second,
		Collect:         []string{"system", "interfaces"},
		Labels:          make(map[string]string),
	}
}

// Collector collects metrics from FortiGate devices.
type Collector struct {
	config  Config
	client  *http.Client
	log     *slog.Logger
	mu      sync.RWMutex
	running bool
}

// NewCollector creates a new FortiGate collector.
func NewCollector(cfg Config, log *slog.Logger) (*Collector, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base_url is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("token is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if len(cfg.Collect) == 0 {
		cfg.Collect = []string{"system", "interfaces"}
	}
	if cfg.Labels == nil {
		cfg.Labels = make(map[string]string)
	}
	if log == nil {
		log = slog.Default()
	}

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

	return &Collector{
		config: cfg,
		client: client,
		log:    log.With("component", "fortigate", "instance", cfg.Name),
	}, nil
}

// Name returns collector name.
func (c *Collector) Name() string {
	return fmt.Sprintf("fortigate-%s", c.config.Name)
}

// Start starts the collector.
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = ctx
	c.running = true
	return nil
}

// Close stops the collector.
func (c *Collector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	return nil
}

// Collect gathers metrics.
func (c *Collector) Collect(ctx context.Context) ([]*types.NetworkMetric, error) {
	c.mu.RLock()
	running := c.running
	c.mu.RUnlock()
	if !running {
		return nil, fmt.Errorf("collector not started")
	}

	// Hoist per-cycle instant once for all metrics
	now := time.Now().UTC()

	var out []*types.NetworkMetric
	for _, item := range c.config.Collect {
		switch item {
		case "system":
			data, err := c.apiGET(ctx, "/api/v2/monitor/system/status")
			if err != nil {
				c.log.Warn("system status request failed", "error", err)
				continue
			}
			metrics, err := parseSystemStatus(data, c.baseLabels(), now)
			if err != nil {
				c.log.Warn("system status parse failed", "error", err)
				continue
			}
			out = append(out, metrics...)
		case "interfaces":
			data, err := c.apiGET(ctx, "/api/v2/monitor/system/interface")
			if err != nil {
				c.log.Warn("interface request failed", "error", err)
				continue
			}
			metrics, err := parseInterfaces(data, c.baseLabels(), now)
			if err != nil {
				c.log.Warn("interface parse failed", "error", err)
				continue
			}
			out = append(out, metrics...)
		default:
			c.log.Warn("unknown collect type", "type", item)
		}
	}
	return out, nil
}

func (c *Collector) baseLabels() map[string]string {
	labels := map[string]string{
		"vendor": "fortinet",
		"type":   "firewall",
		"device": c.config.Name,
	}
	for k, v := range c.config.Labels {
		labels[k] = v
	}
	return labels
}

func (c *Collector) apiGET(ctx context.Context, path string) ([]byte, error) {
	base := strings.TrimRight(c.config.BaseURL, "/")
	u, err := url.Parse(base + path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("api request failed with status %d", resp.StatusCode)
	}
	return body, nil
}

func parseSystemStatus(data []byte, base map[string]string, timestamp time.Time) ([]*types.NetworkMetric, error) {
	type resp struct {
		Results struct {
			Hostname string      `json:"hostname"`
			Version  string      `json:"version"`
			Serial   string      `json:"serial"`
			Model    string      `json:"model"`
			Uptime   interface{} `json:"uptime"`
		} `json:"results"`
	}
	var out resp
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	labels := copyLabels(base)
	if out.Results.Hostname != "" {
		labels["hostname"] = out.Results.Hostname
	}
	if out.Results.Version != "" {
		labels["version"] = out.Results.Version
	}
	if out.Results.Serial != "" {
		labels["serial"] = out.Results.Serial
	}
	if out.Results.Model != "" {
		labels["model"] = out.Results.Model
	}

	metrics := []*types.NetworkMetric{
		types.NewMetricAt("netinfra_fortigate_device_info", 1, labels, timestamp),
	}

	if secs := parseUptime(out.Results.Uptime); secs > 0 {
		metrics = append(metrics, types.NewMetricAt("netinfra_fortigate_uptime_seconds", secs, copyLabels(labels), timestamp))
	}
	return metrics, nil
}

func parseInterfaces(data []byte, base map[string]string, timestamp time.Time) ([]*types.NetworkMetric, error) {
	type iface struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	type resp struct {
		Results []iface `json:"results"`
	}
	var out resp
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	metrics := make([]*types.NetworkMetric, 0, len(out.Results))
	for _, inf := range out.Results {
		labels := copyLabels(base)
		labels["interface"] = inf.Name
		v := 0.0
		if strings.EqualFold(strings.TrimSpace(inf.Status), "up") {
			v = 1.0
		}
		metrics = append(metrics, types.NewMetricAt("netinfra_fortigate_interface_up", v, labels, timestamp))
	}
	return metrics, nil
}

func parseUptime(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
