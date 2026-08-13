// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package paloalto provides Palo Alto PAN-OS integration for network observability.
package paloalto

import (
	"context"
	"crypto/tls"
	"encoding/xml"
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

// Config holds Palo Alto collector configuration.
type Config struct {
	Name            string            `mapstructure:"name" yaml:"name"`
	BaseURL         string            `mapstructure:"base_url" yaml:"base_url"`
	APIKey          string            `mapstructure:"api_key" yaml:"api_key"`
	Username        string            `mapstructure:"username" yaml:"username"`
	Password        string            `mapstructure:"password" yaml:"password"`
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

// Collector collects metrics from Palo Alto PAN-OS devices.
type Collector struct {
	config  Config
	client  *http.Client
	log     *slog.Logger
	apiKey  string
	mu      sync.RWMutex
	running bool
}

// NewCollector creates a new Palo Alto collector.
func NewCollector(cfg Config, log *slog.Logger) (*Collector, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base_url is required")
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
		log:    log.With("component", "paloalto", "instance", cfg.Name),
		apiKey: cfg.APIKey,
	}, nil
}

// Name returns collector name.
func (c *Collector) Name() string {
	return fmt.Sprintf("paloalto-%s", c.config.Name)
}

// Start starts the collector.
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return nil
	}

	if c.apiKey == "" {
		key, err := c.generateAPIKey(ctx)
		if err != nil {
			return fmt.Errorf("generate api key: %w", err)
		}
		c.apiKey = key
	}

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
			data, err := c.opRequest(ctx, "<show><system><info></info></system></show>")
			if err != nil {
				c.log.Warn("system info request failed", "error", err)
				continue
			}
			metrics, err := parseSystemInfo(data, c.baseLabels(), now)
			if err != nil {
				c.log.Warn("system info parse failed", "error", err)
				continue
			}
			out = append(out, metrics...)
		case "interfaces":
			data, err := c.opRequest(ctx, "<show><interface>all</interface></show>")
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
		"vendor": "paloalto",
		"type":   "firewall",
		"device": c.config.Name,
	}
	for k, v := range c.config.Labels {
		labels[k] = v
	}
	return labels
}

func (c *Collector) generateAPIKey(ctx context.Context) (string, error) {
	if c.config.Username == "" || c.config.Password == "" {
		return "", fmt.Errorf("api_key or username/password is required")
	}

	u, err := url.Parse(strings.TrimRight(c.config.BaseURL, "/") + "/api/")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("type", "keygen")
	q.Set("user", c.config.Username)
	q.Set("password", c.config.Password)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("keygen failed with status %d", resp.StatusCode)
	}

	type keygenResponse struct {
		Result struct {
			Key string `xml:"key"`
		} `xml:"result"`
	}
	var out keygenResponse
	if err := xml.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Result.Key == "" {
		return "", fmt.Errorf("empty key in keygen response")
	}
	return out.Result.Key, nil
}

func (c *Collector) opRequest(ctx context.Context, cmd string) ([]byte, error) {
	c.mu.RLock()
	key := c.apiKey
	c.mu.RUnlock()

	u, err := url.Parse(strings.TrimRight(c.config.BaseURL, "/") + "/api/")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("type", "op")
	q.Set("cmd", cmd)
	q.Set("key", key)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("op request failed with status %d", resp.StatusCode)
	}
	return body, nil
}

func parseSystemInfo(data []byte, base map[string]string, timestamp time.Time) ([]*types.NetworkMetric, error) {
	type systemInfoResponse struct {
		Result struct {
			System struct {
				Hostname string `xml:"hostname"`
				Model    string `xml:"model"`
				Serial   string `xml:"serial"`
				SwVer    string `xml:"sw-version"`
				Uptime   string `xml:"uptime"`
			} `xml:"system"`
		} `xml:"result"`
	}
	var out systemInfoResponse
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	labels := copyLabels(base)
	if out.Result.System.Hostname != "" {
		labels["hostname"] = out.Result.System.Hostname
	}
	if out.Result.System.Model != "" {
		labels["model"] = out.Result.System.Model
	}
	if out.Result.System.Serial != "" {
		labels["serial"] = out.Result.System.Serial
	}
	if out.Result.System.SwVer != "" {
		labels["sw_version"] = out.Result.System.SwVer
	}

	metrics := []*types.NetworkMetric{
		types.NewMetricAt("netinfra_paloalto_device_info", 1, labels, timestamp),
	}

	if secs := parseUptimeSeconds(out.Result.System.Uptime); secs > 0 {
		metrics = append(metrics, types.NewMetricAt("netinfra_paloalto_uptime_seconds", secs, copyLabels(labels), timestamp))
	}
	return metrics, nil
}

func parseInterfaces(data []byte, base map[string]string, timestamp time.Time) ([]*types.NetworkMetric, error) {
	type ifaceEntry struct {
		Name  string `xml:"name,attr"`
		State string `xml:"state"`
	}
	type interfaceResponse struct {
		Result struct {
			IFNet struct {
				Entries []ifaceEntry `xml:"entry"`
			} `xml:"ifnet"`
		} `xml:"result"`
	}
	var out interfaceResponse
	if err := xml.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	metrics := make([]*types.NetworkMetric, 0, len(out.Result.IFNet.Entries))
	for _, e := range out.Result.IFNet.Entries {
		labels := copyLabels(base)
		labels["interface"] = e.Name
		state := strings.ToLower(strings.TrimSpace(e.State))
		value := 0.0
		if state == "up" {
			value = 1.0
		}
		metrics = append(metrics, types.NewMetricAt("netinfra_paloalto_interface_up", value, labels, timestamp))
	}
	return metrics, nil
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func parseUptimeSeconds(uptime string) float64 {
	parts := strings.Fields(strings.TrimSpace(uptime))
	if len(parts) < 2 {
		return 0
	}
	// Example fixture: "5 days, 10:11:12"
	days := 0
	if strings.HasPrefix(parts[1], "day") || strings.HasPrefix(parts[1], "days") {
		if d, err := strconv.Atoi(strings.TrimSuffix(parts[0], ",")); err == nil {
			days = d
		}
	}
	timePart := parts[len(parts)-1]
	hms := strings.Split(timePart, ":")
	if len(hms) != 3 {
		return float64(days * 86400)
	}
	h, err := strconv.Atoi(hms[0])
	if err != nil {
		return float64(days * 86400)
	}
	m, err := strconv.Atoi(hms[1])
	if err != nil {
		return float64(days*86400 + h*3600)
	}
	s, err := strconv.Atoi(hms[2])
	if err != nil {
		return float64(days*86400 + h*3600 + m*60)
	}
	return float64(days*86400 + h*3600 + m*60 + s)
}
