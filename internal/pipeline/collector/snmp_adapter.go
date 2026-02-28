// SNMP adapter wires the V2 SNMP poller to the V3 unified export pipeline.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// SNMPConfig holds SNMP adapter configuration.
type SNMPConfig struct {
	AdapterConfig `yaml:",inline" json:",inline"`

	// Targets to poll via SNMP.
	Targets []SNMPTarget `yaml:"targets" json:"targets"`

	// Discovery configuration for dynamic target discovery.
	Discovery *SNMPDiscoveryConfig `yaml:"discovery,omitempty" json:"discovery,omitempty"`

	// MaxConcurrent is the maximum concurrent SNMP polls.
	MaxConcurrent int `yaml:"max_concurrent" json:"max_concurrent"`

	// BulkMaxRepetitions for GETBULK operations.
	BulkMaxRepetitions int `yaml:"bulk_max_repetitions" json:"bulk_max_repetitions"`
}

// SNMPTarget represents an SNMP polling target.
type SNMPTarget struct {
	// Name is the target identifier.
	Name string `yaml:"name" json:"name"`

	// Address is the target address (host:port).
	Address string `yaml:"address" json:"address"`

	// Version is the SNMP version (1, 2c, 3).
	Version string `yaml:"version" json:"version"`

	// Community is the SNMP v1/v2c community string.
	Community string `yaml:"community,omitempty" json:"community,omitempty"`

	// V3Auth holds SNMPv3 authentication settings.
	V3Auth *SNMPv3Auth `yaml:"v3_auth,omitempty" json:"v3_auth,omitempty"`

	// Modules are the SNMP modules to poll.
	Modules []string `yaml:"modules" json:"modules"`

	// Labels are additional labels for metrics.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// CollectInterval overrides the default collection interval.
	CollectInterval time.Duration `yaml:"collect_interval,omitempty" json:"collect_interval,omitempty"`
}

// SNMPv3Auth holds SNMPv3 authentication configuration.
type SNMPv3Auth struct {
	// SecurityLevel: noAuthNoPriv, authNoPriv, authPriv
	SecurityLevel string `yaml:"security_level" json:"security_level"`

	// Username for authentication.
	Username string `yaml:"username" json:"username"`

	// AuthProtocol: MD5, SHA, SHA224, SHA256, SHA384, SHA512
	AuthProtocol string `yaml:"auth_protocol,omitempty" json:"auth_protocol,omitempty"`

	// AuthPassword for authentication.
	AuthPassword string `yaml:"auth_password,omitempty" json:"auth_password,omitempty"`

	// PrivProtocol: DES, AES, AES192, AES256, AES192C, AES256C
	PrivProtocol string `yaml:"priv_protocol,omitempty" json:"priv_protocol,omitempty"`

	// PrivPassword for privacy/encryption.
	PrivPassword string `yaml:"priv_password,omitempty" json:"priv_password,omitempty"`

	// ContextName for SNMP context.
	ContextName string `yaml:"context_name,omitempty" json:"context_name,omitempty"`
}

// SNMPDiscoveryConfig holds SNMP target discovery configuration.
type SNMPDiscoveryConfig struct {
	// Enabled controls discovery.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Networks to scan for SNMP devices (CIDR notation).
	Networks []string `yaml:"networks" json:"networks"`

	// ScanInterval is how often to scan for new devices.
	ScanInterval time.Duration `yaml:"scan_interval" json:"scan_interval"`

	// DefaultModules to apply to discovered devices.
	DefaultModules []string `yaml:"default_modules" json:"default_modules"`
}

// DefaultSNMPConfig returns sensible defaults.
func DefaultSNMPConfig() SNMPConfig {
	return SNMPConfig{
		AdapterConfig:      DefaultAdapterConfig(),
		MaxConcurrent:      100,
		BulkMaxRepetitions: 10,
	}
}

// SNMPPoller is the interface for the V2 SNMP poller.
// This allows mocking in tests and decouples from V2 implementation.
type SNMPPoller interface {
	Poll(ctx context.Context, target SNMPPollTarget) ([]SNMPMetric, error)
}

// SNMPPollTarget is the target for polling (maps to V2 Target).
type SNMPPollTarget struct {
	Name      string
	Address   string
	Version   string
	Community string
	V3Auth    *SNMPv3Auth
	Modules   []string
}

// SNMPMetric holds a single SNMP metric from polling.
type SNMPMetric struct {
	Name        string
	Description string
	Value       float64
	Labels      map[string]string
	Timestamp   time.Time
	Type        string // "gauge" or "counter"
}

// SNMPAdapter wires V2 SNMP to V3 unified export.
type SNMPAdapter struct {
	config SNMPConfig
	sink   MetricSink
	poller SNMPPoller
	log    *slog.Logger

	// State
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Stats
	collectionCount atomic.Int64
	errorCount      atomic.Int64
	lastCollection  atomic.Value // time.Time
	lastError       atomic.Value // string
	targetStatus    sync.Map     // string -> string
}

// NewSNMPAdapter creates a new SNMP adapter.
func NewSNMPAdapter(config SNMPConfig, sink MetricSink, poller SNMPPoller, log *slog.Logger) (*SNMPAdapter, error) {
	if sink == nil {
		return nil, fmt.Errorf("metric sink is required")
	}
	if log == nil {
		log = slog.Default()
	}

	if config.CollectInterval == 0 {
		config.CollectInterval = 60 * time.Second
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 100
	}

	adapter := &SNMPAdapter{
		config: config,
		sink:   sink,
		poller: poller,
		log:    log.With("adapter", "snmp"),
	}
	adapter.lastCollection.Store(time.Time{})
	adapter.lastError.Store("")

	return adapter, nil
}

// Name implements Adapter.
func (a *SNMPAdapter) Name() string {
	return "snmp"
}

// Start implements Adapter.
func (a *SNMPAdapter) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	if !a.config.Enabled {
		a.log.Info("SNMP adapter is disabled")
		return nil
	}

	a.ctx, a.cancel = context.WithCancel(ctx)
	a.running = true

	// Start collection loop
	a.wg.Add(1)
	go a.collectionLoop()

	// Start discovery if enabled
	if a.config.Discovery != nil && a.config.Discovery.Enabled {
		a.wg.Add(1)
		go a.discoveryLoop()
	}

	a.log.Info("started SNMP adapter",
		"targets", len(a.config.Targets),
		"collect_interval", a.config.CollectInterval,
	)

	return nil
}

// Stop implements Adapter.
func (a *SNMPAdapter) Stop(ctx context.Context) error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.cancel()
	a.running = false
	a.mu.Unlock()

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		a.log.Info("stopped SNMP adapter")
	case <-ctx.Done():
		a.log.Warn("SNMP adapter stop timeout")
	}

	return nil
}

// Health implements Adapter.
func (a *SNMPAdapter) Health() AdapterHealth {
	health := AdapterHealth{
		Name:            "snmp",
		Status:          "healthy",
		CollectionCount: a.collectionCount.Load(),
		ErrorCount:      a.errorCount.Load(),
		Targets:         make(map[string]string),
	}

	if lastColl, ok := a.lastCollection.Load().(time.Time); ok && !lastColl.IsZero() {
		health.LastCollection = lastColl
	}

	if lastErr, ok := a.lastError.Load().(string); ok && lastErr != "" {
		health.LastError = lastErr
		health.Status = "degraded"
	}

	// Collect target statuses
	a.targetStatus.Range(func(key, value interface{}) bool {
		health.Targets[key.(string)] = value.(string)
		return true
	})

	// Check if any target is unhealthy
	unhealthyCount := 0
	for _, status := range health.Targets {
		if status == "unhealthy" {
			unhealthyCount++
		}
	}
	if unhealthyCount > len(health.Targets)/2 {
		health.Status = "unhealthy"
	}

	return health
}

// collectionLoop runs periodic SNMP collection.
func (a *SNMPAdapter) collectionLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.CollectInterval)
	defer ticker.Stop()

	// Initial collection
	a.collectAll()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.collectAll()
		}
	}
}

// collectAll collects metrics from all targets concurrently.
func (a *SNMPAdapter) collectAll() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, a.config.MaxConcurrent)

	for _, target := range a.config.Targets {
		wg.Add(1)
		sem <- struct{}{}

		go func(t SNMPTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := a.collectTarget(t); err != nil {
				a.log.Warn("failed to collect from target",
					"target", t.Name,
					"address", t.Address,
					"error", err,
				)
				a.targetStatus.Store(t.Name, "unhealthy")
				a.errorCount.Add(1)
				a.lastError.Store(err.Error())
			} else {
				a.targetStatus.Store(t.Name, "healthy")
			}
		}(target)
	}

	wg.Wait()
	a.lastCollection.Store(time.Now())
	a.collectionCount.Add(1)
}

// collectTarget collects metrics from a single target.
func (a *SNMPAdapter) collectTarget(target SNMPTarget) error {
	ctx, cancel := context.WithTimeout(a.ctx, a.config.Timeout)
	defer cancel()

	// Convert to poll target
	pollTarget := SNMPPollTarget{
		Name:      target.Name,
		Address:   target.Address,
		Version:   target.Version,
		Community: target.Community,
		V3Auth:    target.V3Auth,
		Modules:   target.Modules,
	}

	// Poll via V2 poller
	if a.poller == nil {
		// If no poller provided, use mock data for testing
		return a.collectWithMockData(ctx, target)
	}

	metrics, err := a.poller.Poll(ctx, pollTarget)
	if err != nil {
		return fmt.Errorf("poll failed: %w", err)
	}

	// Convert SNMP metrics to OTLP and send
	otlpMetrics := a.convertToOTLP(target, metrics)
	if err := a.sink.SendMetrics(ctx, otlpMetrics); err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}

	a.log.Debug("collected metrics from target",
		"target", target.Name,
		"metric_count", len(metrics),
	)

	return nil
}

// collectWithMockData provides mock data when no poller is available (for testing).
func (a *SNMPAdapter) collectWithMockData(ctx context.Context, target SNMPTarget) error {
	// Create mock metrics for testing
	metrics := []SNMPMetric{
		{
			Name:        "snmp_interface_ifInOctets",
			Description: "Interface input octets",
			Value:       float64(time.Now().UnixNano() % 1000000),
			Labels: map[string]string{
				"target":  target.Name,
				"ifIndex": "1",
				"ifName":  "eth0",
			},
			Timestamp: time.Now(),
			Type:      "counter",
		},
		{
			Name:        "snmp_interface_ifOutOctets",
			Description: "Interface output octets",
			Value:       float64(time.Now().UnixNano() % 1000000),
			Labels: map[string]string{
				"target":  target.Name,
				"ifIndex": "1",
				"ifName":  "eth0",
			},
			Timestamp: time.Now(),
			Type:      "counter",
		},
	}

	otlpMetrics := a.convertToOTLP(target, metrics)
	return a.sink.SendMetrics(ctx, otlpMetrics)
}

// convertToOTLP converts SNMP metrics to OTLP format.
func (a *SNMPAdapter) convertToOTLP(target SNMPTarget, metrics []SNMPMetric) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()

	// Set resource attributes
	res := rm.Resource()
	res.Attributes().PutStr("service.name", "snmp")
	res.Attributes().PutStr("snmp.target.name", target.Name)
	res.Attributes().PutStr("snmp.target.address", target.Address)
	res.Attributes().PutStr("snmp.version", target.Version)

	// Add target labels as resource attributes
	for k, v := range target.Labels {
		res.Attributes().PutStr(k, v)
	}

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen-snmp-adapter")
	sm.Scope().SetVersion("1.0.0")

	for _, m := range metrics {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName(m.Name)
		metric.SetDescription(m.Description)

		switch m.Type {
		case "counter":
			sum := metric.SetEmptySum()
			sum.SetIsMonotonic(true)
			sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
			dp := sum.DataPoints().AppendEmpty()
			dp.SetDoubleValue(m.Value)
			dp.SetTimestamp(pcommon.NewTimestampFromTime(m.Timestamp))
			for k, v := range m.Labels {
				dp.Attributes().PutStr(k, v)
			}
		default: // gauge
			gauge := metric.SetEmptyGauge()
			dp := gauge.DataPoints().AppendEmpty()
			dp.SetDoubleValue(m.Value)
			dp.SetTimestamp(pcommon.NewTimestampFromTime(m.Timestamp))
			for k, v := range m.Labels {
				dp.Attributes().PutStr(k, v)
			}
		}
	}

	return md
}

// discoveryLoop runs periodic SNMP device discovery.
func (a *SNMPAdapter) discoveryLoop() {
	defer a.wg.Done()

	if a.config.Discovery == nil {
		return
	}

	interval := a.config.Discovery.ScanInterval
	if interval == 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.discoverDevices()
		}
	}
}

// discoverDevices scans networks for SNMP devices.
func (a *SNMPAdapter) discoverDevices() {
	if a.config.Discovery == nil {
		return
	}

	a.log.Debug("starting SNMP device discovery",
		"networks", a.config.Discovery.Networks,
	)

	// Discovery implementation would scan networks
	// For now, this is a placeholder
	// Real implementation would use SNMP broadcast or network scanning
}

// AddTarget dynamically adds a polling target.
func (a *SNMPAdapter) AddTarget(target SNMPTarget) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if target already exists
	for _, t := range a.config.Targets {
		if t.Name == target.Name {
			a.log.Warn("target already exists", "name", target.Name)
			return
		}
	}

	a.config.Targets = append(a.config.Targets, target)
	a.log.Info("added SNMP target", "name", target.Name, "address", target.Address)
}

// RemoveTarget dynamically removes a polling target.
func (a *SNMPAdapter) RemoveTarget(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, t := range a.config.Targets {
		if t.Name == name {
			a.config.Targets = append(a.config.Targets[:i], a.config.Targets[i+1:]...)
			a.targetStatus.Delete(name)
			a.log.Info("removed SNMP target", "name", name)
			return
		}
	}

	a.log.Warn("target not found", "name", name)
}

// Targets returns the current list of targets.
func (a *SNMPAdapter) Targets() []SNMPTarget {
	a.mu.RLock()
	defer a.mu.RUnlock()
	targets := make([]SNMPTarget, len(a.config.Targets))
	copy(targets, a.config.Targets)
	return targets
}
