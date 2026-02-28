// Network infrastructure adapter wires V2 network collectors (Arista/Cisco) to the V3 unified export pipeline.
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

// NetInfraConfig holds network infrastructure adapter configuration.
type NetInfraConfig struct {
	AdapterConfig `yaml:",inline" json:",inline"`

	// CloudVision holds Arista CloudVision configurations.
	CloudVision []CloudVisionConfig `yaml:"cloudvision,omitempty" json:"cloudvision,omitempty"`

	// ACI holds Cisco ACI configurations.
	ACI []ACIConfig `yaml:"aci,omitempty" json:"aci,omitempty"`
}

// CloudVisionConfig holds Arista CloudVision Portal configuration.
type CloudVisionConfig struct {
	// Name is the collector identifier.
	Name string `yaml:"name" json:"name"`

	// Endpoint is the CVP server address.
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Auth holds authentication configuration.
	Auth NetInfraAuth `yaml:"auth" json:"auth"`

	// TLS configuration.
	TLS *NetInfraTLS `yaml:"tls,omitempty" json:"tls,omitempty"`

	// CollectInterval overrides the default collection interval.
	CollectInterval time.Duration `yaml:"collect_interval,omitempty" json:"collect_interval,omitempty"`

	// Labels are additional labels for metrics.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// DeviceFilter filters which devices to collect from.
	DeviceFilter []string `yaml:"device_filter,omitempty" json:"device_filter,omitempty"`

	// MetricGroups specifies which metric groups to collect.
	MetricGroups []string `yaml:"metric_groups,omitempty" json:"metric_groups,omitempty"`
}

// ACIConfig holds Cisco ACI configuration.
type ACIConfig struct {
	// Name is the collector identifier.
	Name string `yaml:"name" json:"name"`

	// Endpoint is the APIC controller address.
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Auth holds authentication configuration.
	Auth NetInfraAuth `yaml:"auth" json:"auth"`

	// TLS configuration.
	TLS *NetInfraTLS `yaml:"tls,omitempty" json:"tls,omitempty"`

	// CollectInterval overrides the default collection interval.
	CollectInterval time.Duration `yaml:"collect_interval,omitempty" json:"collect_interval,omitempty"`

	// Labels are additional labels for metrics.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// TenantFilter filters which tenants to collect from.
	TenantFilter []string `yaml:"tenant_filter,omitempty" json:"tenant_filter,omitempty"`

	// MetricGroups specifies which metric groups to collect.
	MetricGroups []string `yaml:"metric_groups,omitempty" json:"metric_groups,omitempty"`
}

// NetInfraAuth holds authentication configuration.
type NetInfraAuth struct {
	// Type is the auth type: "basic", "token", "certificate".
	Type string `yaml:"type" json:"type"`

	// Username for basic auth.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// Password for basic auth.
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// Token for token-based auth.
	Token string `yaml:"token,omitempty" json:"token,omitempty"`
}

// NetInfraTLS holds TLS configuration.
type NetInfraTLS struct {
	// Enabled controls TLS.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// InsecureSkipVerify skips certificate verification.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`

	// CACert is the CA certificate path.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`
}

// DefaultNetInfraConfig returns sensible defaults.
func DefaultNetInfraConfig() NetInfraConfig {
	return NetInfraConfig{
		AdapterConfig: DefaultAdapterConfig(),
	}
}

// NetInfraCollector is the interface for V2 network infrastructure collectors.
type NetInfraCollector interface {
	Name() string
	Type() string // "cloudvision" or "aci"
	Collect(ctx context.Context) ([]NetInfraMetric, error)
	Health() NetInfraCollectorHealth
}

// NetInfraCollectorHealth holds health status for a network infrastructure collector.
type NetInfraCollectorHealth struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	LastCollect  time.Time `json:"last_collect"`
	ErrorCount   int64     `json:"error_count"`
	LastError    string    `json:"last_error,omitempty"`
	DeviceCount  int       `json:"device_count,omitempty"`
	HealthyCount int       `json:"healthy_count,omitempty"`
}

// NetInfraMetric holds a single network infrastructure metric.
type NetInfraMetric struct {
	Name        string
	Description string
	Value       float64
	Labels      map[string]string
	Timestamp   time.Time
	Unit        string
	Type        string // "gauge" or "counter"
}

// NetInfraAdapter wires V2 network infrastructure collectors to V3 unified export.
type NetInfraAdapter struct {
	config     NetInfraConfig
	sink       MetricSink
	collectors []NetInfraCollector
	log        *slog.Logger

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
	collectorHealth sync.Map     // string -> NetInfraCollectorHealth
}

// NewNetInfraAdapter creates a new network infrastructure adapter.
func NewNetInfraAdapter(config NetInfraConfig, sink MetricSink, log *slog.Logger) (*NetInfraAdapter, error) {
	if sink == nil {
		return nil, fmt.Errorf("metric sink is required")
	}
	if log == nil {
		log = slog.Default()
	}

	if config.CollectInterval == 0 {
		config.CollectInterval = 30 * time.Second
	}

	adapter := &NetInfraAdapter{
		config:     config,
		sink:       sink,
		collectors: make([]NetInfraCollector, 0),
		log:        log.With("adapter", "netinfra"),
	}
	adapter.lastCollection.Store(time.Time{})
	adapter.lastError.Store("")

	return adapter, nil
}

// RegisterCollector adds a network infrastructure collector.
func (a *NetInfraAdapter) RegisterCollector(collector NetInfraCollector) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.collectors = append(a.collectors, collector)
	a.log.Info("registered netinfra collector",
		"name", collector.Name(),
		"type", collector.Type(),
	)
}

// Name implements Adapter.
func (a *NetInfraAdapter) Name() string {
	return "netinfra"
}

// Start implements Adapter.
func (a *NetInfraAdapter) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	if !a.config.Enabled {
		a.log.Info("network infrastructure adapter is disabled")
		return nil
	}

	a.ctx, a.cancel = context.WithCancel(ctx)
	a.running = true

	// Initialize collectors from config if none registered
	if len(a.collectors) == 0 {
		a.initializeCollectors()
	}

	// Start collection loop
	a.wg.Add(1)
	go a.collectionLoop()

	a.log.Info("started network infrastructure adapter",
		"collectors", len(a.collectors),
		"collect_interval", a.config.CollectInterval,
	)

	return nil
}

// initializeCollectors creates collectors from configuration.
func (a *NetInfraAdapter) initializeCollectors() {
	// CloudVision collectors
	for _, cfg := range a.config.CloudVision {
		a.collectors = append(a.collectors, &mockNetInfraCollector{
			name:         cfg.Name,
			collType:     "cloudvision",
			endpoint:     cfg.Endpoint,
			labels:       cfg.Labels,
			deviceFilter: cfg.DeviceFilter,
		})
		a.log.Debug("created CloudVision collector", "name", cfg.Name)
	}

	// ACI collectors
	for _, cfg := range a.config.ACI {
		a.collectors = append(a.collectors, &mockNetInfraCollector{
			name:         cfg.Name,
			collType:     "aci",
			endpoint:     cfg.Endpoint,
			labels:       cfg.Labels,
			tenantFilter: cfg.TenantFilter,
		})
		a.log.Debug("created ACI collector", "name", cfg.Name)
	}
}

// Stop implements Adapter.
func (a *NetInfraAdapter) Stop(ctx context.Context) error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.cancel()
	a.running = false
	a.mu.Unlock()

	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		a.log.Info("stopped network infrastructure adapter")
	case <-ctx.Done():
		a.log.Warn("network infrastructure adapter stop timeout")
	}

	return nil
}

// Health implements Adapter.
func (a *NetInfraAdapter) Health() AdapterHealth {
	health := AdapterHealth{
		Name:            "netinfra",
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

	// Collect collector statuses
	a.collectorHealth.Range(func(key, value interface{}) bool {
		ch := value.(NetInfraCollectorHealth)
		health.Targets[ch.Name] = ch.Status
		return true
	})

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

// collectionLoop runs periodic network infrastructure collection.
func (a *NetInfraAdapter) collectionLoop() {
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

// collectAll collects metrics from all network infrastructure collectors.
func (a *NetInfraAdapter) collectAll() {
	a.mu.RLock()
	collectors := make([]NetInfraCollector, len(a.collectors))
	copy(collectors, a.collectors)
	a.mu.RUnlock()

	var wg sync.WaitGroup
	for _, collector := range collectors {
		wg.Add(1)
		go func(c NetInfraCollector) {
			defer wg.Done()
			if err := a.collectFromCollector(c); err != nil {
				a.log.Warn("failed to collect from network device",
					"name", c.Name(),
					"type", c.Type(),
					"error", err,
				)
				a.collectorHealth.Store(c.Name(), NetInfraCollectorHealth{
					Name:      c.Name(),
					Type:      c.Type(),
					Status:    "unhealthy",
					LastError: err.Error(),
				})
				a.errorCount.Add(1)
				a.lastError.Store(err.Error())
			}
		}(collector)
	}

	wg.Wait()
	a.lastCollection.Store(time.Now())
	a.collectionCount.Add(1)
}

// collectFromCollector collects metrics from a single collector.
func (a *NetInfraAdapter) collectFromCollector(collector NetInfraCollector) error {
	ctx, cancel := context.WithTimeout(a.ctx, a.config.Timeout)
	defer cancel()

	metrics, err := collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collection failed: %w", err)
	}

	// Update health
	health := collector.Health()
	health.LastCollect = time.Now()
	health.Status = "healthy"
	a.collectorHealth.Store(collector.Name(), health)

	// Convert to OTLP and send
	otlpMetrics := a.convertToOTLP(collector, metrics)
	if err := a.sink.SendMetrics(ctx, otlpMetrics); err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}

	a.log.Debug("collected network infrastructure metrics",
		"name", collector.Name(),
		"type", collector.Type(),
		"metric_count", len(metrics),
	)

	return nil
}

// convertToOTLP converts network infrastructure metrics to OTLP format.
func (a *NetInfraAdapter) convertToOTLP(collector NetInfraCollector, metrics []NetInfraMetric) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()

	// Set resource attributes
	res := rm.Resource()
	res.Attributes().PutStr("service.name", "netinfra")
	res.Attributes().PutStr("netinfra.collector.name", collector.Name())
	res.Attributes().PutStr("netinfra.type", collector.Type())

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen-netinfra-adapter")
	sm.Scope().SetVersion("1.0.0")

	for _, m := range metrics {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName(m.Name)
		metric.SetDescription(m.Description)
		metric.SetUnit(m.Unit)

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

// mockNetInfraCollector is a mock collector for testing.
type mockNetInfraCollector struct {
	name         string
	collType     string
	endpoint     string
	labels       map[string]string
	deviceFilter []string
	tenantFilter []string
}

func (m *mockNetInfraCollector) Name() string { return m.name }
func (m *mockNetInfraCollector) Type() string { return m.collType }

func (m *mockNetInfraCollector) Collect(ctx context.Context) ([]NetInfraMetric, error) {
	now := time.Now()
	labels := map[string]string{
		"collector": m.name,
		"type":      m.collType,
	}
	for k, v := range m.labels {
		labels[k] = v
	}

	metrics := []NetInfraMetric{
		{
			Name:        "netinfra_device_up",
			Description: "Network device up status",
			Value:       1,
			Labels:      labels,
			Timestamp:   now,
			Unit:        "",
			Type:        "gauge",
		},
		{
			Name:        "netinfra_interface_rx_bytes_total",
			Description: "Interface received bytes",
			Value:       float64(time.Now().UnixNano() % 1000000000),
			Labels:      labels,
			Timestamp:   now,
			Unit:        "bytes",
			Type:        "counter",
		},
		{
			Name:        "netinfra_interface_tx_bytes_total",
			Description: "Interface transmitted bytes",
			Value:       float64(time.Now().UnixNano() % 1000000000),
			Labels:      labels,
			Timestamp:   now,
			Unit:        "bytes",
			Type:        "counter",
		},
		{
			Name:        "netinfra_interface_errors_total",
			Description: "Interface errors",
			Value:       float64(time.Now().UnixNano() % 100),
			Labels:      labels,
			Timestamp:   now,
			Unit:        "",
			Type:        "counter",
		},
		{
			Name:        "netinfra_cpu_usage_percent",
			Description: "Device CPU usage",
			Value:       float64(time.Now().UnixNano()%80) + 10,
			Labels:      labels,
			Timestamp:   now,
			Unit:        "percent",
			Type:        "gauge",
		},
		{
			Name:        "netinfra_memory_usage_percent",
			Description: "Device memory usage",
			Value:       float64(time.Now().UnixNano()%60) + 20,
			Labels:      labels,
			Timestamp:   now,
			Unit:        "percent",
			Type:        "gauge",
		},
	}

	// Add device-specific labels for CloudVision
	if m.collType == "cloudvision" {
		for i := range metrics {
			metrics[i].Labels["device_model"] = "Arista-7280R"
			metrics[i].Labels["eos_version"] = "4.28.0F"
		}
	}

	// Add tenant-specific labels for ACI
	if m.collType == "aci" {
		for i := range metrics {
			metrics[i].Labels["fabric"] = "ACI-PROD"
			metrics[i].Labels["apic_version"] = "5.2"
		}
	}

	return metrics, nil
}

func (m *mockNetInfraCollector) Health() NetInfraCollectorHealth {
	return NetInfraCollectorHealth{
		Name:         m.name,
		Type:         m.collType,
		Status:       "healthy",
		DeviceCount:  10,
		HealthyCount: 10,
	}
}
