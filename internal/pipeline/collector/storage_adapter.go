// Storage adapter wires V2 storage collectors (Dell/HPE/Pure/NetApp) to the V3 unified export pipeline.
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

// StorageConfig holds storage adapter configuration.
type StorageConfig struct {
	AdapterConfig `yaml:",inline" json:",inline"`

	// DellPowerStore collectors.
	DellPowerStore []StorageArrayConfig `yaml:"dell_powerstore,omitempty" json:"dell_powerstore,omitempty"`

	// HPEPrimera collectors.
	HPEPrimera []StorageArrayConfig `yaml:"hpe_primera,omitempty" json:"hpe_primera,omitempty"`

	// PureFlashArray collectors.
	PureFlashArray []StorageArrayConfig `yaml:"pure_flasharray,omitempty" json:"pure_flasharray,omitempty"`

	// NetAppONTAP collectors.
	NetAppONTAP []StorageArrayConfig `yaml:"netapp_ontap,omitempty" json:"netapp_ontap,omitempty"`
}

// StorageArrayConfig holds configuration for a storage array collector.
type StorageArrayConfig struct {
	// Name is the collector identifier.
	Name string `yaml:"name" json:"name"`

	// Endpoint is the array management endpoint.
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Auth holds authentication configuration.
	Auth StorageAuth `yaml:"auth" json:"auth"`

	// TLS configuration.
	TLS *StorageTLS `yaml:"tls,omitempty" json:"tls,omitempty"`

	// CollectInterval overrides the default collection interval.
	CollectInterval time.Duration `yaml:"collect_interval,omitempty" json:"collect_interval,omitempty"`

	// Labels are additional labels for metrics.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// MetricGroups specifies which metric groups to collect.
	MetricGroups []string `yaml:"metric_groups,omitempty" json:"metric_groups,omitempty"`
}

// StorageAuth holds authentication configuration for storage arrays.
type StorageAuth struct {
	// Type is the auth type: "basic", "api_key", "token".
	Type string `yaml:"type" json:"type"`

	// Username for basic auth.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// Password for basic auth.
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// APIKey for API key auth.
	APIKey string `yaml:"api_key,omitempty" json:"api_key,omitempty"`

	// Token for token-based auth.
	Token string `yaml:"token,omitempty" json:"token,omitempty"`
}

// StorageTLS holds TLS configuration.
type StorageTLS struct {
	// Enabled controls TLS.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// InsecureSkipVerify skips certificate verification.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`

	// CACert is the CA certificate path.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`

	// ClientCert is the client certificate path.
	ClientCert string `yaml:"client_cert,omitempty" json:"client_cert,omitempty"`

	// ClientKey is the client key path.
	ClientKey string `yaml:"client_key,omitempty" json:"client_key,omitempty"`
}

// DefaultStorageConfig returns sensible defaults.
func DefaultStorageConfig() StorageConfig {
	return StorageConfig{
		AdapterConfig: DefaultAdapterConfig(),
	}
}

// StorageCollector is the interface for V2 storage collectors.
type StorageCollector interface {
	Name() string
	Type() string // "dell_powerstore", "hpe_primera", "pure_flasharray", "netapp_ontap"
	Collect(ctx context.Context) ([]StorageMetric, error)
	Health() StorageCollectorHealth
}

// StorageCollectorHealth holds health status for a storage collector.
type StorageCollectorHealth struct {
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Status        string    `json:"status"`
	LastCollect   time.Time `json:"last_collect"`
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error,omitempty"`
	ArrayStatus   string    `json:"array_status,omitempty"`
	FirmwareVer   string    `json:"firmware_version,omitempty"`
	SerialNumber  string    `json:"serial_number,omitempty"`
	Capacity      int64     `json:"capacity_bytes,omitempty"`
	UsedCapacity  int64     `json:"used_capacity_bytes,omitempty"`
}

// StorageMetric holds a single storage metric.
type StorageMetric struct {
	Name        string
	Description string
	Value       float64
	Labels      map[string]string
	Timestamp   time.Time
	Unit        string // "bytes", "iops", "latency_ms", "percent"
	Type        string // "gauge" or "counter"
}

// StorageAdapter wires V2 storage collectors to V3 unified export.
type StorageAdapter struct {
	config     StorageConfig
	sink       MetricSink
	collectors []StorageCollector
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
	collectorHealth sync.Map     // string -> StorageCollectorHealth
}

// NewStorageAdapter creates a new storage adapter.
func NewStorageAdapter(config StorageConfig, sink MetricSink, log *slog.Logger) (*StorageAdapter, error) {
	if sink == nil {
		return nil, fmt.Errorf("metric sink is required")
	}
	if log == nil {
		log = slog.Default()
	}

	if config.CollectInterval == 0 {
		config.CollectInterval = 60 * time.Second
	}

	adapter := &StorageAdapter{
		config:     config,
		sink:       sink,
		collectors: make([]StorageCollector, 0),
		log:        log.With("adapter", "storage"),
	}
	adapter.lastCollection.Store(time.Time{})
	adapter.lastError.Store("")

	return adapter, nil
}

// RegisterCollector adds a storage collector to the adapter.
func (a *StorageAdapter) RegisterCollector(collector StorageCollector) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.collectors = append(a.collectors, collector)
	a.log.Info("registered storage collector",
		"name", collector.Name(),
		"type", collector.Type(),
	)
}

// Name implements Adapter.
func (a *StorageAdapter) Name() string {
	return "storage"
}

// Start implements Adapter.
func (a *StorageAdapter) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	if !a.config.Enabled {
		a.log.Info("storage adapter is disabled")
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

	a.log.Info("started storage adapter",
		"collectors", len(a.collectors),
		"collect_interval", a.config.CollectInterval,
	)

	return nil
}

// initializeCollectors creates collectors from configuration.
func (a *StorageAdapter) initializeCollectors() {
	// This would normally create V2 collectors
	// For now, we create mock collectors based on config
	for _, cfg := range a.config.DellPowerStore {
		a.collectors = append(a.collectors, &mockStorageCollector{
			name:       cfg.Name,
			arrayType:  "dell_powerstore",
			endpoint:   cfg.Endpoint,
			labels:     cfg.Labels,
		})
		a.log.Debug("created Dell PowerStore collector", "name", cfg.Name)
	}

	for _, cfg := range a.config.HPEPrimera {
		a.collectors = append(a.collectors, &mockStorageCollector{
			name:       cfg.Name,
			arrayType:  "hpe_primera",
			endpoint:   cfg.Endpoint,
			labels:     cfg.Labels,
		})
		a.log.Debug("created HPE Primera collector", "name", cfg.Name)
	}

	for _, cfg := range a.config.PureFlashArray {
		a.collectors = append(a.collectors, &mockStorageCollector{
			name:       cfg.Name,
			arrayType:  "pure_flasharray",
			endpoint:   cfg.Endpoint,
			labels:     cfg.Labels,
		})
		a.log.Debug("created Pure FlashArray collector", "name", cfg.Name)
	}

	for _, cfg := range a.config.NetAppONTAP {
		a.collectors = append(a.collectors, &mockStorageCollector{
			name:       cfg.Name,
			arrayType:  "netapp_ontap",
			endpoint:   cfg.Endpoint,
			labels:     cfg.Labels,
		})
		a.log.Debug("created NetApp ONTAP collector", "name", cfg.Name)
	}
}

// Stop implements Adapter.
func (a *StorageAdapter) Stop(ctx context.Context) error {
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
		a.log.Info("stopped storage adapter")
	case <-ctx.Done():
		a.log.Warn("storage adapter stop timeout")
	}

	return nil
}

// Health implements Adapter.
func (a *StorageAdapter) Health() AdapterHealth {
	health := AdapterHealth{
		Name:            "storage",
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
		ch := value.(StorageCollectorHealth)
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

// collectionLoop runs periodic storage collection.
func (a *StorageAdapter) collectionLoop() {
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

// collectAll collects metrics from all storage collectors.
func (a *StorageAdapter) collectAll() {
	a.mu.RLock()
	collectors := make([]StorageCollector, len(a.collectors))
	copy(collectors, a.collectors)
	a.mu.RUnlock()

	var wg sync.WaitGroup
	for _, collector := range collectors {
		wg.Add(1)
		go func(c StorageCollector) {
			defer wg.Done()
			if err := a.collectFromCollector(c); err != nil {
				a.log.Warn("failed to collect from storage array",
					"name", c.Name(),
					"type", c.Type(),
					"error", err,
				)
				a.collectorHealth.Store(c.Name(), StorageCollectorHealth{
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

// collectFromCollector collects metrics from a single storage collector.
func (a *StorageAdapter) collectFromCollector(collector StorageCollector) error {
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

	a.log.Debug("collected storage metrics",
		"name", collector.Name(),
		"type", collector.Type(),
		"metric_count", len(metrics),
	)

	return nil
}

// convertToOTLP converts storage metrics to OTLP format.
func (a *StorageAdapter) convertToOTLP(collector StorageCollector, metrics []StorageMetric) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()

	// Set resource attributes
	res := rm.Resource()
	res.Attributes().PutStr("service.name", "storage")
	res.Attributes().PutStr("storage.collector.name", collector.Name())
	res.Attributes().PutStr("storage.array.type", collector.Type())

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen-storage-adapter")
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

// mockStorageCollector is a mock collector for testing.
type mockStorageCollector struct {
	name      string
	arrayType string
	endpoint  string
	labels    map[string]string
}

func (m *mockStorageCollector) Name() string { return m.name }
func (m *mockStorageCollector) Type() string { return m.arrayType }

func (m *mockStorageCollector) Collect(ctx context.Context) ([]StorageMetric, error) {
	now := time.Now()
	labels := map[string]string{
		"array": m.name,
		"type":  m.arrayType,
	}
	for k, v := range m.labels {
		labels[k] = v
	}

	return []StorageMetric{
		{
			Name:        "storage_capacity_bytes",
			Description: "Total storage capacity",
			Value:       float64(10 * 1024 * 1024 * 1024 * 1024), // 10TB
			Labels:      labels,
			Timestamp:   now,
			Unit:        "bytes",
			Type:        "gauge",
		},
		{
			Name:        "storage_used_bytes",
			Description: "Used storage capacity",
			Value:       float64(3 * 1024 * 1024 * 1024 * 1024), // 3TB
			Labels:      labels,
			Timestamp:   now,
			Unit:        "bytes",
			Type:        "gauge",
		},
		{
			Name:        "storage_iops_read",
			Description: "Read IOPS",
			Value:       float64(time.Now().UnixNano() % 10000),
			Labels:      labels,
			Timestamp:   now,
			Unit:        "iops",
			Type:        "gauge",
		},
		{
			Name:        "storage_iops_write",
			Description: "Write IOPS",
			Value:       float64(time.Now().UnixNano() % 5000),
			Labels:      labels,
			Timestamp:   now,
			Unit:        "iops",
			Type:        "gauge",
		},
		{
			Name:        "storage_latency_read_ms",
			Description: "Read latency",
			Value:       float64(time.Now().UnixNano()%100) / 10.0,
			Labels:      labels,
			Timestamp:   now,
			Unit:        "ms",
			Type:        "gauge",
		},
		{
			Name:        "storage_latency_write_ms",
			Description: "Write latency",
			Value:       float64(time.Now().UnixNano()%100) / 10.0,
			Labels:      labels,
			Timestamp:   now,
			Unit:        "ms",
			Type:        "gauge",
		},
	}, nil
}

func (m *mockStorageCollector) Health() StorageCollectorHealth {
	return StorageCollectorHealth{
		Name:         m.name,
		Type:         m.arrayType,
		Status:       "healthy",
		Capacity:     10 * 1024 * 1024 * 1024 * 1024,
		UsedCapacity: 3 * 1024 * 1024 * 1024 * 1024,
	}
}
