package collector

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

// mockMetricSink is a test sink that captures sent metrics.
type mockMetricSink struct {
	mu      sync.Mutex
	metrics []pmetric.Metrics
	err     error
}

func newMockMetricSink() *mockMetricSink {
	return &mockMetricSink{
		metrics: make([]pmetric.Metrics, 0),
	}
}

func (m *mockMetricSink) SendMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.metrics = append(m.metrics, metrics)
	return nil
}

func (m *mockMetricSink) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.metrics)
}

// TestAdapterRegistry tests the adapter registry.
func TestAdapterRegistry(t *testing.T) {
	sink := newMockMetricSink()
	registry := NewAdapterRegistry(sink, nil)

	// Create a mock adapter
	mockAdapter := &testAdapter{name: "test"}

	// Register adapter
	if err := registry.Register(mockAdapter); err != nil {
		t.Fatalf("failed to register adapter: %v", err)
	}

	// Verify adapter is registered
	names := registry.List()
	if len(names) != 1 {
		t.Errorf("expected 1 adapter, got %d", len(names))
	}

	// Get adapter
	adapter, ok := registry.Get("test")
	if !ok {
		t.Error("adapter not found")
	}
	if adapter.Name() != "test" {
		t.Errorf("expected name 'test', got '%s'", adapter.Name())
	}

	// Duplicate registration should fail
	if err := registry.Register(mockAdapter); err == nil {
		t.Error("expected error for duplicate registration")
	}
}

// TestAdapterRegistryStartStop tests registry start/stop.
func TestAdapterRegistryStartStop(t *testing.T) {
	sink := newMockMetricSink()
	registry := NewAdapterRegistry(sink, nil)

	adapter := &testAdapter{name: "test"}
	registry.Register(adapter)

	ctx := context.Background()

	// Start registry
	if err := registry.Start(ctx); err != nil {
		t.Fatalf("failed to start registry: %v", err)
	}

	// Wait for adapter to start
	time.Sleep(100 * time.Millisecond)

	if !adapter.started.Load() {
		t.Error("adapter was not started")
	}

	// Stop registry
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := registry.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop registry: %v", err)
	}

	if !adapter.stopped.Load() {
		t.Error("adapter was not stopped")
	}
}

// TestSNMPAdapter tests the SNMP adapter.
func TestSNMPAdapter(t *testing.T) {
	sink := newMockMetricSink()

	config := SNMPConfig{
		AdapterConfig: AdapterConfig{
			Enabled:         true,
			CollectInterval: 100 * time.Millisecond,
			Timeout:         5 * time.Second,
		},
		Targets: []SNMPTarget{
			{
				Name:      "test-device",
				Address:   "192.168.1.1:161",
				Version:   "2c",
				Community: "public",
				Modules:   []string{"if-mib"},
			},
		},
	}

	adapter, err := NewSNMPAdapter(config, sink, nil, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	if adapter.Name() != "snmp" {
		t.Errorf("expected name 'snmp', got '%s'", adapter.Name())
	}

	ctx := context.Background()

	// Start adapter
	if err := adapter.Start(ctx); err != nil {
		t.Fatalf("failed to start adapter: %v", err)
	}

	// Wait for at least one collection
	time.Sleep(200 * time.Millisecond)

	// Check metrics were sent
	if sink.Count() == 0 {
		t.Error("no metrics were sent")
	}

	// Check health
	health := adapter.Health()
	if health.Name != "snmp" {
		t.Errorf("expected health name 'snmp', got '%s'", health.Name)
	}
	if health.CollectionCount == 0 {
		t.Error("expected collection count > 0")
	}

	// Stop adapter
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := adapter.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop adapter: %v", err)
	}
}

// TestSNMPAdapterTargetManagement tests dynamic target management.
func TestSNMPAdapterTargetManagement(t *testing.T) {
	sink := newMockMetricSink()

	config := SNMPConfig{
		AdapterConfig: AdapterConfig{
			Enabled:         true,
			CollectInterval: 1 * time.Hour, // Don't auto-collect
		},
	}

	adapter, err := NewSNMPAdapter(config, sink, nil, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// Initially no targets
	if len(adapter.Targets()) != 0 {
		t.Errorf("expected 0 targets, got %d", len(adapter.Targets()))
	}

	// Add a target
	adapter.AddTarget(SNMPTarget{
		Name:    "router-1",
		Address: "192.168.1.1:161",
	})

	if len(adapter.Targets()) != 1 {
		t.Errorf("expected 1 target, got %d", len(adapter.Targets()))
	}

	// Add duplicate (should be ignored)
	adapter.AddTarget(SNMPTarget{
		Name:    "router-1",
		Address: "192.168.1.1:161",
	})

	if len(adapter.Targets()) != 1 {
		t.Errorf("expected 1 target after duplicate, got %d", len(adapter.Targets()))
	}

	// Remove target
	adapter.RemoveTarget("router-1")

	if len(adapter.Targets()) != 0 {
		t.Errorf("expected 0 targets after removal, got %d", len(adapter.Targets()))
	}
}

// TestStorageAdapter tests the storage adapter.
func TestStorageAdapter(t *testing.T) {
	sink := newMockMetricSink()

	config := StorageConfig{
		AdapterConfig: AdapterConfig{
			Enabled:         true,
			CollectInterval: 100 * time.Millisecond,
			Timeout:         5 * time.Second,
		},
		DellPowerStore: []StorageArrayConfig{
			{
				Name:     "dell-array-1",
				Endpoint: "https://dell-array-1.example.com",
			},
		},
	}

	adapter, err := NewStorageAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	if adapter.Name() != "storage" {
		t.Errorf("expected name 'storage', got '%s'", adapter.Name())
	}

	ctx := context.Background()

	// Start adapter
	if err := adapter.Start(ctx); err != nil {
		t.Fatalf("failed to start adapter: %v", err)
	}

	// Wait for collection
	time.Sleep(200 * time.Millisecond)

	// Check metrics were sent
	if sink.Count() == 0 {
		t.Error("no metrics were sent")
	}

	// Check health
	health := adapter.Health()
	if health.Name != "storage" {
		t.Errorf("expected health name 'storage', got '%s'", health.Name)
	}

	// Stop adapter
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := adapter.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop adapter: %v", err)
	}
}

// TestNetInfraAdapter tests the network infrastructure adapter.
func TestNetInfraAdapter(t *testing.T) {
	sink := newMockMetricSink()

	config := NetInfraConfig{
		AdapterConfig: AdapterConfig{
			Enabled:         true,
			CollectInterval: 100 * time.Millisecond,
			Timeout:         5 * time.Second,
		},
		CloudVision: []CloudVisionConfig{
			{
				Name:     "cvp-1",
				Endpoint: "https://cvp.example.com",
			},
		},
		ACI: []ACIConfig{
			{
				Name:     "aci-1",
				Endpoint: "https://apic.example.com",
			},
		},
	}

	adapter, err := NewNetInfraAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	if adapter.Name() != "netinfra" {
		t.Errorf("expected name 'netinfra', got '%s'", adapter.Name())
	}

	ctx := context.Background()

	// Start adapter
	if err := adapter.Start(ctx); err != nil {
		t.Fatalf("failed to start adapter: %v", err)
	}

	// Wait for collection
	time.Sleep(200 * time.Millisecond)

	// Check metrics were sent
	if sink.Count() == 0 {
		t.Error("no metrics were sent")
	}

	// Check health
	health := adapter.Health()
	if health.Name != "netinfra" {
		t.Errorf("expected health name 'netinfra', got '%s'", health.Name)
	}

	// Stop adapter
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := adapter.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop adapter: %v", err)
	}
}

// TestServiceDiscovery tests the service discovery component.
func TestServiceDiscovery(t *testing.T) {
	config := DiscoveryConfig{
		Enabled:         true,
		RefreshInterval: 100 * time.Millisecond,
		File: &FileDiscoveryConfig{
			Enabled: false, // Disable to avoid file access
		},
	}

	sd, err := NewServiceDiscovery(config, nil)
	if err != nil {
		t.Fatalf("failed to create service discovery: %v", err)
	}

	// Set up target handler
	var mu sync.Mutex
	var addedTargets, removedTargets []DiscoveredTarget

	sd.OnTargetChange(func(added, removed []DiscoveredTarget) {
		mu.Lock()
		defer mu.Unlock()
		addedTargets = append(addedTargets, added...)
		removedTargets = append(removedTargets, removed...)
	})

	// Initially no targets
	if sd.TargetCount() != 0 {
		t.Errorf("expected 0 targets, got %d", sd.TargetCount())
	}

	ctx := context.Background()

	// Start service discovery
	if err := sd.Start(ctx); err != nil {
		t.Fatalf("failed to start service discovery: %v", err)
	}

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Stop service discovery
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sd.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop service discovery: %v", err)
	}
}

// TestServiceDiscoveryTargetFiltering tests target filtering.
func TestServiceDiscoveryTargetFiltering(t *testing.T) {
	config := DefaultDiscoveryConfig()

	sd, err := NewServiceDiscovery(config, nil)
	if err != nil {
		t.Fatalf("failed to create service discovery: %v", err)
	}

	// Manually add some targets for testing
	sd.mu.Lock()
	sd.targets["k8s:target1"] = DiscoveredTarget{
		Name:   "target1",
		Type:   "prometheus",
		Source: "kubernetes",
	}
	sd.targets["k8s:target2"] = DiscoveredTarget{
		Name:   "target2",
		Type:   "snmp",
		Source: "kubernetes",
	}
	sd.targets["consul:target3"] = DiscoveredTarget{
		Name:   "target3",
		Type:   "prometheus",
		Source: "consul",
	}
	sd.mu.Unlock()

	// Filter by type
	promTargets := sd.TargetsByType("prometheus")
	if len(promTargets) != 2 {
		t.Errorf("expected 2 prometheus targets, got %d", len(promTargets))
	}

	snmpTargets := sd.TargetsByType("snmp")
	if len(snmpTargets) != 1 {
		t.Errorf("expected 1 snmp target, got %d", len(snmpTargets))
	}

	// Filter by source
	k8sTargets := sd.TargetsBySource("kubernetes")
	if len(k8sTargets) != 2 {
		t.Errorf("expected 2 kubernetes targets, got %d", len(k8sTargets))
	}

	consulTargets := sd.TargetsBySource("consul")
	if len(consulTargets) != 1 {
		t.Errorf("expected 1 consul target, got %d", len(consulTargets))
	}
}

// TestDisabledAdapters tests that disabled adapters don't start.
func TestDisabledAdapters(t *testing.T) {
	sink := newMockMetricSink()

	// SNMP disabled
	snmpConfig := SNMPConfig{
		AdapterConfig: AdapterConfig{
			Enabled: false,
		},
	}
	snmpAdapter, _ := NewSNMPAdapter(snmpConfig, sink, nil, nil)

	ctx := context.Background()
	snmpAdapter.Start(ctx)

	// Storage disabled
	storageConfig := StorageConfig{
		AdapterConfig: AdapterConfig{
			Enabled: false,
		},
	}
	storageAdapter, _ := NewStorageAdapter(storageConfig, sink, nil)
	storageAdapter.Start(ctx)

	// NetInfra disabled
	netinfraConfig := NetInfraConfig{
		AdapterConfig: AdapterConfig{
			Enabled: false,
		},
	}
	netinfraAdapter, _ := NewNetInfraAdapter(netinfraConfig, sink, nil)
	netinfraAdapter.Start(ctx)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// No metrics should be sent
	if sink.Count() != 0 {
		t.Errorf("expected 0 metrics from disabled adapters, got %d", sink.Count())
	}
}

// TestRESTAPIAdapter tests the REST API adapter.
func TestRESTAPIAdapter(t *testing.T) {
	sink := newMockMetricSink()

	config := RESTAPIConfig{
		AdapterConfig: AdapterConfig{
			Enabled:         true,
			CollectInterval: 100 * time.Millisecond,
			Timeout:         5 * time.Second,
		},
		Endpoints: []RESTEndpointConfig{
			{
				Name: "test-api",
				URL:  "http://localhost:9999/metrics", // Won't actually connect
				Metrics: []MetricExtraction{
					{
						Name:     "test_metric",
						JSONPath: "$.value",
						Type:     "gauge",
					},
				},
			},
		},
	}

	adapter, err := NewRESTAPIAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	if adapter.Name() != "restapi" {
		t.Errorf("expected name 'restapi', got '%s'", adapter.Name())
	}

	// Check health before start
	health := adapter.Health()
	if health.Name != "restapi" {
		t.Errorf("expected health name 'restapi', got '%s'", health.Name)
	}
}

// TestRESTAPIJSONPathExtraction tests JSONPath extraction.
func TestRESTAPIJSONPathExtraction(t *testing.T) {
	sink := newMockMetricSink()
	config := DefaultRESTAPIConfig()
	adapter, _ := NewRESTAPIAdapter(config, sink, nil)

	testCases := []struct {
		name     string
		data     interface{}
		path     string
		expected []interface{}
	}{
		{
			name:     "simple key",
			data:     map[string]interface{}{"value": 42.0},
			path:     "$.value",
			expected: []interface{}{42.0},
		},
		{
			name: "nested key",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"metrics": map[string]interface{}{
						"cpu": 75.5,
					},
				},
			},
			path:     "$.data.metrics.cpu",
			expected: []interface{}{75.5},
		},
		{
			name: "array access",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"value": 1.0},
					map[string]interface{}{"value": 2.0},
					map[string]interface{}{"value": 3.0},
				},
			},
			path:     "$.items[1].value",
			expected: []interface{}{2.0},
		},
		{
			name: "array wildcard",
			data: map[string]interface{}{
				"items": []interface{}{1.0, 2.0, 3.0},
			},
			path:     "$.items[*]",
			expected: []interface{}{1.0, 2.0, 3.0},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := adapter.evaluateJSONPath(tc.data, tc.path)
			if len(result) != len(tc.expected) {
				t.Errorf("expected %d results, got %d", len(tc.expected), len(result))
				return
			}
			for i, exp := range tc.expected {
				if result[i] != exp {
					t.Errorf("result[%d]: expected %v, got %v", i, exp, result[i])
				}
			}
		})
	}
}

// TestRESTAPIAuthConfiguration tests authentication configuration.
func TestRESTAPIAuthConfiguration(t *testing.T) {
	sink := newMockMetricSink()

	testCases := []struct {
		name string
		auth *RESTAuth
	}{
		{
			name: "no auth",
			auth: nil,
		},
		{
			name: "basic auth",
			auth: &RESTAuth{
				Type:     "basic",
				Username: "user",
				Password: "pass",
			},
		},
		{
			name: "bearer token",
			auth: &RESTAuth{
				Type:        "bearer",
				BearerToken: "test-token",
			},
		},
		{
			name: "api key",
			auth: &RESTAuth{
				Type:         "api_key",
				APIKey:       "secret-key",
				APIKeyHeader: "X-Custom-Key",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := RESTAPIConfig{
				AdapterConfig: AdapterConfig{
					Enabled: true,
				},
				Endpoints: []RESTEndpointConfig{
					{
						Name: "test",
						URL:  "http://localhost/api",
						Auth: tc.auth,
					},
				},
			}

			adapter, err := NewRESTAPIAdapter(config, sink, nil)
			if err != nil {
				t.Fatalf("failed to create adapter: %v", err)
			}

			if adapter.Name() != "restapi" {
				t.Errorf("expected name 'restapi', got '%s'", adapter.Name())
			}
		})
	}
}

// TestRESTAPIMetricExtraction tests metric extraction configuration.
func TestRESTAPIMetricExtraction(t *testing.T) {
	sink := newMockMetricSink()
	config := DefaultRESTAPIConfig()
	adapter, _ := NewRESTAPIAdapter(config, sink, nil)

	endpoint := RESTEndpointConfig{
		Name: "test",
		URL:  "http://localhost/api",
		Labels: map[string]string{
			"endpoint": "test",
		},
		Metrics: []MetricExtraction{
			{
				Name:        "cpu_usage",
				Description: "CPU usage percentage",
				JSONPath:    "$.cpu",
				Type:        "gauge",
				Unit:        "percent",
				Labels: map[string]string{
					"metric_type": "cpu",
				},
				Multiplier: 100.0,
			},
			{
				Name:     "request_count",
				JSONPath: "$.requests",
				Type:     "counter",
			},
		},
	}

	data := map[string]interface{}{
		"cpu":      0.75,
		"requests": 1000.0,
	}

	metrics := adapter.extractMetrics(endpoint, data)

	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}

	// Check first metric (cpu_usage with multiplier)
	if metrics[0].Name != "cpu_usage" {
		t.Errorf("expected name 'cpu_usage', got '%s'", metrics[0].Name)
	}
	if metrics[0].Value != 75.0 { // 0.75 * 100
		t.Errorf("expected value 75.0, got %v", metrics[0].Value)
	}
	if metrics[0].Labels["endpoint"] != "test" {
		t.Errorf("expected endpoint label 'test', got '%s'", metrics[0].Labels["endpoint"])
	}
	if metrics[0].Labels["metric_type"] != "cpu" {
		t.Errorf("expected metric_type label 'cpu', got '%s'", metrics[0].Labels["metric_type"])
	}

	// Check second metric (request_count)
	if metrics[1].Name != "request_count" {
		t.Errorf("expected name 'request_count', got '%s'", metrics[1].Name)
	}
	if metrics[1].Value != 1000.0 {
		t.Errorf("expected value 1000.0, got %v", metrics[1].Value)
	}
}

// testAdapter is a simple adapter for testing.
type testAdapter struct {
	name    string
	started atomic.Bool
	stopped atomic.Bool
}

func (a *testAdapter) Name() string { return a.name }

func (a *testAdapter) Start(ctx context.Context) error {
	a.started.Store(true)
	return nil
}

func (a *testAdapter) Stop(ctx context.Context) error {
	a.stopped.Store(true)
	return nil
}

func (a *testAdapter) Health() AdapterHealth {
	return AdapterHealth{
		Name:   a.name,
		Status: "healthy",
	}
}

// ============================================================
// Prometheus Adapter Tests
// ============================================================

// TestPrometheusAdapter tests basic Prometheus adapter creation.
func TestPrometheusAdapter(t *testing.T) {
	sink := newMockMetricSink()

	config := DefaultPrometheusConfig()
	config.Enabled = true
	config.CollectInterval = 100 * time.Millisecond
	config.Targets = []PrometheusTarget{
		{
			Name: "test-target",
			URL:  "http://localhost:9090/metrics",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	adapter, err := NewPrometheusAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create Prometheus adapter: %v", err)
	}

	if adapter.Name() != "prometheus" {
		t.Errorf("expected name 'prometheus', got '%s'", adapter.Name())
	}

	// Check health
	health := adapter.Health()
	if health.Name != "prometheus" {
		t.Errorf("expected health name 'prometheus', got '%s'", health.Name)
	}
	if health.Status != "healthy" {
		t.Errorf("expected status 'healthy', got '%s'", health.Status)
	}
}

// TestPrometheusTextParsing tests Prometheus text format parsing.
func TestPrometheusTextParsing(t *testing.T) {
	sink := newMockMetricSink()

	config := DefaultPrometheusConfig()
	config.Enabled = true

	adapter, err := NewPrometheusAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// Sample Prometheus text format
	promText := `# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/api"} 1000
http_requests_total{method="POST",path="/api"} 500

# HELP process_cpu_seconds_total Total user and system CPU
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 45.23

# HELP memory_bytes Current memory usage
# TYPE memory_bytes gauge
memory_bytes{type="heap"} 1048576
memory_bytes{type="stack"} 262144
`

	reader := strings.NewReader(promText)
	families, err := adapter.parsePrometheusText(reader)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	// Verify we parsed families (exact count depends on grouping)
	if len(families) < 3 {
		t.Errorf("expected at least 3 families, got %d", len(families))
	}

	// Find the http_requests_total family
	var httpFamily *MetricFamily
	for _, f := range families {
		if f.Name == "http_requests_total" {
			httpFamily = f
			break
		}
	}

	if httpFamily == nil {
		t.Fatal("http_requests_total family not found")
	}

	if httpFamily.Type != "counter" {
		t.Errorf("expected type 'counter', got '%s'", httpFamily.Type)
	}

	if len(httpFamily.Metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(httpFamily.Metrics))
	}
}

// TestPrometheusHistogramParsing tests histogram parsing.
func TestPrometheusHistogramParsing(t *testing.T) {
	sink := newMockMetricSink()

	config := DefaultPrometheusConfig()
	config.Enabled = true

	adapter, err := NewPrometheusAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// Sample histogram
	promText := `# HELP http_request_duration_seconds Duration of HTTP requests
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.005"} 10
http_request_duration_seconds_bucket{le="0.01"} 20
http_request_duration_seconds_bucket{le="0.025"} 50
http_request_duration_seconds_bucket{le="0.05"} 100
http_request_duration_seconds_bucket{le="0.1"} 150
http_request_duration_seconds_bucket{le="+Inf"} 200
http_request_duration_seconds_sum 10.5
http_request_duration_seconds_count 200
`

	reader := strings.NewReader(promText)
	families, err := adapter.parsePrometheusText(reader)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	// Should parse as one family
	if len(families) < 1 {
		t.Fatal("expected at least 1 family")
	}

	// Find the histogram family
	var histFamily *MetricFamily
	for _, f := range families {
		if f.Name == "http_request_duration_seconds" {
			histFamily = f
			break
		}
	}

	if histFamily == nil {
		t.Fatal("http_request_duration_seconds family not found")
	}

	if histFamily.Type != "histogram" {
		t.Errorf("expected type 'histogram', got '%s'", histFamily.Type)
	}

	// Should have bucket metrics
	if len(histFamily.Metrics) < 6 {
		t.Errorf("expected at least 6 metrics (buckets), got %d", len(histFamily.Metrics))
	}
}

// TestPrometheusLabelParsing tests label parsing edge cases.
func TestPrometheusLabelParsing(t *testing.T) {
	sink := newMockMetricSink()

	config := DefaultPrometheusConfig()
	adapter, err := NewPrometheusAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	tests := []struct {
		name     string
		labels   string
		expected map[string]string
	}{
		{
			name:   "simple",
			labels: `method="GET",path="/api"`,
			expected: map[string]string{
				"method": "GET",
				"path":   "/api",
			},
		},
		{
			name:   "with_underscore",
			labels: `name="test_value"`,
			expected: map[string]string{
				"name": `test_value`,
			},
		},
		{
			name:   "empty_value",
			labels: `name=""`,
			expected: map[string]string{
				"name": "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapter.parseLabels(tt.labels)
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected %s=%s, got %s=%s", k, v, k, result[k])
				}
			}
		})
	}
}

// TestPrometheusOTLPConversion tests conversion to OTLP format.
func TestPrometheusOTLPConversion(t *testing.T) {
	sink := newMockMetricSink()

	config := DefaultPrometheusConfig()
	config.Enabled = true
	config.GlobalLabels = map[string]string{
		"cluster": "test-cluster",
	}

	adapter, err := NewPrometheusAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	target := PrometheusTarget{
		Name: "test-target",
		URL:  "http://localhost:9090/metrics",
		Labels: map[string]string{
			"env": "test",
		},
	}

	families := []*MetricFamily{
		{
			Name: "test_counter",
			Help: "A test counter",
			Type: "counter",
			Metrics: []PrometheusMetric{
				{
					Labels: map[string]string{"instance": "localhost:9090"},
					Value:  100.0,
				},
			},
		},
		{
			Name: "test_gauge",
			Help: "A test gauge",
			Type: "gauge",
			Metrics: []PrometheusMetric{
				{
					Labels: map[string]string{"instance": "localhost:9090"},
					Value:  42.5,
				},
			},
		},
	}

	otlpMetrics := adapter.convertToOTLP(target, families)

	// Verify resource metrics
	if otlpMetrics.ResourceMetrics().Len() != 1 {
		t.Fatalf("expected 1 resource metrics, got %d", otlpMetrics.ResourceMetrics().Len())
	}

	rm := otlpMetrics.ResourceMetrics().At(0)

	// Check resource attributes
	res := rm.Resource()
	serviceName, ok := res.Attributes().Get("service.name")
	if !ok || serviceName.Str() != "prometheus" {
		t.Error("expected service.name='prometheus'")
	}

	cluster, ok := res.Attributes().Get("cluster")
	if !ok || cluster.Str() != "test-cluster" {
		t.Error("expected cluster='test-cluster' from global labels")
	}

	// Check scope metrics
	if rm.ScopeMetrics().Len() != 1 {
		t.Fatalf("expected 1 scope metrics, got %d", rm.ScopeMetrics().Len())
	}

	sm := rm.ScopeMetrics().At(0)

	// Should have 2 metrics (counter + gauge)
	if sm.Metrics().Len() != 2 {
		t.Errorf("expected 2 metrics, got %d", sm.Metrics().Len())
	}
}

// TestPrometheusAdapterConfig tests configuration validation.
func TestPrometheusAdapterConfig(t *testing.T) {
	// Nil sink should error
	config := DefaultPrometheusConfig()
	_, err := NewPrometheusAdapter(config, nil, nil)
	if err == nil {
		t.Error("expected error for nil sink")
	}

	// Valid config should succeed
	sink := newMockMetricSink()
	adapter, err := NewPrometheusAdapter(config, sink, nil)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// Check defaults were applied
	if adapter.config.ScrapeTimeout != 10*time.Second {
		t.Errorf("expected scrape timeout 10s, got %v", adapter.config.ScrapeTimeout)
	}
	if adapter.config.MaxConcurrent != 10 {
		t.Errorf("expected max concurrent 10, got %d", adapter.config.MaxConcurrent)
	}
}
