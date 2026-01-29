package unified

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/discover/autodiscover"
)

// UnifiedAgent is the main integration point for cloud and discovery services.
type UnifiedAgent struct {
	cloudManager     *CloudManager
	discoveryEngine  *autodiscover.DiscoveryEngine
	otelExporter     *OTelExporter
	resourceExporter *ResourceExporter
	healthReporter   *HealthReporter
	metricsAgg       *MetricsAggregator

	config UnifiedAgentConfig
	mu     sync.RWMutex

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// UnifiedAgentConfig configures the unified agent.
type UnifiedAgentConfig struct {
	// Cloud configuration
	CloudConfig Config

	// Discovery configuration
	EnableDiscovery   bool
	DiscoveryInterval time.Duration
	DiscoverK8s       bool
	DiscoverDatabases bool
	DiscoverMQ        bool
	DiscoverRuntimes  bool

	// Export configuration
	EnableMetricsExport    bool
	MetricsExportInterval  time.Duration
	EnableResourceExport   bool
	ResourceExportInterval time.Duration

	// Health check configuration
	EnableHealthChecks  bool
	HealthCheckInterval time.Duration
}

// DefaultUnifiedAgentConfig returns default configuration.
func DefaultUnifiedAgentConfig() UnifiedAgentConfig {
	return UnifiedAgentConfig{
		CloudConfig:            DefaultConfig(),
		EnableDiscovery:        true,
		DiscoveryInterval:      5 * time.Minute,
		DiscoverK8s:            true,
		DiscoverDatabases:      true,
		DiscoverMQ:             true,
		DiscoverRuntimes:       true,
		EnableMetricsExport:    true,
		MetricsExportInterval:  60 * time.Second,
		EnableResourceExport:   true,
		ResourceExportInterval: 5 * time.Minute,
		EnableHealthChecks:     true,
		HealthCheckInterval:    30 * time.Second,
	}
}

// NewUnifiedAgent creates a new unified agent.
func NewUnifiedAgent(config UnifiedAgentConfig) *UnifiedAgent {
	cloudManager := NewCloudManager(config.CloudConfig)

	// Create discovery engine
	discoveryConfig := autodiscover.DiscoveryConfig{
		Interval:         config.DiscoveryInterval,
		EnabledDetectors: []string{"os", "container"},
	}

	if config.DiscoverK8s {
		discoveryConfig.EnabledDetectors = append(discoveryConfig.EnabledDetectors, "kubernetes")
	}
	if config.DiscoverDatabases {
		discoveryConfig.EnabledDetectors = append(discoveryConfig.EnabledDetectors, "database")
	}
	if config.DiscoverMQ {
		discoveryConfig.EnabledDetectors = append(discoveryConfig.EnabledDetectors, "message_queue")
	}
	if config.DiscoverRuntimes {
		discoveryConfig.EnabledDetectors = append(discoveryConfig.EnabledDetectors, "runtime", "process")
	}

	discoveryConfig.EnabledDetectors = append(discoveryConfig.EnabledDetectors, "network", "service_classifier")

	discoveryEngine := autodiscover.NewDiscoveryEngine(discoveryConfig)

	return &UnifiedAgent{
		cloudManager:     cloudManager,
		discoveryEngine:  discoveryEngine,
		resourceExporter: NewResourceExporter(cloudManager),
		healthReporter:   NewHealthReporter(cloudManager),
		metricsAgg:       NewMetricsAggregator(),
		config:           config,
		stopCh:           make(chan struct{}),
	}
}

// SetOTelExporter sets the OpenTelemetry exporter.
func (a *UnifiedAgent) SetOTelExporter(exporter *OTelExporter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.otelExporter = exporter
}

// Start starts the unified agent.
func (a *UnifiedAgent) Start(ctx context.Context) error {
	// Initialize cloud provider detection
	if err := a.cloudManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start cloud manager: %w", err)
	}

	// Start discovery engine
	if a.config.EnableDiscovery {
		if err := a.discoveryEngine.Start(ctx); err != nil {
			return fmt.Errorf("failed to start discovery engine: %w", err)
		}
	}

	// Start metrics export loop
	if a.config.EnableMetricsExport {
		a.wg.Add(1)
		go a.metricsExportLoop(ctx)
	}

	// Start resource export loop
	if a.config.EnableResourceExport {
		a.wg.Add(1)
		go a.resourceExportLoop(ctx)
	}

	// Start health check loop
	if a.config.EnableHealthChecks {
		a.wg.Add(1)
		go a.healthCheckLoop(ctx)
	}

	return nil
}

// Stop stops the unified agent.
func (a *UnifiedAgent) Stop(ctx context.Context) error {
	close(a.stopCh)

	// Stop discovery engine
	if a.discoveryEngine != nil {
		a.discoveryEngine.Stop()
	}

	// Stop cloud manager
	if a.cloudManager != nil {
		a.cloudManager.Stop()
	}

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// metricsExportLoop exports metrics periodically.
func (a *UnifiedAgent) metricsExportLoop(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.MetricsExportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.exportMetrics(ctx)
		}
	}
}

// exportMetrics collects and exports metrics.
func (a *UnifiedAgent) exportMetrics(ctx context.Context) {
	// Collect metrics from cloud manager
	metrics, err := a.cloudManager.CollectMetrics(ctx)
	if err != nil {
		// Log error
		return
	}

	// Normalize metrics
	provider := a.cloudManager.GetActiveProvider()
	if provider != nil {
		metrics = NormalizeMetrics(metrics, provider.Name())
	}

	// Add to aggregator
	a.metricsAgg.Add(metrics)

	// Export to OTel if configured
	a.mu.RLock()
	exporter := a.otelExporter
	a.mu.RUnlock()

	if exporter != nil {
		allMetrics := a.metricsAgg.Get()
		if err := exporter.ExportMetrics(ctx, allMetrics); err != nil {
			// Log error, put metrics back
			a.metricsAgg.Add(allMetrics)
		}
	}
}

// resourceExportLoop exports resources periodically.
func (a *UnifiedAgent) resourceExportLoop(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.ResourceExportInterval)
	defer ticker.Stop()

	// Initial export
	a.exportResources(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.exportResources(ctx)
		}
	}
}

// exportResources discovers and exports resources.
func (a *UnifiedAgent) exportResources(ctx context.Context) {
	resources, err := a.resourceExporter.ExportResources(ctx)
	if err != nil {
		// Log error
		return
	}

	// Resources are now available for querying
	_ = resources
}

// healthCheckLoop runs health checks periodically.
func (a *UnifiedAgent) healthCheckLoop(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.runHealthCheck(ctx)
		}
	}
}

// runHealthCheck runs a health check.
func (a *UnifiedAgent) runHealthCheck(ctx context.Context) {
	status, err := a.healthReporter.GetHealthStatus(ctx)
	if err != nil {
		// Log error
		return
	}

	// Health status is now available
	_ = status
}

// GetCloudMetadata returns current cloud metadata.
func (a *UnifiedAgent) GetCloudMetadata() (*CloudMetadata, error) {
	return a.cloudManager.GetMetadata()
}

// GetDiscoveredState returns current discovery state.
func (a *UnifiedAgent) GetDiscoveredState() *autodiscover.DiscoveredState {
	return a.discoveryEngine.GetState()
}

// GetResources returns discovered resources.
func (a *UnifiedAgent) GetResources(ctx context.Context) ([]Resource, error) {
	return a.cloudManager.DiscoverResources(ctx)
}

// GetMetrics returns current metrics.
func (a *UnifiedAgent) GetMetrics(ctx context.Context) ([]Metric, error) {
	return a.cloudManager.CollectMetrics(ctx)
}

// GetHealthStatus returns current health status.
func (a *UnifiedAgent) GetHealthStatus(ctx context.Context) (*HealthStatus, error) {
	return a.healthReporter.GetHealthStatus(ctx)
}

// TriggerDiscovery triggers an immediate discovery run.
func (a *UnifiedAgent) TriggerDiscovery(ctx context.Context) (*autodiscover.DiscoveredState, error) {
	return a.discoveryEngine.RunDiscovery(ctx)
}

// Integration provides a high-level integration API.
type Integration struct {
	agent *UnifiedAgent
}

// NewIntegration creates a new integration.
func NewIntegration(config UnifiedAgentConfig) *Integration {
	return &Integration{
		agent: NewUnifiedAgent(config),
	}
}

// Start starts the integration.
func (i *Integration) Start(ctx context.Context) error {
	return i.agent.Start(ctx)
}

// Stop stops the integration.
func (i *Integration) Stop(ctx context.Context) error {
	return i.agent.Stop(ctx)
}

// GetEnvironmentInfo returns comprehensive environment information.
func (i *Integration) GetEnvironmentInfo(ctx context.Context) (*EnvironmentInfo, error) {
	info := &EnvironmentInfo{
		Timestamp: time.Now(),
	}

	// Get cloud metadata
	if metadata, err := i.agent.GetCloudMetadata(); err == nil && metadata != nil {
		info.Cloud = metadata
	}

	// Get discovery state
	if state := i.agent.GetDiscoveredState(); state != nil {
		info.Discovery = state
	}

	// Get health status
	if health, err := i.agent.GetHealthStatus(ctx); err == nil {
		info.Health = health
	}

	return info, nil
}

// EnvironmentInfo represents comprehensive environment information.
type EnvironmentInfo struct {
	Timestamp time.Time                     `json:"timestamp"`
	Cloud     *CloudMetadata                `json:"cloud,omitempty"`
	Discovery *autodiscover.DiscoveredState `json:"discovery,omitempty"`
	Health    *HealthStatus                 `json:"health,omitempty"`
}

// ServiceRegistry maintains a registry of discovered services.
type ServiceRegistry struct {
	services map[string]ServiceEntry
	mu       sync.RWMutex
}

// ServiceEntry represents a registered service.
type ServiceEntry struct {
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Protocol     string            `json:"protocol"`
	Tags         map[string]string `json:"tags,omitempty"`
	Metadata     map[string]any    `json:"metadata,omitempty"`
	LastSeen     time.Time         `json:"last_seen"`
	HealthStatus string            `json:"health_status"`
}

// NewServiceRegistry creates a new service registry.
func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		services: make(map[string]ServiceEntry),
	}
}

// Register registers a service.
func (r *ServiceRegistry) Register(entry ServiceEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s:%d", entry.Name, entry.Host, entry.Port)
	entry.LastSeen = time.Now()
	r.services[key] = entry
}

// Deregister removes a service.
func (r *ServiceRegistry) Deregister(name, host string, port int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s:%d", name, host, port)
	delete(r.services, key)
}

// GetServices returns all registered services.
func (r *ServiceRegistry) GetServices() []ServiceEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	services := make([]ServiceEntry, 0, len(r.services))
	for _, entry := range r.services {
		services = append(services, entry)
	}
	return services
}

// GetServicesByType returns services by type.
func (r *ServiceRegistry) GetServicesByType(serviceType string) []ServiceEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	services := make([]ServiceEntry, 0)
	for _, entry := range r.services {
		if entry.Type == serviceType {
			services = append(services, entry)
		}
	}
	return services
}

// Cleanup removes stale services.
func (r *ServiceRegistry) Cleanup(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, entry := range r.services {
		if entry.LastSeen.Before(cutoff) {
			delete(r.services, key)
		}
	}
}
