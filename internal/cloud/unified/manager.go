package unified

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// CloudManager orchestrates cloud provider detection, metadata collection,
// and resource discovery across all supported cloud platforms.
type CloudManager struct {
	providers      []CloudProvider
	activeProvider CloudProvider
	metadata       *CloudMetadata
	resources      []Resource

	config Config
	mu     sync.RWMutex
	logger *slog.Logger

	// State management
	started   bool
	stopCh    chan struct{}
	stoppedWg sync.WaitGroup

	// Callbacks for state changes
	onProviderDetected func(CloudProvider, *CloudMetadata)
	onResourceChange   func([]Resource)
	onMetricsCollected func([]Metric)
}

// NewCloudManager creates a new CloudManager with the given configuration.
// Providers must be registered separately using RegisterProvider.
func NewCloudManager(config Config, logger *slog.Logger) *CloudManager {
	if logger == nil {
		logger = slog.Default()
	}
	if err := config.Validate(); err != nil {
		logger.Warn("invalid cloud config, using defaults", "error", err)
		config = DefaultConfig()
	}

	return &CloudManager{
		providers: make([]CloudProvider, 0),
		config:    config,
		logger:    logger.With("component", "cloud-manager"),
		stopCh:    make(chan struct{}),
	}
}

// RegisterProvider adds a cloud provider to the manager.
// Providers are tried in priority order during detection.
func (cm *CloudManager) RegisterProvider(provider CloudProvider) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.providers = append(cm.providers, provider)

	// Sort by priority (lower = higher priority)
	sort.Slice(cm.providers, func(i, j int) bool {
		return cm.providers[i].Priority() < cm.providers[j].Priority()
	})
}

// OnProviderDetected sets a callback for when a provider is detected.
func (cm *CloudManager) OnProviderDetected(fn func(CloudProvider, *CloudMetadata)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.onProviderDetected = fn
}

// OnResourceChange sets a callback for when resources change.
func (cm *CloudManager) OnResourceChange(fn func([]Resource)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.onResourceChange = fn
}

// OnMetricsCollected sets a callback for when metrics are collected.
func (cm *CloudManager) OnMetricsCollected(fn func([]Metric)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.onMetricsCollected = fn
}

// Start begins cloud detection and continuous collection.
func (cm *CloudManager) Start(ctx context.Context) error {
	cm.mu.Lock()
	if cm.started {
		cm.mu.Unlock()
		return fmt.Errorf("cloud manager already started")
	}
	cm.started = true
	cm.mu.Unlock()

	cm.logger.Info("starting cloud manager", "auto_detect", cm.config.AutoDetect)

	// Run initial detection
	if cm.config.AutoDetect {
		if err := cm.detectProvider(ctx); err != nil {
			cm.logger.Warn("initial cloud detection failed", "error", err)
		}
	}

	// Start background loops
	if cm.config.CollectMetrics {
		cm.stoppedWg.Add(1)
		go cm.metricsLoop(ctx)
	}

	if cm.config.DiscoverResources {
		cm.stoppedWg.Add(1)
		go cm.resourceLoop(ctx)
	}

	// Re-detect periodically (for hybrid/dynamic environments)
	if cm.config.AutoDetect && cm.config.DetectionInterval > 0 {
		cm.stoppedWg.Add(1)
		go cm.redetectLoop(ctx)
	}

	return nil
}

// Stop gracefully shuts down the cloud manager.
func (cm *CloudManager) Stop() {
	cm.mu.Lock()
	if !cm.started {
		cm.mu.Unlock()
		return
	}
	cm.started = false
	cm.mu.Unlock()

	close(cm.stopCh)
	cm.stoppedWg.Wait()
	cm.logger.Info("cloud manager stopped")
}

// detectProvider tries each provider in priority order.
func (cm *CloudManager) detectProvider(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, cm.config.DetectionTimeout)
	defer cancel()

	cm.mu.RLock()
	providers := make([]CloudProvider, len(cm.providers))
	copy(providers, cm.providers)
	cm.mu.RUnlock()

	if len(providers) == 0 {
		cm.logger.Warn("no cloud providers registered")
		return nil
	}

	// Try detection in parallel with priority ordering
	type detectionResult struct {
		provider CloudProvider
		metadata *CloudMetadata
		priority int
		err      error
	}

	results := make(chan detectionResult, len(providers))
	var wg sync.WaitGroup

	for _, provider := range providers {
		wg.Add(1)
		go func(p CloudProvider) {
			defer wg.Done()

			detected, err := p.Detect(ctx)
			if err != nil {
				cm.logger.Debug("provider detection error",
					"provider", p.Name(),
					"error", err)
				return
			}

			if !detected {
				return
			}

			// Provider detected, get metadata
			metadata, err := p.GetMetadata(ctx)
			if err != nil {
				cm.logger.Warn("failed to get metadata from detected provider",
					"provider", p.Name(),
					"error", err)
				return
			}

			results <- detectionResult{
				provider: p,
				metadata: metadata,
				priority: p.Priority(),
			}
		}(provider)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all successful detections
	var detected []detectionResult
	for r := range results {
		detected = append(detected, r)
	}

	if len(detected) == 0 {
		cm.logger.Info("no cloud provider detected")
		return nil
	}

	// Sort by priority and pick highest (lowest number)
	sort.Slice(detected, func(i, j int) bool {
		return detected[i].priority < detected[j].priority
	})

	winner := detected[0]
	cm.logger.Info("cloud provider detected",
		"provider", winner.provider.Name(),
		"type", winner.provider.Type(),
		"region", winner.metadata.Region,
		"instance_id", winner.metadata.InstanceID)

	cm.mu.Lock()
	cm.activeProvider = winner.provider
	cm.metadata = winner.metadata
	callback := cm.onProviderDetected
	cm.mu.Unlock()

	if callback != nil {
		callback(winner.provider, winner.metadata)
	}

	return nil
}

// metricsLoop periodically collects metrics from the active provider.
func (cm *CloudManager) metricsLoop(ctx context.Context) {
	defer cm.stoppedWg.Done()

	ticker := time.NewTicker(cm.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.collectMetrics(ctx)
		}
	}
}

// collectMetrics gathers metrics from the active provider.
func (cm *CloudManager) collectMetrics(ctx context.Context) {
	cm.mu.RLock()
	provider := cm.activeProvider
	callback := cm.onMetricsCollected
	cm.mu.RUnlock()

	if provider == nil {
		return
	}

	metrics, err := provider.CollectMetrics(ctx)
	if err != nil {
		cm.logger.Warn("failed to collect metrics",
			"provider", provider.Name(),
			"error", err)
		return
	}

	if callback != nil && len(metrics) > 0 {
		callback(metrics)
	}
}

// resourceLoop periodically discovers resources from the active provider.
func (cm *CloudManager) resourceLoop(ctx context.Context) {
	defer cm.stoppedWg.Done()

	// Initial discovery
	cm.discoverResources(ctx)

	ticker := time.NewTicker(cm.config.ResourceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.discoverResources(ctx)
		}
	}
}

// discoverResources finds resources from the active provider.
func (cm *CloudManager) discoverResources(ctx context.Context) {
	cm.mu.RLock()
	provider := cm.activeProvider
	cm.mu.RUnlock()

	if provider == nil {
		return
	}

	resources, err := provider.DiscoverResources(ctx)
	if err != nil {
		cm.logger.Warn("failed to discover resources",
			"provider", provider.Name(),
			"error", err)
		return
	}

	cm.mu.Lock()
	cm.resources = resources
	callback := cm.onResourceChange
	cm.mu.Unlock()

	if callback != nil {
		callback(resources)
	}
}

// DiscoverResources is the public API for resource discovery.
func (cm *CloudManager) DiscoverResources(ctx context.Context) ([]Resource, error) {
	cm.mu.RLock()
	provider := cm.activeProvider
	cm.mu.RUnlock()

	if provider == nil {
		return nil, nil
	}

	return provider.DiscoverResources(ctx)
}

// redetectLoop periodically re-runs provider detection.
func (cm *CloudManager) redetectLoop(ctx context.Context) {
	defer cm.stoppedWg.Done()

	ticker := time.NewTicker(cm.config.DetectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopCh:
			return
		case <-ticker.C:
			if err := cm.detectProvider(ctx); err != nil {
				cm.logger.Warn("re-detection failed", "error", err)
			}
		}
	}
}

// GetActiveProvider returns the currently active cloud provider.
func (cm *CloudManager) GetActiveProvider() CloudProvider {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.activeProvider
}

// GetMetadata returns the active cloud metadata.
func (cm *CloudManager) GetMetadata() *CloudMetadata {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.metadata
}

// GetResources returns discovered resources.
func (cm *CloudManager) GetResources() []Resource {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	result := make([]Resource, len(cm.resources))
	copy(result, cm.resources)
	return result
}

// GetResourcesByType returns resources of a specific type.
func (cm *CloudManager) GetResourcesByType(resourceType ResourceType) []Resource {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var result []Resource
	for _, r := range cm.resources {
		if r.Type == resourceType {
			result = append(result, r)
		}
	}
	return result
}

// ToOTelAttributes converts metadata to OpenTelemetry resource attributes.
func (cm *CloudManager) ToOTelAttributes() []attribute.KeyValue {
	cm.mu.RLock()
	meta := cm.metadata
	cm.mu.RUnlock()

	if meta == nil {
		return nil
	}

	attrs := []attribute.KeyValue{
		semconv.CloudProviderKey.String(meta.Provider),
		semconv.CloudRegionKey.String(meta.Region),
		semconv.CloudAvailabilityZoneKey.String(meta.AvailabilityZone),
		semconv.CloudAccountIDKey.String(meta.AccountID),
		semconv.HostIDKey.String(meta.InstanceID),
		semconv.HostNameKey.String(meta.Hostname),
		semconv.HostTypeKey.String(meta.InstanceType),
	}

	// Add cloud-specific platform attributes
	switch meta.Provider {
	case "aws":
		attrs = append(attrs, semconv.CloudPlatformAWSEC2)
	case "gcp":
		attrs = append(attrs, semconv.CloudPlatformGCPComputeEngine)
	case "azure":
		attrs = append(attrs, semconv.CloudPlatformAzureVM)
	case "openstack":
		attrs = append(attrs, semconv.CloudPlatformKey.String("openstack_nova"))
	case "vmware":
		attrs = append(attrs, semconv.CloudPlatformKey.String("vmware_vsphere"))
	case "nutanix":
		attrs = append(attrs, semconv.CloudPlatformKey.String("nutanix_ahv"))
	case "onprem":
		attrs = append(attrs, semconv.CloudPlatformKey.String("on_premises"))
	}

	// Add optional attributes
	if meta.PublicIP != "" {
		attrs = append(attrs, attribute.String("host.ip.public", meta.PublicIP))
	}
	if meta.PrivateIP != "" {
		attrs = append(attrs, attribute.String("host.ip.private", meta.PrivateIP))
	}
	if meta.ImageID != "" {
		attrs = append(attrs, semconv.HostImageIDKey.String(meta.ImageID))
	}
	if meta.ImageName != "" {
		attrs = append(attrs, semconv.HostImageNameKey.String(meta.ImageName))
	}
	if meta.Hypervisor != "" {
		attrs = append(attrs, attribute.String("cloud.hypervisor", meta.Hypervisor))
	}
	if meta.Architecture != "" {
		attrs = append(attrs, semconv.HostArchKey.String(meta.Architecture))
	}

	// Add datacenter for private clouds
	if meta.Datacenter != "" {
		attrs = append(attrs, attribute.String("cloud.datacenter", meta.Datacenter))
	}
	if meta.ClusterName != "" {
		attrs = append(attrs, attribute.String("cloud.cluster.name", meta.ClusterName))
	}
	if meta.HostName != "" && meta.HostName != meta.Hostname {
		attrs = append(attrs, attribute.String("cloud.host.name", meta.HostName))
	}

	return attrs
}

// IsDetected returns true if a cloud provider has been detected.
func (cm *CloudManager) IsDetected() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.activeProvider != nil
}

// ProviderName returns the name of the active provider, or empty string.
func (cm *CloudManager) ProviderName() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.activeProvider == nil {
		return ""
	}
	return cm.activeProvider.Name()
}

// ProviderType returns the type of the active provider.
func (cm *CloudManager) ProviderType() CloudType {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.activeProvider == nil {
		return CloudTypeUnknown
	}
	return cm.activeProvider.Type()
}

// HealthCheck runs a health check on the active provider.
func (cm *CloudManager) HealthCheck(ctx context.Context) HealthCheckResult {
	cm.mu.RLock()
	provider := cm.activeProvider
	cm.mu.RUnlock()

	if provider == nil {
		return HealthCheckResult{
			Healthy:   false,
			Message:   "no active provider",
			LastCheck: time.Now(),
		}
	}

	return provider.HealthCheck(ctx)
}

// Refresh forces immediate re-detection and metadata refresh.
func (cm *CloudManager) Refresh(ctx context.Context) error {
	if err := cm.detectProvider(ctx); err != nil {
		return fmt.Errorf("detection failed: %w", err)
	}

	cm.discoverResources(ctx)
	return nil
}
