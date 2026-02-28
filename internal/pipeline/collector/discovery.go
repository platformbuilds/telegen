// Service discovery provides dynamic target discovery for collector mode.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// DiscoveryConfig holds service discovery configuration.
type DiscoveryConfig struct {
	// Enabled controls service discovery.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// RefreshInterval is how often to refresh targets.
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`

	// Kubernetes discovery configuration.
	Kubernetes *K8sDiscoveryConfig `yaml:"kubernetes,omitempty" json:"kubernetes,omitempty"`

	// Consul discovery configuration.
	Consul *ConsulDiscoveryConfig `yaml:"consul,omitempty" json:"consul,omitempty"`

	// DNS-SD discovery configuration.
	DNS *DNSDiscoveryConfig `yaml:"dns,omitempty" json:"dns,omitempty"`

	// File-based discovery configuration.
	File *FileDiscoveryConfig `yaml:"file,omitempty" json:"file,omitempty"`
}

// DefaultDiscoveryConfig returns sensible defaults.
func DefaultDiscoveryConfig() DiscoveryConfig {
	return DiscoveryConfig{
		Enabled:         false,
		RefreshInterval: 30 * time.Second,
	}
}

// K8sDiscoveryConfig holds Kubernetes service discovery configuration.
type K8sDiscoveryConfig struct {
	// Enabled controls K8s discovery.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Namespaces to watch (empty means all).
	Namespaces []string `yaml:"namespaces,omitempty" json:"namespaces,omitempty"`

	// LabelSelector to filter services.
	LabelSelector string `yaml:"label_selector,omitempty" json:"label_selector,omitempty"`

	// AnnotationPrefix for discovering targets.
	AnnotationPrefix string `yaml:"annotation_prefix,omitempty" json:"annotation_prefix,omitempty"`

	// TargetPort to use for discovered services.
	TargetPort int `yaml:"target_port,omitempty" json:"target_port,omitempty"`

	// ServiceMonitor compatibility for Prometheus Operator.
	ServiceMonitor *ServiceMonitorConfig `yaml:"service_monitor,omitempty" json:"service_monitor,omitempty"`
}

// ServiceMonitorConfig holds ServiceMonitor compatibility configuration.
type ServiceMonitorConfig struct {
	// Enabled controls ServiceMonitor discovery.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Namespace to watch for ServiceMonitors (empty means all).
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`

	// LabelSelector to filter ServiceMonitors.
	LabelSelector string `yaml:"label_selector,omitempty" json:"label_selector,omitempty"`
}

// ConsulDiscoveryConfig holds Consul service discovery configuration.
type ConsulDiscoveryConfig struct {
	// Enabled controls Consul discovery.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Address of the Consul agent.
	Address string `yaml:"address" json:"address"`

	// Token for Consul ACL.
	Token string `yaml:"token,omitempty" json:"token,omitempty"`

	// Datacenter to query.
	Datacenter string `yaml:"datacenter,omitempty" json:"datacenter,omitempty"`

	// Services to discover (empty means all).
	Services []string `yaml:"services,omitempty" json:"services,omitempty"`

	// Tags to filter services.
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`

	// HealthyOnly returns only healthy services.
	HealthyOnly bool `yaml:"healthy_only" json:"healthy_only"`
}

// DNSDiscoveryConfig holds DNS-SD configuration.
type DNSDiscoveryConfig struct {
	// Enabled controls DNS discovery.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Names to resolve (SRV or A/AAAA records).
	Names []string `yaml:"names" json:"names"`

	// Type is the DNS query type: "SRV", "A", "AAAA".
	Type string `yaml:"type" json:"type"`

	// Port to use for discovered hosts (for A/AAAA records).
	Port int `yaml:"port,omitempty" json:"port,omitempty"`

	// RefreshInterval overrides the default refresh interval.
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty" json:"refresh_interval,omitempty"`
}

// FileDiscoveryConfig holds file-based discovery configuration.
type FileDiscoveryConfig struct {
	// Enabled controls file discovery.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Files to watch for target definitions.
	Files []string `yaml:"files" json:"files"`

	// RefreshInterval overrides the default refresh interval.
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty" json:"refresh_interval,omitempty"`
}

// DiscoveredTarget represents a discovered target.
type DiscoveredTarget struct {
	// Name is the target identifier.
	Name string `yaml:"name" json:"name"`

	// Address is the target address (host:port).
	Address string `yaml:"address" json:"address"`

	// Type is the target type: "snmp", "prometheus", "restapi", "storage", "netinfra".
	Type string `yaml:"type" json:"type"`

	// Labels are additional labels for the target.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Config holds type-specific configuration.
	Config map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`

	// DiscoveredAt is when this target was discovered.
	DiscoveredAt time.Time `yaml:"discovered_at" json:"discovered_at"`

	// Source is where this target came from.
	Source string `yaml:"source" json:"source"` // "kubernetes", "consul", "dns", "file"
}

// TargetHandler is called when targets are discovered or removed.
type TargetHandler func(added, removed []DiscoveredTarget)

// ServiceDiscovery manages dynamic target discovery.
type ServiceDiscovery struct {
	config   DiscoveryConfig
	log      *slog.Logger
	handlers []TargetHandler

	// Current targets
	targets map[string]DiscoveredTarget
	mu      sync.RWMutex

	// State
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
}

// NewServiceDiscovery creates a new service discovery manager.
func NewServiceDiscovery(config DiscoveryConfig, log *slog.Logger) (*ServiceDiscovery, error) {
	if log == nil {
		log = slog.Default()
	}

	if config.RefreshInterval == 0 {
		config.RefreshInterval = 30 * time.Second
	}

	return &ServiceDiscovery{
		config:   config,
		log:      log.With("component", "service-discovery"),
		handlers: make([]TargetHandler, 0),
		targets:  make(map[string]DiscoveredTarget),
	}, nil
}

// OnTargetChange registers a handler for target changes.
func (s *ServiceDiscovery) OnTargetChange(handler TargetHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers = append(s.handlers, handler)
}

// Start begins service discovery.
func (s *ServiceDiscovery) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	if !s.config.Enabled {
		s.log.Info("service discovery is disabled")
		return nil
	}

	s.ctx, s.cancel = context.WithCancel(ctx)
	s.running = true

	// Start discovery providers
	if s.config.Kubernetes != nil && s.config.Kubernetes.Enabled {
		s.wg.Add(1)
		go s.runK8sDiscovery()
	}

	if s.config.Consul != nil && s.config.Consul.Enabled {
		s.wg.Add(1)
		go s.runConsulDiscovery()
	}

	if s.config.DNS != nil && s.config.DNS.Enabled {
		s.wg.Add(1)
		go s.runDNSDiscovery()
	}

	if s.config.File != nil && s.config.File.Enabled {
		s.wg.Add(1)
		go s.runFileDiscovery()
	}

	s.log.Info("started service discovery",
		"refresh_interval", s.config.RefreshInterval,
	)

	return nil
}

// Stop stops service discovery.
func (s *ServiceDiscovery) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.cancel()
	s.running = false
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.log.Info("stopped service discovery")
	case <-ctx.Done():
		s.log.Warn("service discovery stop timeout")
	}

	return nil
}

// Targets returns current discovered targets.
func (s *ServiceDiscovery) Targets() []DiscoveredTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()

	targets := make([]DiscoveredTarget, 0, len(s.targets))
	for _, t := range s.targets {
		targets = append(targets, t)
	}
	return targets
}

// updateTargets updates discovered targets and notifies handlers.
func (s *ServiceDiscovery) updateTargets(source string, newTargets []DiscoveredTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Build map of new targets
	newMap := make(map[string]DiscoveredTarget)
	for _, t := range newTargets {
		key := fmt.Sprintf("%s:%s", source, t.Name)
		t.Source = source
		newMap[key] = t
	}

	// Find added and removed targets
	var added, removed []DiscoveredTarget

	// Check for new targets
	for key, t := range newMap {
		if _, exists := s.targets[key]; !exists {
			added = append(added, t)
		}
		s.targets[key] = t
	}

	// Check for removed targets
	for key, t := range s.targets {
		if t.Source == source {
			if _, exists := newMap[key]; !exists {
				removed = append(removed, t)
				delete(s.targets, key)
			}
		}
	}

	// Notify handlers
	if len(added) > 0 || len(removed) > 0 {
		for _, handler := range s.handlers {
			go handler(added, removed)
		}

		s.log.Info("targets updated",
			"source", source,
			"added", len(added),
			"removed", len(removed),
			"total", len(s.targets),
		)
	}
}

// runK8sDiscovery runs Kubernetes service discovery.
func (s *ServiceDiscovery) runK8sDiscovery() {
	defer s.wg.Done()

	s.log.Info("starting Kubernetes discovery")

	ticker := time.NewTicker(s.config.RefreshInterval)
	defer ticker.Stop()

	// Initial discovery
	s.discoverK8sTargets()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.discoverK8sTargets()
		}
	}
}

// discoverK8sTargets discovers targets from Kubernetes.
func (s *ServiceDiscovery) discoverK8sTargets() {
	// Check if running in K8s
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); os.IsNotExist(err) {
		s.log.Debug("not running in Kubernetes, skipping K8s discovery")
		return
	}

	// In a real implementation, this would use the K8s client
	// For now, we create mock targets
	targets := []DiscoveredTarget{
		{
			Name:         "prometheus-node-exporter",
			Address:      "10.0.0.1:9100",
			Type:         "prometheus",
			Labels:       map[string]string{"namespace": "monitoring", "service": "node-exporter"},
			DiscoveredAt: time.Now(),
		},
		{
			Name:         "prometheus-kube-state-metrics",
			Address:      "10.0.0.2:8080",
			Type:         "prometheus",
			Labels:       map[string]string{"namespace": "monitoring", "service": "kube-state-metrics"},
			DiscoveredAt: time.Now(),
		},
	}

	s.updateTargets("kubernetes", targets)
}

// runConsulDiscovery runs Consul service discovery.
func (s *ServiceDiscovery) runConsulDiscovery() {
	defer s.wg.Done()

	if s.config.Consul == nil {
		return
	}

	s.log.Info("starting Consul discovery",
		"address", s.config.Consul.Address,
	)

	ticker := time.NewTicker(s.config.RefreshInterval)
	defer ticker.Stop()

	// Initial discovery
	s.discoverConsulTargets()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.discoverConsulTargets()
		}
	}
}

// discoverConsulTargets discovers targets from Consul.
func (s *ServiceDiscovery) discoverConsulTargets() {
	if s.config.Consul == nil {
		return
	}

	// In a real implementation, this would use the Consul API client
	// For now, we create mock targets
	targets := []DiscoveredTarget{
		{
			Name:         "redis-primary",
			Address:      "redis-primary.service.consul:6379",
			Type:         "prometheus",
			Labels:       map[string]string{"service": "redis", "role": "primary"},
			DiscoveredAt: time.Now(),
		},
	}

	s.updateTargets("consul", targets)
}

// runDNSDiscovery runs DNS-SD discovery.
func (s *ServiceDiscovery) runDNSDiscovery() {
	defer s.wg.Done()

	if s.config.DNS == nil {
		return
	}

	interval := s.config.DNS.RefreshInterval
	if interval == 0 {
		interval = s.config.RefreshInterval
	}

	s.log.Info("starting DNS discovery",
		"names", s.config.DNS.Names,
		"type", s.config.DNS.Type,
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial discovery
	s.discoverDNSTargets()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.discoverDNSTargets()
		}
	}
}

// discoverDNSTargets discovers targets via DNS.
func (s *ServiceDiscovery) discoverDNSTargets() {
	if s.config.DNS == nil {
		return
	}

	var targets []DiscoveredTarget

	// In a real implementation, this would use net.LookupSRV or net.LookupHost
	// For now, we create mock targets based on configured names
	for _, name := range s.config.DNS.Names {
		port := s.config.DNS.Port
		if port == 0 {
			port = 9090
		}

		targets = append(targets, DiscoveredTarget{
			Name:         name,
			Address:      fmt.Sprintf("%s:%d", name, port),
			Type:         "prometheus",
			Labels:       map[string]string{"dns_name": name},
			DiscoveredAt: time.Now(),
		})
	}

	s.updateTargets("dns", targets)
}

// runFileDiscovery runs file-based discovery.
func (s *ServiceDiscovery) runFileDiscovery() {
	defer s.wg.Done()

	if s.config.File == nil {
		return
	}

	interval := s.config.File.RefreshInterval
	if interval == 0 {
		interval = s.config.RefreshInterval
	}

	s.log.Info("starting file discovery",
		"files", s.config.File.Files,
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial discovery
	s.discoverFileTargets()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.discoverFileTargets()
		}
	}
}

// discoverFileTargets discovers targets from files.
func (s *ServiceDiscovery) discoverFileTargets() {
	if s.config.File == nil {
		return
	}

	var allTargets []DiscoveredTarget

	for _, file := range s.config.File.Files {
		targets, err := s.loadTargetsFromFile(file)
		if err != nil {
			s.log.Warn("failed to load targets from file",
				"file", file,
				"error", err,
			)
			continue
		}
		allTargets = append(allTargets, targets...)
	}

	s.updateTargets("file", allTargets)
}

// FileTargets represents the structure of a targets file.
type FileTargets struct {
	Targets []DiscoveredTarget `yaml:"targets" json:"targets"`
}

// loadTargetsFromFile loads targets from a YAML file.
func (s *ServiceDiscovery) loadTargetsFromFile(file string) ([]DiscoveredTarget, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var ft FileTargets
	if err := yaml.Unmarshal(data, &ft); err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	// Set discovery time
	now := time.Now()
	for i := range ft.Targets {
		ft.Targets[i].DiscoveredAt = now
	}

	return ft.Targets, nil
}

// TargetCount returns the number of discovered targets.
func (s *ServiceDiscovery) TargetCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.targets)
}

// TargetsByType returns targets filtered by type.
func (s *ServiceDiscovery) TargetsByType(targetType string) []DiscoveredTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var targets []DiscoveredTarget
	for _, t := range s.targets {
		if t.Type == targetType {
			targets = append(targets, t)
		}
	}
	return targets
}

// TargetsBySource returns targets filtered by discovery source.
func (s *ServiceDiscovery) TargetsBySource(source string) []DiscoveredTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var targets []DiscoveredTarget
	for _, t := range s.targets {
		if t.Source == source {
			targets = append(targets, t)
		}
	}
	return targets
}
