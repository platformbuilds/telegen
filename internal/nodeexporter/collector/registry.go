// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"fmt"
	"log/slog"
	"sync"
)

// CollectorFactory is a function that creates a new collector.
type CollectorFactory func(cfg CollectorConfig) (Collector, error)

// collectorInfo holds metadata about a registered collector.
type collectorInfo struct {
	factory        CollectorFactory
	defaultEnabled bool
}

// Registry manages collector registration and instantiation.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]collectorInfo
}

// NewRegistry creates a new collector registry.
func NewRegistry() *Registry {
	return &Registry{
		collectors: make(map[string]collectorInfo),
	}
}

// Register adds a collector factory to the registry.
func (r *Registry) Register(name string, defaultEnabled bool, factory CollectorFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors[name] = collectorInfo{
		factory:        factory,
		defaultEnabled: defaultEnabled,
	}
}

// IsDefaultEnabled returns whether a collector is enabled by default.
func (r *Registry) IsDefaultEnabled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if info, ok := r.collectors[name]; ok {
		return info.defaultEnabled
	}
	return false
}

// List returns all registered collector names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.collectors))
	for name := range r.collectors {
		names = append(names, name)
	}
	return names
}

// Create instantiates a collector by name.
func (r *Registry) Create(name string, cfg CollectorConfig) (Collector, error) {
	r.mu.RLock()
	info, ok := r.collectors[name]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown collector: %s", name)
	}

	return info.factory(cfg)
}

// CreateEnabled creates all enabled collectors.
func (r *Registry) CreateEnabled(
	cfg CollectorConfig,
	enabledChecker func(name string, defaultEnabled bool) bool,
	logger *slog.Logger,
) (map[string]Collector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	collectors := make(map[string]Collector)

	for name, info := range r.collectors {
		if !enabledChecker(name, info.defaultEnabled) {
			logger.Debug("collector disabled", "collector", name)
			continue
		}

		collectorCfg := cfg
		collectorCfg.Logger = logger.With("collector", name)

		collector, err := info.factory(collectorCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create collector %s: %w", name, err)
		}

		collectors[name] = collector
		logger.Debug("collector enabled", "collector", name)
	}

	return collectors, nil
}

// DefaultRegistry is the global collector registry.
var DefaultRegistry = NewRegistry()

// Register registers a collector with the default registry.
func Register(name string, defaultEnabled bool, factory CollectorFactory) {
	DefaultRegistry.Register(name, defaultEnabled, factory)
}
