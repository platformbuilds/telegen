// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package storage provides infrastructure storage metrics collection.
package storage

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/storage/dell"
	"github.com/platformbuilds/telegen/internal/storage/hpe"
	"github.com/platformbuilds/telegen/internal/storage/netapp"
	"github.com/platformbuilds/telegen/internal/storage/pure"
	"github.com/platformbuilds/telegen/internal/storagedef"
)

// Manager coordinates all storage collectors and exports metrics
type Manager struct {
	config     storagedef.Config
	collectors map[string]storagedef.StorageCollector
	exporter   storagedef.MetricExporter
	log        *slog.Logger

	mu       sync.RWMutex
	running  bool
	stopCh   chan struct{}
	wg       sync.WaitGroup
	lastRun  time.Time
	health   map[string]*storagedef.CollectorHealth
	healthMu sync.RWMutex
}

// NewManager creates a new storage metrics manager
func NewManager(cfg storagedef.Config, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "storage-manager")

	if cfg.CollectInterval == 0 {
		cfg.CollectInterval = 60 * time.Second
	}

	return &Manager{
		config:     cfg,
		collectors: make(map[string]storagedef.StorageCollector),
		log:        log,
		stopCh:     make(chan struct{}),
		health:     make(map[string]*storagedef.CollectorHealth),
	}, nil
}

// Start initializes all collectors and begins metric collection
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	m.log.Info("starting storage metrics manager",
		"collect_interval", m.config.CollectInterval,
		"enabled", m.config.Enabled,
	)

	if !m.config.Enabled {
		m.log.Info("storage metrics manager is disabled")
		return nil
	}

	// Initialize exporter
	if err := m.initExporter(ctx); err != nil {
		return fmt.Errorf("failed to initialize exporter: %w", err)
	}

	// Initialize Dell PowerStore collectors
	for _, cfg := range m.config.DellPowerStore {
		collector, err := dell.NewPowerStoreCollector(cfg, m.log)
		if err != nil {
			m.log.Error("failed to create Dell PowerStore collector",
				"name", cfg.Name,
				"error", err,
			)
			continue
		}

		if err := collector.Start(ctx); err != nil {
			m.log.Error("failed to start Dell PowerStore collector",
				"name", cfg.Name,
				"error", err,
			)
			continue
		}

		m.collectors[cfg.Name] = collector
		m.log.Info("initialized Dell PowerStore collector", "name", cfg.Name)
	}

	// Initialize HPE Primera collectors
	for _, cfg := range m.config.HPEPrimera {
		collector, err := hpe.NewPrimeraCollector(cfg, m.log)
		if err != nil {
			m.log.Error("failed to create HPE Primera collector",
				"name", cfg.Name,
				"error", err,
			)
			continue
		}

		if err := collector.Start(ctx); err != nil {
			m.log.Error("failed to start HPE Primera collector",
				"name", cfg.Name,
				"error", err,
			)
			continue
		}

		m.collectors[cfg.Name] = collector
		m.log.Info("initialized HPE Primera collector", "name", cfg.Name)
	}

	// Initialize Pure FlashArray collectors
	for _, cfg := range m.config.PureFlashArray {
		collector, err := pure.NewFlashArrayCollector(cfg, m.log)
		if err != nil {
			m.log.Error("failed to create Pure FlashArray collector",
				"name", cfg.Name,
				"error", err,
			)
			continue
		}

		if err := collector.Start(ctx); err != nil {
			m.log.Error("failed to start Pure FlashArray collector",
				"name", cfg.Name,
				"error", err,
			)
			continue
		}

		m.collectors[cfg.Name] = collector
		m.log.Info("initialized Pure FlashArray collector", "name", cfg.Name)
	}

	// Initialize NetApp ONTAP collectors
	for _, cfg := range m.config.NetAppONTAP {
		collector, err := netapp.NewONTAPCollector(cfg, m.log)
		if err != nil {
			m.log.Error("failed to create NetApp ONTAP collector",
				"name", cfg.Name,
				"error", err,
			)
			continue
		}

		if err := collector.Start(ctx); err != nil {
			m.log.Error("failed to start NetApp ONTAP collector",
				"name", cfg.Name,
				"error", err,
			)
			continue
		}

		m.collectors[cfg.Name] = collector
		m.log.Info("initialized NetApp ONTAP collector", "name", cfg.Name)
	}

	// Start the collection loop
	m.wg.Add(1)
	go m.collectLoop(ctx)

	m.running = true
	m.log.Info("storage metrics manager started",
		"collectors", len(m.collectors),
	)

	return nil
}

// Stop gracefully shuts down the manager and all collectors
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.log.Info("stopping storage metrics manager")

	// Signal stop
	close(m.stopCh)

	// Wait for collection loop to stop
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Stop all collectors
	for name, collector := range m.collectors {
		if err := collector.Stop(ctx); err != nil {
			m.log.Warn("error stopping collector",
				"name", name,
				"error", err,
			)
		}
	}

	// Stop exporter
	if m.exporter != nil {
		if err := m.exporter.Stop(ctx); err != nil {
			m.log.Warn("error stopping exporter", "error", err)
		}
	}

	m.running = false
	m.log.Info("storage metrics manager stopped")
	return nil
}

// initExporter initializes the OTLP exporter
func (m *Manager) initExporter(ctx context.Context) error {
	if !m.config.OTLP.Enabled {
		m.log.Debug("OTLP exporter is disabled")
		return nil
	}

	exporter, err := NewOTLPExporter(m.config.OTLP, m.log)
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	if err := exporter.Start(ctx); err != nil {
		return fmt.Errorf("failed to start OTLP exporter: %w", err)
	}

	m.exporter = exporter
	return nil
}

// collectLoop runs the periodic metric collection
func (m *Manager) collectLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CollectInterval)
	defer ticker.Stop()

	// Collect immediately on start
	m.collectAll(ctx)

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.collectAll(ctx)
		}
	}
}

// collectAll collects metrics from all collectors
func (m *Manager) collectAll(ctx context.Context) {
	m.mu.RLock()
	collectors := make(map[string]storagedef.StorageCollector, len(m.collectors))
	for k, v := range m.collectors {
		collectors[k] = v
	}
	m.mu.RUnlock()

	start := time.Now()
	var totalMetrics int

	for name, collector := range collectors {
		collectStart := time.Now()

		metrics, err := collector.CollectMetrics(ctx)
		if err != nil {
			m.log.Warn("failed to collect metrics",
				"collector", name,
				"error", err,
			)
			m.updateHealth(name, &storagedef.CollectorHealth{
				Status:       storagedef.HealthStatusUnhealthy,
				LastCheck:    time.Now(),
				LastError:    err,
				ResponseTime: time.Since(collectStart),
			})
			continue
		}

		// Update health
		m.updateHealth(name, &storagedef.CollectorHealth{
			Status:       storagedef.HealthStatusHealthy,
			LastCheck:    time.Now(),
			LastSuccess:  time.Now(),
			ResponseTime: time.Since(collectStart),
		})

		// Export metrics
		if m.exporter != nil && len(metrics) > 0 {
			if err := m.exporter.Export(ctx, metrics); err != nil {
				m.log.Warn("failed to export metrics",
					"collector", name,
					"error", err,
				)
			}
		}

		totalMetrics += len(metrics)
		m.log.Debug("collected metrics",
			"collector", name,
			"count", len(metrics),
			"duration", time.Since(collectStart),
		)
	}

	m.lastRun = time.Now()
	m.log.Info("collection cycle completed",
		"collectors", len(collectors),
		"metrics", totalMetrics,
		"duration", time.Since(start),
	)
}

// updateHealth updates the health status for a collector
func (m *Manager) updateHealth(name string, health *storagedef.CollectorHealth) {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()

	existing, ok := m.health[name]
	if ok && health.LastError != nil {
		health.ErrorCount = existing.ErrorCount + 1
	}
	m.health[name] = health
}

// GetHealth returns the health status of all collectors
func (m *Manager) GetHealth() map[string]*storagedef.CollectorHealth {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	result := make(map[string]*storagedef.CollectorHealth, len(m.health))
	for k, v := range m.health {
		result[k] = v
	}
	return result
}

// GetCollectorHealth returns the health status of a specific collector
func (m *Manager) GetCollectorHealth(name string) (*storagedef.CollectorHealth, bool) {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	h, ok := m.health[name]
	return h, ok
}

// RegisterCollector adds a new collector at runtime
func (m *Manager) RegisterCollector(collector storagedef.StorageCollector) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := collector.Name()
	if _, exists := m.collectors[name]; exists {
		return fmt.Errorf("collector %q already registered", name)
	}

	m.collectors[name] = collector
	m.log.Info("registered collector", "name", name, "vendor", collector.Vendor())
	return nil
}

// UnregisterCollector removes a collector at runtime
func (m *Manager) UnregisterCollector(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	collector, exists := m.collectors[name]
	if !exists {
		return fmt.Errorf("collector %q not found", name)
	}

	if err := collector.Stop(context.Background()); err != nil {
		m.log.Warn("error stopping collector during unregister",
			"name", name,
			"error", err,
		)
	}

	delete(m.collectors, name)
	m.log.Info("unregistered collector", "name", name)
	return nil
}

// ListCollectors returns a list of all registered collector names
func (m *Manager) ListCollectors() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.collectors))
	for name := range m.collectors {
		names = append(names, name)
	}
	return names
}

// IsRunning returns whether the manager is currently running
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// LastCollectionTime returns the time of the last collection cycle
func (m *Manager) LastCollectionTime() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRun
}
