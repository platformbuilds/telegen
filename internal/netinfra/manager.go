// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netinfra

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/netinfra/arista"
	"github.com/mirastacklabs-ai/telegen/internal/netinfra/cisco"
	"github.com/mirastacklabs-ai/telegen/internal/netinfra/types"
)

// Manager coordinates all network infrastructure collectors
type Manager struct {
	config     Config
	log        *slog.Logger
	collectors []types.Collector
	exporter   *Exporter

	metrics chan []*types.NetworkMetric
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex
	running bool
}

// Config holds network infrastructure manager configuration
type Config struct {
	// Enabled controls whether network infrastructure collection is active
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// CollectInterval is the default collection interval
	CollectInterval time.Duration `mapstructure:"collect_interval" yaml:"collect_interval"`
	// CloudVision holds Arista CloudVision configurations
	CloudVision []arista.Config `mapstructure:"cloudvision" yaml:"cloudvision"`
	// ACI holds Cisco ACI configurations
	ACI []cisco.Config `mapstructure:"aci" yaml:"aci"`
	// Exporter configuration
	Exporter ExporterConfig `mapstructure:"exporter" yaml:"exporter"`
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		CollectInterval: 30 * time.Second,
		Exporter:        DefaultExporterConfig(),
	}
}

// NewManager creates a new network infrastructure manager
func NewManager(cfg Config, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "netinfra")

	m := &Manager{
		config:     cfg,
		log:        log,
		collectors: make([]types.Collector, 0),
		metrics:    make(chan []*types.NetworkMetric, 1000),
	}

	// Create CloudVision collectors
	for _, cvpCfg := range cfg.CloudVision {
		collector, err := arista.NewCloudVisionCollector(cvpCfg, log)
		if err != nil {
			log.Warn("failed to create CloudVision collector", "name", cvpCfg.Name, "error", err)
			continue
		}
		m.collectors = append(m.collectors, collector)
		log.Info("created CloudVision collector", "name", cvpCfg.Name)
	}

	// Create ACI collectors
	for _, aciCfg := range cfg.ACI {
		collector, err := cisco.NewACICollector(aciCfg, log)
		if err != nil {
			log.Warn("failed to create ACI collector", "name", aciCfg.Name, "error", err)
			continue
		}
		m.collectors = append(m.collectors, collector)
		log.Info("created ACI collector", "name", aciCfg.Name)
	}

	// Create exporter
	var err error
	m.exporter, err = NewExporter(cfg.Exporter, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}

	return m, nil
}

// Start starts the network infrastructure manager
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	if !m.config.Enabled {
		m.log.Info("network infrastructure collection is disabled")
		return nil
	}

	m.ctx, m.cancel = context.WithCancel(ctx)

	m.log.Info("starting network infrastructure manager", "collectors", len(m.collectors))

	// Start exporter
	if err := m.exporter.Start(m.ctx); err != nil {
		return fmt.Errorf("failed to start exporter: %w", err)
	}

	// Start all collectors
	for _, collector := range m.collectors {
		if starter, ok := collector.(interface{ Start(context.Context) error }); ok {
			if err := starter.Start(m.ctx); err != nil {
				m.log.Warn("failed to start collector", "name", collector.Name(), "error", err)
			}
		}
	}

	// Start collection workers
	for _, collector := range m.collectors {
		m.wg.Add(1)
		go m.collectorWorker(collector)
	}

	// Start metrics distribution worker
	m.wg.Add(1)
	go m.distributeMetrics()

	m.running = true
	m.log.Info("network infrastructure manager started")
	return nil
}

// Stop stops the network infrastructure manager
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.log.Info("stopping network infrastructure manager")

	m.cancel()
	m.wg.Wait()

	// Stop all collectors
	for _, collector := range m.collectors {
		if err := collector.Close(); err != nil {
			m.log.Warn("failed to close collector", "name", collector.Name(), "error", err)
		}
	}

	// Stop exporter
	if err := m.exporter.Stop(context.Background()); err != nil {
		m.log.Warn("failed to stop exporter", "error", err)
	}

	close(m.metrics)

	m.running = false
	m.log.Info("network infrastructure manager stopped")
	return nil
}

// collectorWorker runs the collection loop for a single collector
func (m *Manager) collectorWorker(collector types.Collector) {
	defer m.wg.Done()

	interval := m.config.CollectInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Collect immediately on start
	m.collect(collector)

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.collect(collector)
		}
	}
}

// collect runs a single collection cycle for a collector
func (m *Manager) collect(collector types.Collector) {
	ctx, cancel := context.WithTimeout(m.ctx, m.config.CollectInterval)
	defer cancel()

	startTime := time.Now()
	metrics, err := collector.Collect(ctx)
	duration := time.Since(startTime)

	if err != nil {
		m.log.Warn("collection failed",
			"collector", collector.Name(),
			"error", err,
			"duration", duration,
		)
		return
	}

	m.log.Debug("collection completed",
		"collector", collector.Name(),
		"metrics", len(metrics),
		"duration", duration,
	)

	if len(metrics) > 0 {
		select {
		case m.metrics <- metrics:
		default:
			m.log.Warn("metrics channel full, dropping metrics",
				"collector", collector.Name(),
				"count", len(metrics),
			)
		}
	}
}

// distributeMetrics distributes collected metrics to the exporter
func (m *Manager) distributeMetrics() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case metrics, ok := <-m.metrics:
			if !ok {
				return
			}
			if err := m.exporter.Export(m.ctx, metrics); err != nil {
				m.log.Warn("failed to export metrics", "error", err, "count", len(metrics))
			}
		}
	}
}

// GetCollectors returns all collectors
func (m *Manager) GetCollectors() []types.Collector {
	m.mu.RLock()
	defer m.mu.RUnlock()

	collectors := make([]types.Collector, len(m.collectors))
	copy(collectors, m.collectors)
	return collectors
}

// AddCollector adds a new collector at runtime
func (m *Manager) AddCollector(collector types.Collector) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate
	for _, c := range m.collectors {
		if c.Name() == collector.Name() {
			return fmt.Errorf("collector already exists: %s", collector.Name())
		}
	}

	m.collectors = append(m.collectors, collector)

	// If running, start the collector worker
	if m.running {
		if starter, ok := collector.(interface{ Start(context.Context) error }); ok {
			if err := starter.Start(m.ctx); err != nil {
				return fmt.Errorf("failed to start collector: %w", err)
			}
		}
		m.wg.Add(1)
		go m.collectorWorker(collector)
	}

	m.log.Info("added collector", "name", collector.Name())
	return nil
}

// RemoveCollector removes a collector at runtime
func (m *Manager) RemoveCollector(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, c := range m.collectors {
		if c.Name() == name {
			// Close the collector
			if err := c.Close(); err != nil {
				m.log.Warn("failed to close collector", "name", name, "error", err)
			}

			// Remove from slice
			m.collectors = append(m.collectors[:i], m.collectors[i+1:]...)
			m.log.Info("removed collector", "name", name)
			return nil
		}
	}

	return fmt.Errorf("collector not found: %s", name)
}
