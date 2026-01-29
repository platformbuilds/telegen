// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package pipeline provides the signal processing pipeline for Telegen.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/agent/memory"
	"github.com/platformbuilds/telegen/internal/exporters"
	"github.com/platformbuilds/telegen/internal/selftelemetry"
	"github.com/platformbuilds/telegen/internal/sigdef"
)

// SignalType is an alias to sigdef.SignalType for backwards compatibility
type SignalType = sigdef.SignalType

// Signal type constants - re-exported from sigdef
const (
	SignalTraces   = sigdef.SignalTraces
	SignalMetrics  = sigdef.SignalMetrics
	SignalLogs     = sigdef.SignalLogs
	SignalProfiles = sigdef.SignalProfiles
)

// Config holds pipeline configuration
type Config struct {
	// Per-signal pipeline configurations
	Traces   SignalPipelineConfig `mapstructure:"traces"`
	Metrics  SignalPipelineConfig `mapstructure:"metrics"`
	Logs     SignalPipelineConfig `mapstructure:"logs"`
	Profiles SignalPipelineConfig `mapstructure:"profiles"`

	// eBPF configuration (for agent mode)
	EBPF EBPFPipelineConfig `mapstructure:"ebpf"`

	// SNMP configuration (for collector mode)
	SNMP SNMPPipelineConfig `mapstructure:"snmp"`

	// Profiling configuration
	Profiling ProfilingConfig `mapstructure:"profiling"`

	// BatchSize for signal batching
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval for periodic flushing
	FlushInterval time.Duration `mapstructure:"flush_interval"`
}

// SignalPipelineConfig holds per-signal configuration
type SignalPipelineConfig struct {
	Enabled    bool              `mapstructure:"enabled"`
	QueueSize  int               `mapstructure:"queue_size"`
	Processors []ProcessorConfig `mapstructure:"processors"`
}

// ProcessorConfig holds processor configuration
type ProcessorConfig struct {
	Type   string                 `mapstructure:"type"`
	Config map[string]interface{} `mapstructure:"config"`
}

// EBPFPipelineConfig holds eBPF-specific configuration
type EBPFPipelineConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// SNMPPipelineConfig holds SNMP-specific configuration
type SNMPPipelineConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// ProfilingConfig holds profiling configuration
type ProfilingConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

// DefaultConfig returns default pipeline configuration
func DefaultConfig() Config {
	return Config{
		Traces: SignalPipelineConfig{
			Enabled:   true,
			QueueSize: 10000,
		},
		Metrics: SignalPipelineConfig{
			Enabled:   true,
			QueueSize: 10000,
		},
		Logs: SignalPipelineConfig{
			Enabled:   true,
			QueueSize: 10000,
		},
		Profiles: SignalPipelineConfig{
			Enabled:   false,
			QueueSize: 1000,
		},
		EBPF: EBPFPipelineConfig{
			Enabled: true,
		},
		BatchSize:     1000,
		FlushInterval: 5 * time.Second,
	}
}

// Manager orchestrates all signal pipelines
type Manager struct {
	cfg          Config
	log          *slog.Logger
	st           *selftelemetry.Metrics
	exporterReg  *exporters.Registry
	memoryBudget *memory.Budget

	// Signal-specific routers
	tracesRouter   *Router
	metricsRouter  *Router
	logsRouter     *Router
	profilesRouter *Router

	// Processor chains
	processors map[SignalType]*ProcessorChain

	// Lifecycle
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewManager creates a new pipeline manager
func NewManager(
	cfg Config,
	exporterReg *exporters.Registry,
	memoryBudget *memory.Budget,
	log *slog.Logger,
	st *selftelemetry.Metrics,
) (*Manager, error) {
	m := &Manager{
		cfg:          cfg,
		log:          log.With("component", "pipeline_manager"),
		st:           st,
		exporterReg:  exporterReg,
		memoryBudget: memoryBudget,
		processors:   make(map[SignalType]*ProcessorChain),
		stopCh:       make(chan struct{}),
	}

	// Initialize processor chains for each signal type
	if cfg.Traces.Enabled {
		chain, err := NewProcessorChain(SignalTraces, cfg.Traces.Processors, log, st)
		if err != nil {
			return nil, fmt.Errorf("failed to create traces processor chain: %w", err)
		}
		m.processors[SignalTraces] = chain
		m.tracesRouter = NewRouter(SignalTraces, cfg.Traces.QueueSize, chain, exporterReg, log, st)
	}

	if cfg.Metrics.Enabled {
		chain, err := NewProcessorChain(SignalMetrics, cfg.Metrics.Processors, log, st)
		if err != nil {
			return nil, fmt.Errorf("failed to create metrics processor chain: %w", err)
		}
		m.processors[SignalMetrics] = chain
		m.metricsRouter = NewRouter(SignalMetrics, cfg.Metrics.QueueSize, chain, exporterReg, log, st)
	}

	if cfg.Logs.Enabled {
		chain, err := NewProcessorChain(SignalLogs, cfg.Logs.Processors, log, st)
		if err != nil {
			return nil, fmt.Errorf("failed to create logs processor chain: %w", err)
		}
		m.processors[SignalLogs] = chain
		m.logsRouter = NewRouter(SignalLogs, cfg.Logs.QueueSize, chain, exporterReg, log, st)
	}

	if cfg.Profiles.Enabled {
		chain, err := NewProcessorChain(SignalProfiles, cfg.Profiles.Processors, log, st)
		if err != nil {
			return nil, fmt.Errorf("failed to create profiles processor chain: %w", err)
		}
		m.processors[SignalProfiles] = chain
		m.profilesRouter = NewRouter(SignalProfiles, cfg.Profiles.QueueSize, chain, exporterReg, log, st)
	}

	return m, nil
}

// Start initializes and starts all pipelines
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("pipeline manager already running")
	}

	m.log.Info("starting pipeline manager")

	// Start routers
	if m.tracesRouter != nil {
		if err := m.tracesRouter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start traces router: %w", err)
		}
	}
	if m.metricsRouter != nil {
		if err := m.metricsRouter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start metrics router: %w", err)
		}
	}
	if m.logsRouter != nil {
		if err := m.logsRouter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start logs router: %w", err)
		}
	}
	if m.profilesRouter != nil {
		if err := m.profilesRouter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start profiles router: %w", err)
		}
	}

	m.running = true
	m.log.Info("pipeline manager started")
	return nil
}

// Stop gracefully shuts down all pipelines
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.log.Info("stopping pipeline manager")
	close(m.stopCh)

	var errs []error

	// Stop routers (in reverse order of start)
	if m.profilesRouter != nil {
		if err := m.profilesRouter.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if m.logsRouter != nil {
		if err := m.logsRouter.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if m.metricsRouter != nil {
		if err := m.metricsRouter.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if m.tracesRouter != nil {
		if err := m.tracesRouter.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	m.wg.Wait()
	m.running = false
	m.log.Info("pipeline manager stopped")

	if len(errs) > 0 {
		return fmt.Errorf("pipeline shutdown errors: %v", errs)
	}
	return nil
}

// TracesRouter returns the traces router
func (m *Manager) TracesRouter() *Router {
	return m.tracesRouter
}

// MetricsRouter returns the metrics router
func (m *Manager) MetricsRouter() *Router {
	return m.metricsRouter
}

// LogsRouter returns the logs router
func (m *Manager) LogsRouter() *Router {
	return m.logsRouter
}

// ProfilesRouter returns the profiles router
func (m *Manager) ProfilesRouter() *Router {
	return m.profilesRouter
}

// Stats returns pipeline statistics
func (m *Manager) Stats() PipelineStats {
	stats := PipelineStats{
		Pipelines: make(map[SignalType]SignalStats),
	}

	if m.tracesRouter != nil {
		stats.Pipelines[SignalTraces] = m.tracesRouter.Stats()
	}
	if m.metricsRouter != nil {
		stats.Pipelines[SignalMetrics] = m.metricsRouter.Stats()
	}
	if m.logsRouter != nil {
		stats.Pipelines[SignalLogs] = m.logsRouter.Stats()
	}
	if m.profilesRouter != nil {
		stats.Pipelines[SignalProfiles] = m.profilesRouter.Stats()
	}

	return stats
}

// PipelineStats holds overall pipeline statistics
type PipelineStats struct {
	Pipelines map[SignalType]SignalStats
}

// SignalStats holds statistics for a single signal type
type SignalStats struct {
	QueueSize   int
	QueueCap    int
	Received    int64
	Processed   int64
	Dropped     int64
	Exported    int64
	ExportError int64
}
