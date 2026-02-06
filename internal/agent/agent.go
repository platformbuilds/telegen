// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package agent provides the core Telegen agent implementation.
// It orchestrates eBPF tracers, signal pipelines, and exporters.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/platformbuilds/telegen/internal/agent/memory"
	"github.com/platformbuilds/telegen/internal/exporters"
	"github.com/platformbuilds/telegen/internal/pipeline"
	"github.com/platformbuilds/telegen/internal/profiler"
	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// Mode represents the operating mode of the agent
type Mode string

const (
	// ModeAgent is for local host/container observability with eBPF
	ModeAgent Mode = "agent"
	// ModeCollector is for remote device monitoring via protocols like SNMP
	ModeCollector Mode = "collector"
	// ModeUnified combines both agent and collector capabilities
	ModeUnified Mode = "unified"
)

// State represents the current state of the agent
type State int32

const (
	StateCreated State = iota
	StateStarting
	StateRunning
	StateStopping
	StateStopped
)

func (s State) String() string {
	switch s {
	case StateCreated:
		return "created"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Config holds the agent configuration
type Config struct {
	// Mode specifies whether to run as agent, collector, or unified
	Mode Mode `mapstructure:"mode"`

	// ServiceName is the name of this telegen instance
	ServiceName string `mapstructure:"service_name"`

	// InstanceID uniquely identifies this agent instance
	InstanceID string `mapstructure:"instance_id"`

	// ListenAddress for health/debug endpoints
	ListenAddress string `mapstructure:"listen_address"`

	// ShutdownTimeout is the max time to wait for graceful shutdown
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`

	// Pipeline configuration
	Pipeline pipeline.Config `mapstructure:"pipeline"`

	// Exporter configuration
	Exporters exporters.Config `mapstructure:"exporters"`

	// Profiling configuration
	Profiling profiler.RunnerConfig `mapstructure:"profiling"`

	// Memory budget configuration
	Memory memory.Config `mapstructure:"memory"`

	// DebugEnabled enables debug endpoints
	DebugEnabled bool `mapstructure:"debug_enabled"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	hostname, _ := os.Hostname()
	return Config{
		Mode:            ModeAgent,
		ServiceName:     "telegen",
		InstanceID:      hostname,
		ListenAddress:   ":19090",
		ShutdownTimeout: 30 * time.Second,
		Pipeline:        pipeline.DefaultConfig(),
		Exporters:       exporters.DefaultConfig(),
		Profiling:       profiler.DefaultRunnerConfig(),
		Memory:          memory.DefaultConfig(),
		DebugEnabled:    false,
	}
}

// Agent is the main Telegen agent that orchestrates all components
type Agent struct {
	cfg     Config
	log     *slog.Logger
	state   atomic.Int32
	stateMu sync.RWMutex //nolint:unused // reserved for future state transitions

	// Core components
	pipelineManager *pipeline.Manager
	exporterReg     *exporters.Registry
	memoryBudget    *memory.Budget
	selfTelemetry   *selftelemetry.Metrics
	profilerRunner  *profiler.Runner

	// HTTP server for health/debug
	httpServer *http.Server
	httpMux    *http.ServeMux

	// Lifecycle
	startTime time.Time
	stopOnce  sync.Once
	done      chan struct{}
}

// New creates a new Agent with the given configuration
func New(cfg Config, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}

	// Validate mode
	switch cfg.Mode {
	case ModeAgent, ModeCollector, ModeUnified:
		// valid
	case "":
		cfg.Mode = ModeAgent
	default:
		return nil, fmt.Errorf("invalid mode: %s", cfg.Mode)
	}

	a := &Agent{
		cfg:  cfg,
		log:  log.With("component", "agent"),
		done: make(chan struct{}),
	}
	a.state.Store(int32(StateCreated))

	// Initialize HTTP mux for health/debug endpoints
	a.httpMux = http.NewServeMux()

	return a, nil
}

// Start initializes and starts all agent components
func (a *Agent) Start(ctx context.Context) error {
	if !a.state.CompareAndSwap(int32(StateCreated), int32(StateStarting)) {
		return errors.New("agent already started or stopped")
	}

	a.startTime = time.Now()
	a.log.Info("starting agent",
		"mode", a.cfg.Mode,
		"service", a.cfg.ServiceName,
		"instance", a.cfg.InstanceID,
	)

	// Initialize self-telemetry
	var err error
	a.selfTelemetry, err = selftelemetry.NewMetrics("telegen")
	if err != nil {
		return fmt.Errorf("failed to initialize self-telemetry: %w", err)
	}

	// Initialize memory budget manager
	a.memoryBudget, err = memory.NewBudget(a.cfg.Memory, a.log, a.selfTelemetry)
	if err != nil {
		return fmt.Errorf("failed to initialize memory budget: %w", err)
	}

	// Initialize exporter registry
	a.exporterReg, err = exporters.NewRegistry(a.cfg.Exporters, a.log, a.selfTelemetry)
	if err != nil {
		return fmt.Errorf("failed to initialize exporter registry: %w", err)
	}

	// Initialize pipeline manager
	a.pipelineManager, err = pipeline.NewManager(
		a.cfg.Pipeline,
		a.exporterReg,
		a.memoryBudget,
		a.log,
		a.selfTelemetry,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize pipeline manager: %w", err)
	}

	// Setup HTTP handlers
	a.setupHTTPHandlers()

	// Start HTTP server
	a.httpServer = &http.Server{
		Addr:    a.cfg.ListenAddress,
		Handler: a.httpMux,
	}
	go func() {
		if err := a.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.log.Error("HTTP server error", "error", err)
		}
	}()

	// Start exporters
	if err := a.exporterReg.Start(ctx); err != nil {
		return fmt.Errorf("failed to start exporters: %w", err)
	}

	// Start pipeline manager
	if err := a.pipelineManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start pipeline manager: %w", err)
	}

	// Initialize and start eBPF profiler if enabled
	if a.cfg.Profiling.Enabled {
		// Inject service metadata into profiling config
		profCfg := a.cfg.Profiling
		profCfg.ServiceName = a.cfg.ServiceName

		a.profilerRunner, err = profiler.NewRunner(profCfg, a.log)
		if err != nil {
			return fmt.Errorf("failed to create profiler runner: %w", err)
		}
		if err := a.profilerRunner.Start(ctx); err != nil {
			a.log.Warn("failed to start profiler runner", "error", err)
			// Non-fatal: continue without profiling
		}
	}

	a.state.Store(int32(StateRunning))
	a.selfTelemetry.SetReady(true)
	a.log.Info("agent started successfully")

	return nil
}

// Stop gracefully shuts down all agent components
func (a *Agent) Stop(ctx context.Context) error {
	var stopErr error
	a.stopOnce.Do(func() {
		if !a.state.CompareAndSwap(int32(StateRunning), int32(StateStopping)) {
			stopErr = errors.New("agent not running")
			return
		}

		a.log.Info("stopping agent")
		a.selfTelemetry.SetReady(false)

		// Create timeout context if not already done
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, a.cfg.ShutdownTimeout)
			defer cancel()
		}

		// Stop HTTP server
		if a.httpServer != nil {
			if err := a.httpServer.Shutdown(ctx); err != nil {
				a.log.Warn("HTTP server shutdown error", "error", err)
			}
		}

		// Stop profiler runner
		if a.profilerRunner != nil {
			if err := a.profilerRunner.Stop(ctx); err != nil {
				a.log.Warn("profiler runner shutdown error", "error", err)
			}
		}

		// Stop pipeline manager
		if a.pipelineManager != nil {
			if err := a.pipelineManager.Stop(ctx); err != nil {
				a.log.Warn("pipeline manager shutdown error", "error", err)
				stopErr = err
			}
		}

		// Stop exporters
		if a.exporterReg != nil {
			if err := a.exporterReg.Stop(ctx); err != nil {
				a.log.Warn("exporter registry shutdown error", "error", err)
				if stopErr == nil {
					stopErr = err
				}
			}
		}

		a.state.Store(int32(StateStopped))
		close(a.done)
		a.log.Info("agent stopped", "uptime", time.Since(a.startTime))
	})
	return stopErr
}

// Wait blocks until the agent is stopped
func (a *Agent) Wait() {
	<-a.done
}

// State returns the current agent state
func (a *Agent) State() State {
	return State(a.state.Load())
}

// Mode returns the agent's operating mode
func (a *Agent) Mode() Mode {
	return a.cfg.Mode
}

// Uptime returns how long the agent has been running
func (a *Agent) Uptime() time.Duration {
	if a.startTime.IsZero() {
		return 0
	}
	return time.Since(a.startTime)
}

// PipelineManager returns the pipeline manager instance
func (a *Agent) PipelineManager() *pipeline.Manager {
	return a.pipelineManager
}

// ExporterRegistry returns the exporter registry instance
func (a *Agent) ExporterRegistry() *exporters.Registry {
	return a.exporterReg
}

// setupHTTPHandlers configures HTTP endpoints for health and debug
func (a *Agent) setupHTTPHandlers() {
	// Health check endpoint
	a.httpMux.HandleFunc("/healthz", a.handleHealth)

	// Readiness endpoint
	a.httpMux.HandleFunc("/readyz", a.handleReady)

	// Metrics endpoint (Prometheus format)
	a.selfTelemetry.InstallHandler(a.httpMux)

	// Debug endpoints (if enabled)
	if a.cfg.DebugEnabled {
		a.setupDebugHandlers()
	}
}

// handleHealth handles liveness probe requests
func (a *Agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	state := a.State()
	if state == StateRunning || state == StateStarting {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"healthy","state":"%s"}`, state)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = fmt.Fprintf(w, `{"status":"unhealthy","state":"%s"}`, state)
}

// handleReady handles readiness probe requests
func (a *Agent) handleReady(w http.ResponseWriter, r *http.Request) {
	if a.State() == StateRunning {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"status":"not ready"}`))
}
