package operations

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// ============================================================
// Graceful Shutdown Configuration
// ============================================================

// ShutdownConfig configuration for graceful shutdown.
type ShutdownConfig struct {
	// Timeout is the maximum time to wait for shutdown
	Timeout time.Duration `yaml:"timeout"`

	// DrainTimeout is the time to wait for in-flight data to drain
	DrainTimeout time.Duration `yaml:"drain_timeout"`

	// Signals to listen for (defaults to SIGTERM, SIGINT)
	Signals []os.Signal `yaml:"-"`

	// PreShutdownHook is called before shutdown begins
	PreShutdownHook func() `yaml:"-"`

	// OnTimeout is called if shutdown times out
	OnTimeout func() `yaml:"-"`

	// EnableHealthCheck marks service unhealthy during shutdown
	EnableHealthCheck bool `yaml:"enable_health_check"`
}

// DefaultShutdownConfig returns sensible defaults.
func DefaultShutdownConfig() ShutdownConfig {
	return ShutdownConfig{
		Timeout:           30 * time.Second,
		DrainTimeout:      10 * time.Second,
		Signals:           []os.Signal{syscall.SIGTERM, syscall.SIGINT},
		EnableHealthCheck: true,
	}
}

// ============================================================
// Shutdown Priority
// ============================================================

// ShutdownPriority defines the order of shutdown.
type ShutdownPriority int

const (
	// ShutdownPriorityFirst runs first (e.g., stop accepting new work)
	ShutdownPriorityFirst ShutdownPriority = 100
	// ShutdownPriorityEarly runs early (e.g., flush buffers)
	ShutdownPriorityEarly ShutdownPriority = 200
	// ShutdownPriorityNormal is the default priority
	ShutdownPriorityNormal ShutdownPriority = 500
	// ShutdownPriorityLate runs late (e.g., close exporters)
	ShutdownPriorityLate ShutdownPriority = 800
	// ShutdownPriorityLast runs last (e.g., close database connections)
	ShutdownPriorityLast ShutdownPriority = 900
)

// ============================================================
// Stoppable Interface
// ============================================================

// Stoppable is implemented by components that need graceful shutdown.
type Stoppable interface {
	// Stop performs graceful shutdown
	Stop(ctx context.Context) error

	// Name returns the component name for logging
	Name() string
}

// StoppableFunc wraps a function as a Stoppable.
type StoppableFunc struct {
	NameStr  string
	StopFunc func(ctx context.Context) error
}

func (s StoppableFunc) Name() string                       { return s.NameStr }
func (s StoppableFunc) Stop(ctx context.Context) error { return s.StopFunc(ctx) }

// ============================================================
// Shutdown Handler
// ============================================================

// ShutdownHandler manages graceful shutdown.
type ShutdownHandler struct {
	config    ShutdownConfig
	logger    *zap.Logger
	mu        sync.RWMutex
	hooks     map[ShutdownPriority][]Stoppable

	// State
	shutdownOnce   sync.Once
	shutdownChan   chan struct{}
	isShuttingDown atomic.Bool
	shutdownStart  atomic.Value // time.Time

	// Stats
	componentsStopped atomic.Int32
	errors            []error
	errorsMu          sync.Mutex
}

// NewShutdownHandler creates a new shutdown handler.
func NewShutdownHandler(config ShutdownConfig, logger *zap.Logger) *ShutdownHandler {
	if logger == nil {
		logger = zap.NewNop()
	}

	if config.Signals == nil {
		config.Signals = []os.Signal{syscall.SIGTERM, syscall.SIGINT}
	}

	return &ShutdownHandler{
		config:       config,
		logger:       logger,
		hooks:        make(map[ShutdownPriority][]Stoppable),
		shutdownChan: make(chan struct{}),
		errors:       make([]error, 0),
	}
}

// Register adds a component with default priority.
func (h *ShutdownHandler) Register(s Stoppable) {
	h.RegisterWithPriority(s, ShutdownPriorityNormal)
}

// RegisterWithPriority adds a component with specific priority.
func (h *ShutdownHandler) RegisterWithPriority(s Stoppable, priority ShutdownPriority) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.hooks[priority]; !ok {
		h.hooks[priority] = make([]Stoppable, 0)
	}
	h.hooks[priority] = append(h.hooks[priority], s)

	h.logger.Debug("Registered shutdown hook",
		zap.String("name", s.Name()),
		zap.Int("priority", int(priority)),
	)
}

// RegisterFunc adds a function as a shutdown hook.
func (h *ShutdownHandler) RegisterFunc(name string, priority ShutdownPriority, fn func(ctx context.Context) error) {
	h.RegisterWithPriority(StoppableFunc{
		NameStr:  name,
		StopFunc: fn,
	}, priority)
}

// WaitForShutdown blocks until shutdown signal is received.
func (h *ShutdownHandler) WaitForShutdown(ctx context.Context) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, h.config.Signals...)
	defer signal.Stop(sigChan)

	select {
	case <-ctx.Done():
		h.logger.Info("Context cancelled, initiating shutdown")
	case sig := <-sigChan:
		h.logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
	}

	return h.Shutdown()
}

// Shutdown initiates graceful shutdown.
func (h *ShutdownHandler) Shutdown() error {
	var err error

	h.shutdownOnce.Do(func() {
		h.isShuttingDown.Store(true)
		h.shutdownStart.Store(time.Now())
		close(h.shutdownChan)

		h.logger.Info("Starting graceful shutdown",
			zap.Duration("timeout", h.config.Timeout),
			zap.Duration("drain_timeout", h.config.DrainTimeout),
		)

		// Pre-shutdown hook
		if h.config.PreShutdownHook != nil {
			h.config.PreShutdownHook()
		}

		// Create timeout context
		ctx, cancel := context.WithTimeout(context.Background(), h.config.Timeout)
		defer cancel()

		// Execute shutdown in priority order
		err = h.executeShutdown(ctx)

		// Handle timeout
		if ctx.Err() == context.DeadlineExceeded {
			h.logger.Error("Shutdown timed out")
			if h.config.OnTimeout != nil {
				h.config.OnTimeout()
			}
		}
	})

	return err
}

// executeShutdown runs all shutdown hooks in priority order.
func (h *ShutdownHandler) executeShutdown(ctx context.Context) error {
	// Get priorities in order
	h.mu.RLock()
	priorities := make([]ShutdownPriority, 0, len(h.hooks))
	for p := range h.hooks {
		priorities = append(priorities, p)
	}
	h.mu.RUnlock()

	// Sort priorities
	sortPriorities(priorities)

	// Execute each priority group
	for _, priority := range priorities {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("shutdown cancelled: %w", err)
		}

		h.mu.RLock()
		hooks := h.hooks[priority]
		h.mu.RUnlock()

		h.logger.Debug("Executing shutdown hooks",
			zap.Int("priority", int(priority)),
			zap.Int("count", len(hooks)),
		)

		// Execute hooks in parallel within same priority
		var wg sync.WaitGroup
		for _, hook := range hooks {
			wg.Add(1)
			go func(s Stoppable) {
				defer wg.Done()
				h.stopComponent(ctx, s)
			}(hook)
		}
		wg.Wait()
	}

	// Report results
	h.errorsMu.Lock()
	errorCount := len(h.errors)
	h.errorsMu.Unlock()

	h.logger.Info("Graceful shutdown complete",
		zap.Int32("components_stopped", h.componentsStopped.Load()),
		zap.Int("errors", errorCount),
		zap.Duration("duration", time.Since(h.shutdownStart.Load().(time.Time))),
	)

	if errorCount > 0 {
		return fmt.Errorf("shutdown completed with %d errors", errorCount)
	}

	return nil
}

// stopComponent stops a single component.
func (h *ShutdownHandler) stopComponent(ctx context.Context, s Stoppable) {
	start := time.Now()

	h.logger.Debug("Stopping component", zap.String("name", s.Name()))

	if err := s.Stop(ctx); err != nil {
		h.logger.Error("Component stop failed",
			zap.String("name", s.Name()),
			zap.Error(err),
			zap.Duration("duration", time.Since(start)),
		)

		h.errorsMu.Lock()
		h.errors = append(h.errors, fmt.Errorf("%s: %w", s.Name(), err))
		h.errorsMu.Unlock()
	} else {
		h.logger.Debug("Component stopped",
			zap.String("name", s.Name()),
			zap.Duration("duration", time.Since(start)),
		)
	}

	h.componentsStopped.Add(1)
}

// IsShuttingDown returns whether shutdown is in progress.
func (h *ShutdownHandler) IsShuttingDown() bool {
	return h.isShuttingDown.Load()
}

// ShutdownChan returns a channel that closes when shutdown begins.
func (h *ShutdownHandler) ShutdownChan() <-chan struct{} {
	return h.shutdownChan
}

// sortPriorities sorts priorities in ascending order.
func sortPriorities(priorities []ShutdownPriority) {
	for i := 0; i < len(priorities)-1; i++ {
		for j := i + 1; j < len(priorities); j++ {
			if priorities[j] < priorities[i] {
				priorities[i], priorities[j] = priorities[j], priorities[i]
			}
		}
	}
}

// ============================================================
// Drainer
// ============================================================

// Drainer handles draining in-flight data before shutdown.
type Drainer struct {
	inFlight   atomic.Int64
	draining   atomic.Bool
	drainedCh  chan struct{}
	timeout    time.Duration
	logger     *zap.Logger
	mu         sync.Mutex
}

// NewDrainer creates a new drainer.
func NewDrainer(timeout time.Duration, logger *zap.Logger) *Drainer {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Drainer{
		drainedCh: make(chan struct{}),
		timeout:   timeout,
		logger:    logger,
	}
}

// Acquire marks that work is in progress.
// Returns false if draining has started.
func (d *Drainer) Acquire() bool {
	if d.draining.Load() {
		return false
	}
	d.inFlight.Add(1)
	// Double-check after incrementing
	if d.draining.Load() {
		d.Release()
		return false
	}
	return true
}

// Release marks that work is complete.
func (d *Drainer) Release() {
	current := d.inFlight.Add(-1)
	if current == 0 && d.draining.Load() {
		d.mu.Lock()
		select {
		case <-d.drainedCh:
			// Already closed
		default:
			close(d.drainedCh)
		}
		d.mu.Unlock()
	}
}

// InFlight returns the count of in-flight work.
func (d *Drainer) InFlight() int64 {
	return d.inFlight.Load()
}

// IsDraining returns whether draining is in progress.
func (d *Drainer) IsDraining() bool {
	return d.draining.Load()
}

// Drain starts draining and waits for completion.
func (d *Drainer) Drain(ctx context.Context) error {
	d.draining.Store(true)

	d.logger.Info("Starting drain", zap.Int64("in_flight", d.inFlight.Load()))

	// If nothing in flight, we're done
	if d.inFlight.Load() == 0 {
		d.mu.Lock()
		select {
		case <-d.drainedCh:
		default:
			close(d.drainedCh)
		}
		d.mu.Unlock()
		return nil
	}

	// Wait for drain with timeout
	select {
	case <-d.drainedCh:
		d.logger.Info("Drain complete")
		return nil
	case <-ctx.Done():
		d.logger.Warn("Drain timeout",
			zap.Int64("remaining", d.inFlight.Load()),
		)
		return fmt.Errorf("drain timeout with %d items in flight", d.inFlight.Load())
	case <-time.After(d.timeout):
		d.logger.Warn("Drain timeout",
			zap.Int64("remaining", d.inFlight.Load()),
		)
		return fmt.Errorf("drain timeout with %d items in flight", d.inFlight.Load())
	}
}

// ============================================================
// Health Integration
// ============================================================

// ShutdownAwareHealth provides health status that changes during shutdown.
type ShutdownAwareHealth struct {
	handler    *ShutdownHandler
	drainer    *Drainer
	healthy    atomic.Bool
	readyCheck func() bool
}

// NewShutdownAwareHealth creates a new shutdown-aware health checker.
func NewShutdownAwareHealth(handler *ShutdownHandler, drainer *Drainer) *ShutdownAwareHealth {
	h := &ShutdownAwareHealth{
		handler: handler,
		drainer: drainer,
	}
	h.healthy.Store(true)
	return h
}

// SetReadyCheck sets a custom readiness check function.
func (h *ShutdownAwareHealth) SetReadyCheck(check func() bool) {
	h.readyCheck = check
}

// IsHealthy returns whether the service is healthy.
func (h *ShutdownAwareHealth) IsHealthy() bool {
	if h.handler != nil && h.handler.IsShuttingDown() {
		return false
	}
	return h.healthy.Load()
}

// IsReady returns whether the service is ready to accept work.
func (h *ShutdownAwareHealth) IsReady() bool {
	// Not ready if shutting down
	if h.handler != nil && h.handler.IsShuttingDown() {
		return false
	}

	// Not ready if draining
	if h.drainer != nil && h.drainer.IsDraining() {
		return false
	}

	// Custom readiness check
	if h.readyCheck != nil {
		return h.readyCheck()
	}

	return h.healthy.Load()
}

// SetHealthy sets the health status.
func (h *ShutdownAwareHealth) SetHealthy(healthy bool) {
	h.healthy.Store(healthy)
}

// ============================================================
// Stats
// ============================================================

// ShutdownStats provides shutdown statistics.
type ShutdownStats struct {
	IsShuttingDown    bool          `json:"is_shutting_down"`
	ShutdownStart     time.Time     `json:"shutdown_start,omitempty"`
	ComponentsStopped int32         `json:"components_stopped"`
	ErrorCount        int           `json:"error_count"`
	RegisteredHooks   int           `json:"registered_hooks"`
	DrainInFlight     int64         `json:"drain_in_flight,omitempty"`
	DrainActive       bool          `json:"drain_active"`
}

// Stats returns current shutdown statistics.
func (h *ShutdownHandler) Stats() ShutdownStats {
	h.mu.RLock()
	hookCount := 0
	for _, hooks := range h.hooks {
		hookCount += len(hooks)
	}
	h.mu.RUnlock()

	h.errorsMu.Lock()
	errorCount := len(h.errors)
	h.errorsMu.Unlock()

	stats := ShutdownStats{
		IsShuttingDown:    h.isShuttingDown.Load(),
		ComponentsStopped: h.componentsStopped.Load(),
		ErrorCount:        errorCount,
		RegisteredHooks:   hookCount,
	}

	if start := h.shutdownStart.Load(); start != nil {
		stats.ShutdownStart = start.(time.Time)
	}

	return stats
}
