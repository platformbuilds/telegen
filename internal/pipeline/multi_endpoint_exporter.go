// Package pipeline provides multi-endpoint OTLP export with circuit breakers.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// EndpointConfig configures a single export endpoint.
type EndpointConfig struct {
	// Name is a friendly name for the endpoint.
	Name string `yaml:"name" json:"name"`

	// URL is the OTLP endpoint URL.
	URL string `yaml:"url" json:"url"`

	// Insecure disables TLS.
	Insecure bool `yaml:"insecure" json:"insecure"`

	// Headers are additional headers to send.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// Timeout for export operations.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Priority determines failover order (lower = higher priority).
	Priority int `yaml:"priority" json:"priority"`

	// Enabled allows disabling endpoints without removing config.
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// MultiEndpointConfig configures the multi-endpoint exporter.
type MultiEndpointConfig struct {
	// Endpoints to export to.
	Endpoints []EndpointConfig `yaml:"endpoints" json:"endpoints"`

	// CircuitBreaker configuration.
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`

	// Retry configuration.
	Retry RetryConfig `yaml:"retry" json:"retry"`

	// FanOut exports to all endpoints concurrently (true) or only primary (false).
	// Default: false (failover mode).
	FanOut bool `yaml:"fan_out" json:"fan_out"`

	// MaxConcurrentExports limits concurrent operations.
	MaxConcurrentExports int `yaml:"max_concurrent_exports" json:"max_concurrent_exports"`

	// BatchSize is the max signals per batch.
	BatchSize int `yaml:"batch_size" json:"batch_size"`

	// CriticalFailureCallback is called when all endpoints fail (data loss).
	CriticalFailureCallback func(signalType PipelineSignalType, count int, err error)
}

// DefaultMultiEndpointConfig returns default configuration.
func DefaultMultiEndpointConfig() MultiEndpointConfig {
	return MultiEndpointConfig{
		CircuitBreaker:       DefaultCircuitBreakerConfig(),
		Retry:                RetryConfig{Enabled: true, MaxAttempts: 3, InitialInterval: time.Second, MaxInterval: 30 * time.Second, Multiplier: 2.0},
		FanOut:               false,
		MaxConcurrentExports: 4,
		BatchSize:            1000,
	}
}

// MultiEndpointExporter exports signals to multiple endpoints with circuit breakers.
type MultiEndpointExporter struct {
	config MultiEndpointConfig
	logger *slog.Logger

	endpoints []*endpointState
	sem       chan struct{}

	// Global stats
	totalExported atomic.Int64
	totalFailed   atomic.Int64
	totalDropped  atomic.Int64

	mu       sync.RWMutex
	shutdown bool
}

// endpointState holds state for a single endpoint.
type endpointState struct {
	config         EndpointConfig
	exporter       *UnifiedExporter
	circuitBreaker *CircuitBreaker
	healthy        atomic.Bool
}

// NewMultiEndpointExporter creates a new multi-endpoint exporter.
func NewMultiEndpointExporter(config MultiEndpointConfig, logger *slog.Logger) (*MultiEndpointExporter, error) {
	if len(config.Endpoints) == 0 {
		return nil, fmt.Errorf("at least one endpoint required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Apply defaults.
	if config.MaxConcurrentExports == 0 {
		config.MaxConcurrentExports = 4
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}

	me := &MultiEndpointExporter{
		config:    config,
		logger:    logger,
		endpoints: make([]*endpointState, 0, len(config.Endpoints)),
		sem:       make(chan struct{}, config.MaxConcurrentExports),
	}

	// Create endpoint states.
	for _, epConfig := range config.Endpoints {
		if !epConfig.Enabled {
			continue
		}

		exporterConfig := ExporterConfig{
			Endpoint: epConfig.URL,
			Insecure: epConfig.Insecure,
			Headers:  epConfig.Headers,
			Timeout:  epConfig.Timeout,
			Retry:    config.Retry,
		}

		exporter, err := NewUnifiedExporter(exporterConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create exporter for %s: %w", epConfig.Name, err)
		}

		cbConfig := config.CircuitBreaker
		cbConfig.OnStateChange = func(endpoint string, from, to CircuitState) {
			logger.Warn("circuit breaker state change",
				"endpoint", endpoint,
				"from", from.String(),
				"to", to.String())
		}

		state := &endpointState{
			config:         epConfig,
			exporter:       exporter,
			circuitBreaker: NewCircuitBreaker(epConfig.Name, cbConfig),
		}
		state.healthy.Store(true)

		me.endpoints = append(me.endpoints, state)
	}

	if len(me.endpoints) == 0 {
		return nil, fmt.Errorf("no enabled endpoints")
	}

	return me, nil
}

// Connect establishes connections to all endpoints.
func (me *MultiEndpointExporter) Connect(ctx context.Context) error {
	var errs []error
	for _, ep := range me.endpoints {
		if err := ep.exporter.Connect(ctx); err != nil {
			me.logger.Error("failed to connect to endpoint",
				"endpoint", ep.config.Name,
				"error", err)
			errs = append(errs, err)
			ep.healthy.Store(false)
		}
	}

	// At least one endpoint must connect.
	connected := 0
	for _, ep := range me.endpoints {
		if ep.healthy.Load() {
			connected++
		}
	}
	if connected == 0 {
		return fmt.Errorf("failed to connect to any endpoint: %v", errs)
	}

	return nil
}

// ExportTraces exports traces to endpoints.
func (me *MultiEndpointExporter) ExportTraces(ctx context.Context, traces ptrace.Traces) error {
	return me.export(ctx, SignalTypeTrace, traces.SpanCount(), func(ep *endpointState) error {
		return ep.exporter.exportTraces(ctx, traces)
	})
}

// ExportLogs exports logs to endpoints.
func (me *MultiEndpointExporter) ExportLogs(ctx context.Context, logs plog.Logs) error {
	return me.export(ctx, SignalTypeLog, logs.LogRecordCount(), func(ep *endpointState) error {
		return ep.exporter.exportLogs(ctx, logs)
	})
}

// ExportMetrics exports metrics to endpoints.
func (me *MultiEndpointExporter) ExportMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	return me.export(ctx, SignalTypeMetric, metrics.DataPointCount(), func(ep *endpointState) error {
		return ep.exporter.exportMetrics(ctx, metrics)
	})
}

// export handles the actual export logic with circuit breaker and failover.
func (me *MultiEndpointExporter) export(ctx context.Context, signalType PipelineSignalType, count int, exportFn func(*endpointState) error) error {
	me.mu.RLock()
	if me.shutdown {
		me.mu.RUnlock()
		return fmt.Errorf("exporter is shut down")
	}
	me.mu.RUnlock()

	// Acquire semaphore.
	select {
	case me.sem <- struct{}{}:
		defer func() { <-me.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}

	if me.config.FanOut {
		return me.exportFanOut(ctx, signalType, count, exportFn)
	}
	return me.exportFailover(ctx, signalType, count, exportFn)
}

// exportFailover tries endpoints in priority order until one succeeds.
func (me *MultiEndpointExporter) exportFailover(ctx context.Context, signalType PipelineSignalType, count int, exportFn func(*endpointState) error) error {
	var lastErr error

	for _, ep := range me.endpoints {
		// Check circuit breaker.
		if !ep.circuitBreaker.Allow() {
			me.logger.Debug("circuit breaker rejected request",
				"endpoint", ep.config.Name,
				"state", ep.circuitBreaker.State().String())
			continue
		}

		err := me.exportWithRetry(ctx, ep, exportFn)
		if err == nil {
			ep.circuitBreaker.RecordSuccess()
			me.totalExported.Add(int64(count))
			return nil
		}

		ep.circuitBreaker.RecordFailure()
		lastErr = err
		me.logger.Warn("export failed, trying next endpoint",
			"endpoint", ep.config.Name,
			"error", err)
	}

	// All endpoints failed - CRITICAL FAILURE
	me.totalFailed.Add(int64(count))
	me.totalDropped.Add(int64(count))
	me.handleCriticalFailure(signalType, count, lastErr)

	return fmt.Errorf("all endpoints failed: %w", lastErr)
}

// exportFanOut exports to all healthy endpoints concurrently.
func (me *MultiEndpointExporter) exportFanOut(ctx context.Context, signalType PipelineSignalType, count int, exportFn func(*endpointState) error) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successCount int
	var lastErr error

	for _, ep := range me.endpoints {
		if !ep.circuitBreaker.Allow() {
			continue
		}

		wg.Add(1)
		go func(ep *endpointState) {
			defer wg.Done()

			err := me.exportWithRetry(ctx, ep, exportFn)
			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				ep.circuitBreaker.RecordSuccess()
				successCount++
			} else {
				ep.circuitBreaker.RecordFailure()
				lastErr = err
			}
		}(ep)
	}

	wg.Wait()

	if successCount > 0 {
		me.totalExported.Add(int64(count))
		return nil
	}

	// All endpoints failed - CRITICAL FAILURE
	me.totalFailed.Add(int64(count))
	me.totalDropped.Add(int64(count))
	me.handleCriticalFailure(signalType, count, lastErr)

	return fmt.Errorf("all endpoints failed: %w", lastErr)
}

// exportWithRetry exports with retry logic.
func (me *MultiEndpointExporter) exportWithRetry(ctx context.Context, ep *endpointState, exportFn func(*endpointState) error) error {
	var err error
	cfg := me.config.Retry

	for attempt := 0; attempt <= cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := me.calculateBackoff(attempt, cfg)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err = exportFn(ep)
		if err == nil {
			return nil
		}

		if !cfg.Enabled || !isRetryable(err) {
			break
		}
	}

	return err
}

func (me *MultiEndpointExporter) calculateBackoff(attempt int, cfg RetryConfig) time.Duration {
	backoff := cfg.InitialInterval
	for i := 1; i < attempt; i++ {
		backoff = time.Duration(float64(backoff) * cfg.Multiplier)
		if backoff > cfg.MaxInterval {
			return cfg.MaxInterval
		}
	}
	return backoff
}

// handleCriticalFailure handles complete export failure (data loss).
func (me *MultiEndpointExporter) handleCriticalFailure(signalType PipelineSignalType, count int, err error) {
	me.logger.Error("CRITICAL FAILURE: data loss - all endpoints failed",
		"signal_type", signalType.String(),
		"count", count,
		"error", err)

	if me.config.CriticalFailureCallback != nil {
		me.config.CriticalFailureCallback(signalType, count, err)
	}
}

// Shutdown gracefully shuts down all endpoints.
func (me *MultiEndpointExporter) Shutdown(ctx context.Context) error {
	me.mu.Lock()
	me.shutdown = true
	me.mu.Unlock()

	var errs []error
	for _, ep := range me.endpoints {
		if err := ep.exporter.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

// Stats returns statistics for all endpoints.
func (me *MultiEndpointExporter) Stats() MultiEndpointStats {
	stats := MultiEndpointStats{
		TotalExported: me.totalExported.Load(),
		TotalFailed:   me.totalFailed.Load(),
		TotalDropped:  me.totalDropped.Load(),
		Endpoints:     make([]EndpointStats, len(me.endpoints)),
	}

	for i, ep := range me.endpoints {
		cbStats := ep.circuitBreaker.Stats()
		stats.Endpoints[i] = EndpointStats{
			Name:           ep.config.Name,
			URL:            ep.config.URL,
			Healthy:        ep.healthy.Load(),
			CircuitState:   cbStats.State.String(),
			TotalSuccess:   cbStats.TotalSuccess,
			TotalFailure:   cbStats.TotalFailure,
			TotalRejected:  cbStats.TotalRejected,
		}
	}

	return stats
}

// MultiEndpointStats holds statistics for all endpoints.
type MultiEndpointStats struct {
	TotalExported int64
	TotalFailed   int64
	TotalDropped  int64
	Endpoints     []EndpointStats
}

// EndpointStats holds statistics for a single endpoint.
type EndpointStats struct {
	Name          string
	URL           string
	Healthy       bool
	CircuitState  string
	TotalSuccess  int64
	TotalFailure  int64
	TotalRejected int64
}
