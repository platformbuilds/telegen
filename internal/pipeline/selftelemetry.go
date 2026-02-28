// Package pipeline provides self-telemetry integration for V3 pipeline.
package pipeline

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SelfTelemetryConfig configures the self-telemetry HTTP server.
type SelfTelemetryConfig struct {
	// Enabled enables self-telemetry HTTP server.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// ListenAddress is the address to listen on.
	ListenAddress string `yaml:"listen_address" json:"listen_address"`

	// TLSEnabled enables TLS for the HTTP server.
	TLSEnabled bool `yaml:"tls_enabled" json:"tls_enabled"`

	// TLSCertFile is the path to the TLS certificate.
	TLSCertFile string `yaml:"tls_cert_file" json:"tls_cert_file"`

	// TLSKeyFile is the path to the TLS key.
	TLSKeyFile string `yaml:"tls_key_file" json:"tls_key_file"`

	// MetricsPath is the path for the metrics endpoint.
	MetricsPath string `yaml:"metrics_path" json:"metrics_path"`

	// HealthPath is the path for the health endpoint.
	HealthPath string `yaml:"health_path" json:"health_path"`

	// ReadyPath is the path for the readiness endpoint.
	ReadyPath string `yaml:"ready_path" json:"ready_path"`

	// Namespace is the prometheus metrics namespace.
	Namespace string `yaml:"namespace" json:"namespace"`
}

// DefaultSelfTelemetryConfig returns reasonable defaults.
func DefaultSelfTelemetryConfig() SelfTelemetryConfig {
	return SelfTelemetryConfig{
		Enabled:       true,
		ListenAddress: ":8888",
		TLSEnabled:    false,
		MetricsPath:   "/metrics",
		HealthPath:    "/health",
		ReadyPath:     "/ready",
		Namespace:     "telegen",
	}
}

// SelfTelemetry provides self-telemetry for the V3 pipeline.
type SelfTelemetry struct {
	config SelfTelemetryConfig
	logger *slog.Logger
	server *http.Server
	mux    *http.ServeMux

	// Health state.
	healthy atomic.Bool
	ready   atomic.Bool

	// Metrics.
	registry *prometheus.Registry
	metrics  *V3Metrics

	// Shutdown.
	mu       sync.RWMutex
	shutdown bool
}

// V3Metrics contains all V3 pipeline prometheus metrics.
type V3Metrics struct {
	// Signal collection metrics.
	SignalsCollected *prometheus.CounterVec
	SignalsDropped   *prometheus.CounterVec

	// Queue metrics.
	QueueSize    *prometheus.GaugeVec
	QueueDropped *prometheus.CounterVec
	QueueLatency *prometheus.HistogramVec

	// Export metrics.
	ExportSuccess *prometheus.CounterVec
	ExportFailure *prometheus.CounterVec
	ExportLatency *prometheus.HistogramVec
	ExportRetries *prometheus.CounterVec

	// Circuit breaker metrics.
	CircuitBreakerState   *prometheus.GaugeVec
	CircuitBreakerTrips   *prometheus.CounterVec
	CircuitBreakerRecover *prometheus.CounterVec

	// Pipeline metrics.
	PipelineUptime     *prometheus.GaugeVec
	PipelineAdapters   *prometheus.GaugeVec
	PipelineConverters *prometheus.GaugeVec

	// Exporter metrics.
	ExporterConnections *prometheus.GaugeVec
	ExporterEndpoints   *prometheus.GaugeVec

	// Processing metrics.
	ProcessingLatency *prometheus.HistogramVec
	EnrichmentLatency *prometheus.HistogramVec

	// Resource metrics.
	MemoryUsage *prometheus.GaugeVec
	CPUUsage    *prometheus.GaugeVec
	GoroutineCount prometheus.Gauge
}

// NewSelfTelemetry creates a new self-telemetry instance.
func NewSelfTelemetry(config SelfTelemetryConfig, logger *slog.Logger) (*SelfTelemetry, error) {
	if logger == nil {
		logger = slog.Default()
	}

	st := &SelfTelemetry{
		config:   config,
		logger:   logger,
		mux:      http.NewServeMux(),
		registry: prometheus.NewRegistry(),
	}

	// Initialize metrics.
	st.metrics = st.registerMetrics()

	// Register default collectors.
	st.registry.MustRegister(prometheus.NewGoCollector())
	st.registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	// Setup HTTP handlers.
	st.setupHandlers()

	// Set initial state.
	st.healthy.Store(true)
	st.ready.Store(false)

	return st, nil
}

// registerMetrics registers all V3 prometheus metrics.
func (st *SelfTelemetry) registerMetrics() *V3Metrics {
	ns := st.config.Namespace
	if ns == "" {
		ns = "telegen"
	}

	m := &V3Metrics{
		// Signal collection.
		SignalsCollected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "signals_collected_total",
			Help:      "Total signals collected by type and collector",
		}, []string{"signal_type", "collector"}),

		SignalsDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "signals_dropped_total",
			Help:      "Total signals dropped by type and reason",
		}, []string{"signal_type", "reason"}),

		// Queue metrics.
		QueueSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "queue_size",
			Help:      "Current queue size by signal type",
		}, []string{"signal_type"}),

		QueueDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "queue_dropped_total",
			Help:      "Total items dropped from queue by reason",
		}, []string{"signal_type", "reason"}),

		QueueLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "queue_latency_seconds",
			Help:      "Queue wait time in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"signal_type"}),

		// Export metrics.
		ExportSuccess: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "export_success_total",
			Help:      "Successful exports by endpoint and signal type",
		}, []string{"endpoint", "signal_type"}),

		ExportFailure: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "export_failure_total",
			Help:      "Failed exports by endpoint and signal type",
		}, []string{"endpoint", "signal_type"}),

		ExportLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "export_latency_seconds",
			Help:      "Export latency in seconds",
			Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"endpoint", "signal_type"}),

		ExportRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "export_retries_total",
			Help:      "Export retry attempts by endpoint",
		}, []string{"endpoint"}),

		// Circuit breaker metrics.
		CircuitBreakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "circuit_breaker_state",
			Help:      "Circuit breaker state (0=closed, 1=half-open, 2=open)",
		}, []string{"endpoint"}),

		CircuitBreakerTrips: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "circuit_breaker_trips_total",
			Help:      "Circuit breaker trip count by endpoint",
		}, []string{"endpoint"}),

		CircuitBreakerRecover: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "circuit_breaker_recoveries_total",
			Help:      "Circuit breaker recovery count by endpoint",
		}, []string{"endpoint"}),

		// Pipeline metrics.
		PipelineUptime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "pipeline_uptime_seconds",
			Help:      "Pipeline uptime in seconds",
		}, []string{"pipeline"}),

		PipelineAdapters: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "pipeline_adapters",
			Help:      "Number of registered adapters",
		}, []string{"pipeline"}),

		PipelineConverters: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "pipeline_converters",
			Help:      "Number of registered converters",
		}, []string{"pipeline"}),

		// Exporter metrics.
		ExporterConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "exporter_connections",
			Help:      "Number of active exporter connections",
		}, []string{"endpoint"}),

		ExporterEndpoints: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "exporter_endpoints",
			Help:      "Number of configured endpoints",
		}, []string{"mode"}),

		// Processing metrics.
		ProcessingLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "processing_latency_seconds",
			Help:      "Signal processing latency",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1},
		}, []string{"stage"}),

		EnrichmentLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "enrichment_latency_seconds",
			Help:      "Metadata enrichment latency",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1},
		}, []string{"enricher"}),

		// Resource metrics.
		MemoryUsage: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "memory_usage_bytes",
			Help:      "Memory usage by component",
		}, []string{"component"}),

		CPUUsage: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "cpu_usage_percent",
			Help:      "CPU usage by component",
		}, []string{"component"}),

		GoroutineCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "goroutines",
			Help:      "Current goroutine count",
		}),
	}

	// Register all metrics.
	st.registry.MustRegister(
		m.SignalsCollected, m.SignalsDropped,
		m.QueueSize, m.QueueDropped, m.QueueLatency,
		m.ExportSuccess, m.ExportFailure, m.ExportLatency, m.ExportRetries,
		m.CircuitBreakerState, m.CircuitBreakerTrips, m.CircuitBreakerRecover,
		m.PipelineUptime, m.PipelineAdapters, m.PipelineConverters,
		m.ExporterConnections, m.ExporterEndpoints,
		m.ProcessingLatency, m.EnrichmentLatency,
		m.MemoryUsage, m.CPUUsage, m.GoroutineCount,
	)

	return m
}

// setupHandlers configures HTTP handlers.
func (st *SelfTelemetry) setupHandlers() {
	// Metrics endpoint.
	st.mux.Handle(st.config.MetricsPath, promhttp.HandlerFor(st.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	// Health endpoint.
	st.mux.HandleFunc(st.config.HealthPath, st.healthHandler)

	// Ready endpoint.
	st.mux.HandleFunc(st.config.ReadyPath, st.readyHandler)

	// Info endpoint.
	st.mux.HandleFunc("/info", st.infoHandler)
}

// healthHandler handles health checks.
func (st *SelfTelemetry) healthHandler(w http.ResponseWriter, r *http.Request) {
	if st.healthy.Load() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"unhealthy"}`))
	}
}

// readyHandler handles readiness checks.
func (st *SelfTelemetry) readyHandler(w http.ResponseWriter, r *http.Request) {
	if st.ready.Load() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not_ready"}`))
	}
}

// infoHandler provides pipeline information.
func (st *SelfTelemetry) infoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"version":"3.0.0","mode":"pipeline"}`))
}

// Start starts the self-telemetry HTTP server.
func (st *SelfTelemetry) Start(ctx context.Context) error {
	st.mu.Lock()
	if st.shutdown {
		st.mu.Unlock()
		return fmt.Errorf("self-telemetry is shut down")
	}
	st.mu.Unlock()

	var tlsConfig *tls.Config
	if st.config.TLSEnabled {
		cert, err := tls.LoadX509KeyPair(st.config.TLSCertFile, st.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	st.server = &http.Server{
		Addr:              st.config.ListenAddress,
		Handler:           st.mux,
		TLSConfig:         tlsConfig,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	listener, err := net.Listen("tcp", st.config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", st.config.ListenAddress, err)
	}

	st.logger.Info("starting self-telemetry server",
		"address", st.config.ListenAddress,
		"tls", st.config.TLSEnabled,
		"metrics_path", st.config.MetricsPath)

	go func() {
		var serveErr error
		if st.config.TLSEnabled {
			serveErr = st.server.ServeTLS(listener, "", "")
		} else {
			serveErr = st.server.Serve(listener)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			st.logger.Error("self-telemetry server error", "error", serveErr)
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the server.
func (st *SelfTelemetry) Shutdown(ctx context.Context) error {
	st.mu.Lock()
	st.shutdown = true
	st.mu.Unlock()

	if st.server != nil {
		return st.server.Shutdown(ctx)
	}
	return nil
}

// SetHealthy sets the health state.
func (st *SelfTelemetry) SetHealthy(healthy bool) {
	st.healthy.Store(healthy)
}

// SetReady sets the ready state.
func (st *SelfTelemetry) SetReady(ready bool) {
	st.ready.Store(ready)
}

// Metrics returns the V3 metrics instance.
func (st *SelfTelemetry) Metrics() *V3Metrics {
	return st.metrics
}

// ObserveSignalCollected records a collected signal.
func (m *V3Metrics) ObserveSignalCollected(signalType, collector string) {
	m.SignalsCollected.WithLabelValues(signalType, collector).Inc()
}

// ObserveSignalDropped records a dropped signal.
func (m *V3Metrics) ObserveSignalDropped(signalType, reason string) {
	m.SignalsDropped.WithLabelValues(signalType, reason).Inc()
}

// ObserveExportSuccess records a successful export.
func (m *V3Metrics) ObserveExportSuccess(endpoint, signalType string) {
	m.ExportSuccess.WithLabelValues(endpoint, signalType).Inc()
}

// ObserveExportFailure records a failed export.
func (m *V3Metrics) ObserveExportFailure(endpoint, signalType string) {
	m.ExportFailure.WithLabelValues(endpoint, signalType).Inc()
}

// ObserveExportLatency records export latency.
func (m *V3Metrics) ObserveExportLatency(endpoint, signalType string, d time.Duration) {
	m.ExportLatency.WithLabelValues(endpoint, signalType).Observe(d.Seconds())
}

// SetQueueSize sets the current queue size.
func (m *V3Metrics) SetQueueSize(signalType string, size int) {
	m.QueueSize.WithLabelValues(signalType).Set(float64(size))
}

// ObserveQueueLatency records queue wait time.
func (m *V3Metrics) ObserveQueueLatency(signalType string, d time.Duration) {
	m.QueueLatency.WithLabelValues(signalType).Observe(d.Seconds())
}

// SetCircuitBreakerState sets circuit breaker state (0=closed, 1=half-open, 2=open).
func (m *V3Metrics) SetCircuitBreakerState(endpoint string, state int) {
	m.CircuitBreakerState.WithLabelValues(endpoint).Set(float64(state))
}

// ObserveCircuitBreakerTrip records a circuit breaker trip.
func (m *V3Metrics) ObserveCircuitBreakerTrip(endpoint string) {
	m.CircuitBreakerTrips.WithLabelValues(endpoint).Inc()
}

// ObserveCircuitBreakerRecover records a circuit breaker recovery.
func (m *V3Metrics) ObserveCircuitBreakerRecover(endpoint string) {
	m.CircuitBreakerRecover.WithLabelValues(endpoint).Inc()
}

// SetPipelineUptime sets pipeline uptime.
func (m *V3Metrics) SetPipelineUptime(pipeline string, uptime time.Duration) {
	m.PipelineUptime.WithLabelValues(pipeline).Set(uptime.Seconds())
}

// ObserveProcessingLatency records processing latency for a stage.
func (m *V3Metrics) ObserveProcessingLatency(stage string, d time.Duration) {
	m.ProcessingLatency.WithLabelValues(stage).Observe(d.Seconds())
}

// ObserveEnrichmentLatency records enrichment latency.
func (m *V3Metrics) ObserveEnrichmentLatency(enricher string, d time.Duration) {
	m.EnrichmentLatency.WithLabelValues(enricher).Observe(d.Seconds())
}
