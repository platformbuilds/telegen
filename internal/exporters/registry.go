// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/platformbuilds/telegen/internal/pipeline"
	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// Registry manages multiple exporters and routes signals to them
type Registry struct {
	cfg Config
	log *slog.Logger
	st  *selftelemetry.Metrics

	mu        sync.RWMutex
	exporters map[string]Exporter
	bySignal  map[pipeline.SignalType][]Exporter

	running bool
}

// NewRegistry creates a new exporter registry
func NewRegistry(cfg Config, log *slog.Logger, st *selftelemetry.Metrics) (*Registry, error) {
	r := &Registry{
		cfg:       cfg,
		log:       log.With("component", "exporter_registry"),
		st:        st,
		exporters: make(map[string]Exporter),
		bySignal:  make(map[pipeline.SignalType][]Exporter),
	}

	// Initialize configured exporters
	if err := r.initializeExporters(); err != nil {
		return nil, err
	}

	return r, nil
}

// initializeExporters creates exporters based on configuration
func (r *Registry) initializeExporters() error {
	// Initialize OTLP exporter if enabled
	if r.cfg.OTLP.Enabled {
		otlp, err := NewOTLPExporter(r.cfg.OTLP, r.log, r.st)
		if err != nil {
			return fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
		r.Register(otlp)
	}

	// Initialize debug exporter if enabled
	if r.cfg.Debug.Enabled {
		debug := NewDebugExporter(r.cfg.Debug, r.log)
		r.Register(debug)
	}

	return nil
}

// Register adds an exporter to the registry
func (r *Registry) Register(exp Exporter) {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := exp.Name()
	r.exporters[name] = exp

	// Index by supported signals
	for _, sigType := range exp.SupportedSignals() {
		r.bySignal[sigType] = append(r.bySignal[sigType], exp)
	}

	r.log.Info("registered exporter", "name", name, "signals", exp.SupportedSignals())
}

// Unregister removes an exporter from the registry
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	exp, ok := r.exporters[name]
	if !ok {
		return
	}

	delete(r.exporters, name)

	// Remove from signal index
	for _, sigType := range exp.SupportedSignals() {
		exporters := r.bySignal[sigType]
		for i, e := range exporters {
			if e.Name() == name {
				r.bySignal[sigType] = append(exporters[:i], exporters[i+1:]...)
				break
			}
		}
	}

	r.log.Info("unregistered exporter", "name", name)
}

// Start initializes all registered exporters
func (r *Registry) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("registry already running")
	}

	r.log.Info("starting exporter registry", "count", len(r.exporters))

	for name, exp := range r.exporters {
		if err := exp.Start(ctx); err != nil {
			return fmt.Errorf("failed to start exporter %s: %w", name, err)
		}
		r.log.Debug("started exporter", "name", name)
	}

	r.running = true
	return nil
}

// Stop shuts down all registered exporters
func (r *Registry) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	r.log.Info("stopping exporter registry")

	var errs []error
	for name, exp := range r.exporters {
		if err := exp.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("exporter %s: %w", name, err))
		}
	}

	r.running = false

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping exporters: %v", errs)
	}
	return nil
}

// Export exports signals to all relevant exporters
func (r *Registry) Export(ctx context.Context, signalType pipeline.SignalType, signals []pipeline.Signal) error {
	r.mu.RLock()
	exporters := r.bySignal[signalType]
	r.mu.RUnlock()

	if len(exporters) == 0 {
		return nil
	}

	var errs []error
	for _, exp := range exporters {
		if err := exp.Export(ctx, signalType, signals); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", exp.Name(), err))
			if r.st != nil {
				r.st.ExporterErrors.WithLabelValues(exp.Name(), string(signalType)).Inc()
			}
		} else {
			if r.st != nil {
				r.st.ExporterSuccess.WithLabelValues(exp.Name(), string(signalType)).Add(float64(len(signals)))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("export errors: %v", errs)
	}
	return nil
}

// ExportToExporter exports signals to a specific exporter by name
func (r *Registry) ExportToExporter(ctx context.Context, name string, signalType pipeline.SignalType, signals []pipeline.Signal) error {
	r.mu.RLock()
	exp, ok := r.exporters[name]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("exporter %s not found", name)
	}

	return exp.Export(ctx, signalType, signals)
}

// Get retrieves an exporter by name
func (r *Registry) Get(name string) (Exporter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	exp, ok := r.exporters[name]
	return exp, ok
}

// List returns all registered exporter names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.exporters))
	for name := range r.exporters {
		names = append(names, name)
	}
	return names
}

// Stats returns registry statistics
func (r *Registry) Stats() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RegistryStats{
		ExporterCount: len(r.exporters),
		Exporters:     make(map[string]ExporterInfo),
	}

	for name, exp := range r.exporters {
		stats.Exporters[name] = ExporterInfo{
			Name:    name,
			Signals: exp.SupportedSignals(),
		}
	}

	return stats
}

// RegistryStats holds registry statistics
type RegistryStats struct {
	ExporterCount int
	Exporters     map[string]ExporterInfo
}

// ExporterInfo holds information about an exporter
type ExporterInfo struct {
	Name    string
	Signals []pipeline.SignalType
}
