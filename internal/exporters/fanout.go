// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"context"
	"log/slog"
	"sync"

	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// FanoutExporter exports signals to multiple destinations in parallel
type FanoutExporter struct {
	name      string
	log       *slog.Logger
	st        *selftelemetry.Metrics
	exporters []Exporter

	// Configuration
	failFast    bool // Stop on first error
	maxParallel int  // Max parallel exports (0 = unlimited)

	mu      sync.RWMutex
	running bool
}

// FanoutConfig holds fanout exporter configuration
type FanoutConfig struct {
	// Name of this fanout exporter
	Name string `mapstructure:"name"`

	// FailFast stops on first error if true
	FailFast bool `mapstructure:"fail_fast"`

	// MaxParallel limits concurrent exports (0 = unlimited)
	MaxParallel int `mapstructure:"max_parallel"`
}

// NewFanoutExporter creates a new fanout exporter
func NewFanoutExporter(
	cfg FanoutConfig,
	exporters []Exporter,
	log *slog.Logger,
	st *selftelemetry.Metrics,
) *FanoutExporter {
	name := cfg.Name
	if name == "" {
		name = "fanout"
	}

	return &FanoutExporter{
		name:        name,
		log:         log.With("component", "fanout_exporter", "name", name),
		st:          st,
		exporters:   exporters,
		failFast:    cfg.FailFast,
		maxParallel: cfg.MaxParallel,
	}
}

func (f *FanoutExporter) Name() string {
	return f.name
}

func (f *FanoutExporter) Start(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.running {
		return nil
	}

	f.log.Info("starting fanout exporter", "destinations", len(f.exporters))

	// Start all child exporters
	for _, exp := range f.exporters {
		if err := exp.Start(ctx); err != nil {
			return err
		}
	}

	f.running = true
	return nil
}

func (f *FanoutExporter) Stop(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.running {
		return nil
	}

	f.log.Info("stopping fanout exporter")

	var errs []error
	for _, exp := range f.exporters {
		if err := exp.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	f.running = false

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (f *FanoutExporter) Export(ctx context.Context, signalType sigdef.SignalType, signals []sigdef.Signal) error {
	if len(f.exporters) == 0 {
		return nil
	}

	// For a single exporter, just call directly
	if len(f.exporters) == 1 {
		return f.exporters[0].Export(ctx, signalType, signals)
	}

	// Parallel export
	return f.exportParallel(ctx, signalType, signals)
}

func (f *FanoutExporter) exportParallel(ctx context.Context, signalType sigdef.SignalType, signals []sigdef.Signal) error {
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, len(f.exporters))
		sem     chan struct{}
	)

	// Create semaphore if max parallel is set
	if f.maxParallel > 0 {
		sem = make(chan struct{}, f.maxParallel)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, exp := range f.exporters {
		// Check if signal type is supported
		if !f.supportsSignal(exp, signalType) {
			continue
		}

		wg.Add(1)
		go func(e Exporter) {
			defer wg.Done()

			// Acquire semaphore if set
			if sem != nil {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
			}

			if err := e.Export(ctx, signalType, signals); err != nil {
				errChan <- err
				if f.failFast {
					cancel()
				}
				if f.st != nil {
					f.st.FanoutExportError.WithLabelValues(f.name, e.Name()).Inc()
				}
			} else {
				if f.st != nil {
					f.st.FanoutExportSuccess.WithLabelValues(f.name, e.Name()).Inc()
				}
			}
		}(exp)
	}

	// Wait for all exports to complete
	wg.Wait()
	close(errChan)

	// Collect errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (f *FanoutExporter) supportsSignal(exp Exporter, signalType sigdef.SignalType) bool {
	for _, s := range exp.SupportedSignals() {
		if s == signalType {
			return true
		}
	}
	return false
}

func (f *FanoutExporter) SupportedSignals() []sigdef.SignalType {
	// Collect all supported signals from child exporters
	signalSet := make(map[sigdef.SignalType]struct{})
	for _, exp := range f.exporters {
		for _, s := range exp.SupportedSignals() {
			signalSet[s] = struct{}{}
		}
	}

	signals := make([]sigdef.SignalType, 0, len(signalSet))
	for s := range signalSet {
		signals = append(signals, s)
	}
	return signals
}

// Add adds an exporter to the fanout
func (f *FanoutExporter) Add(exp Exporter) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exporters = append(f.exporters, exp)
}

// Remove removes an exporter from the fanout by name
func (f *FanoutExporter) Remove(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, exp := range f.exporters {
		if exp.Name() == name {
			f.exporters = append(f.exporters[:i], f.exporters[i+1:]...)
			return
		}
	}
}

// Count returns the number of child exporters
func (f *FanoutExporter) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.exporters)
}
