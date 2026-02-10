// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Manager coordinates profilers and profile collection
type Manager struct {
	config Config
	log    *slog.Logger

	mu        sync.RWMutex
	profilers map[ProfileType]Profiler
	collector *Collector
	resolver  *SymbolResolver

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new profiler manager
func NewManager(config Config, log *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		config:    config,
		log:       log.With("component", "profiler_manager"),
		profilers: make(map[ProfileType]Profiler),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// SetCollector sets the profile collector
func (m *Manager) SetCollector(collector *Collector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collector = collector
}

// SetResolver sets the symbol resolver
func (m *Manager) SetResolver(resolver *SymbolResolver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolver = resolver
	if m.collector != nil {
		m.collector.SetSymbolResolver(resolver)
	}
}

// Register registers a profiler for a profile type
func (m *Manager) Register(profileType ProfileType, profiler Profiler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.profilers[profileType]; exists {
		return errors.New("profiler already registered for type: " + string(profileType))
	}

	m.profilers[profileType] = profiler
	m.log.Info("registered profiler", "type", profileType)
	return nil
}

// Unregister removes a profiler
func (m *Manager) Unregister(profileType ProfileType) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.profilers, profileType)
}

// Start starts all registered profilers
func (m *Manager) Start() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for ptype, profiler := range m.profilers {
		if err := profiler.Start(m.ctx); err != nil {
			m.log.Error("failed to start profiler", "type", ptype, "error", err)
			return err
		}
		m.log.Info("started profiler", "type", ptype)

		// Start collection goroutine
		m.wg.Add(1)
		go m.collectProfiles(ptype, profiler)
	}

	return nil
}

// Stop stops all profilers
func (m *Manager) Stop() error {
	m.cancel()
	m.wg.Wait()

	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for ptype, profiler := range m.profilers {
		if err := profiler.Stop(); err != nil {
			m.log.Error("failed to stop profiler", "type", ptype, "error", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (m *Manager) collectProfiles(ptype ProfileType, profiler Profiler) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			profile, err := profiler.Collect(m.ctx)
			if err != nil {
				m.log.Debug("failed to collect profile", "type", ptype, "error", err)
				continue
			}
			if profile != nil && m.collector != nil {
				m.collector.Collect(profile)
			}
		}
	}
}

// GetProfiler returns a profiler by type
func (m *Manager) GetProfiler(ptype ProfileType) Profiler {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.profilers[ptype]
}

// Types returns all registered profile types
func (m *Manager) Types() []ProfileType {
	m.mu.RLock()
	defer m.mu.RUnlock()

	types := make([]ProfileType, 0, len(m.profilers))
	for t := range m.profilers {
		types = append(types, t)
	}
	return types
}
