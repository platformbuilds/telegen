// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package database provides eBPF-based database and message queue tracing.
// It supports PostgreSQL, MySQL, Oracle, Redis, and Kafka.
package database

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TracerConfig holds configuration for a database tracer.
type TracerConfig struct {
	// Enabled determines if this tracer is active.
	Enabled bool

	// LibraryPaths are paths to search for database client libraries.
	LibraryPaths []string

	// MaxQueryLength is the maximum query length to capture.
	MaxQueryLength int

	// CaptureParameters determines if query parameters are captured.
	CaptureParameters bool

	// SampleRate is the sampling rate (0.0 to 1.0).
	SampleRate float64
}

// DefaultTracerConfig returns the default tracer configuration.
func DefaultTracerConfig() TracerConfig {
	return TracerConfig{
		Enabled:           true,
		LibraryPaths:      []string{"/usr/lib", "/usr/local/lib", "/lib"},
		MaxQueryLength:    4096,
		CaptureParameters: false,
		SampleRate:        1.0,
	}
}

// Tracer interface defines the methods for a database tracer.
type Tracer interface {
	// Name returns the tracer name.
	Name() string

	// DatabaseType returns the database type this tracer handles.
	DatabaseType() DatabaseType

	// Start starts the tracer.
	Start(ctx context.Context) error

	// Stop stops the tracer.
	Stop() error

	// Events returns a channel of database events.
	Events() <-chan *DatabaseEvent
}

// ManagerConfig holds configuration for the database tracing manager.
type ManagerConfig struct {
	// Tracers is a map of database type to tracer configuration.
	Tracers map[DatabaseType]TracerConfig

	// AutoDetect enables automatic detection of database clients.
	AutoDetect bool

	// EventBufferSize is the size of the event buffer.
	EventBufferSize int

	// Logger is the logger to use.
	Logger *slog.Logger
}

// DefaultManagerConfig returns the default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		Tracers: map[DatabaseType]TracerConfig{
			DBTypePostgreSQL: DefaultTracerConfig(),
			DBTypeMySQL:      DefaultTracerConfig(),
			DBTypeOracle:     DefaultTracerConfig(),
			DBTypeRedis:      DefaultTracerConfig(),
			DBTypeKafka:      DefaultTracerConfig(),
		},
		AutoDetect:      true,
		EventBufferSize: 10000,
		Logger:          slog.Default(),
	}
}

// Manager coordinates all database tracers.
type Manager struct {
	config  ManagerConfig
	tracers map[DatabaseType]Tracer
	events  chan *DatabaseEvent
	mu      sync.RWMutex
	running bool
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewManager creates a new database tracing manager.
func NewManager(config ManagerConfig) *Manager {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Manager{
		config:  config,
		tracers: make(map[DatabaseType]Tracer),
		events:  make(chan *DatabaseEvent, config.EventBufferSize),
		done:    make(chan struct{}),
	}
}

// RegisterTracer registers a tracer for a database type.
func (m *Manager) RegisterTracer(tracer Tracer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dbType := tracer.DatabaseType()
	if _, exists := m.tracers[dbType]; exists {
		return fmt.Errorf("tracer already registered for %s", dbType)
	}

	m.tracers[dbType] = tracer
	m.config.Logger.Info("registered database tracer",
		"database", dbType.String(),
		"tracer", tracer.Name())
	return nil
}

// Start starts all registered tracers.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("manager already running")
	}
	m.running = true
	m.mu.Unlock()

	m.config.Logger.Info("starting database tracing manager",
		"tracers", len(m.tracers))

	// Start each tracer
	for dbType, tracer := range m.tracers {
		config, ok := m.config.Tracers[dbType]
		if !ok || !config.Enabled {
			continue
		}

		if err := tracer.Start(ctx); err != nil {
			m.config.Logger.Error("failed to start tracer",
				"database", dbType.String(),
				"error", err)
			continue
		}

		// Forward events from tracer to manager's event channel
		m.wg.Add(1)
		go m.forwardEvents(tracer)
	}

	return nil
}

// forwardEvents forwards events from a tracer to the manager's event channel.
func (m *Manager) forwardEvents(tracer Tracer) {
	defer m.wg.Done()

	for {
		select {
		case <-m.done:
			return
		case event, ok := <-tracer.Events():
			if !ok {
				return
			}
			select {
			case m.events <- event:
			default:
				// Buffer full, drop event
				m.config.Logger.Warn("event buffer full, dropping event",
					"database", tracer.DatabaseType().String())
			}
		}
	}
}

// Stop stops all tracers.
func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	m.mu.Unlock()

	close(m.done)

	var errs []error
	for dbType, tracer := range m.tracers {
		if err := tracer.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop %s tracer: %w", dbType, err))
		}
	}

	m.wg.Wait()
	close(m.events)

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping tracers: %v", errs)
	}
	return nil
}

// Events returns a channel of database events from all tracers.
func (m *Manager) Events() <-chan *DatabaseEvent {
	return m.events
}

// GetTracer returns the tracer for a specific database type.
func (m *Manager) GetTracer(dbType DatabaseType) (Tracer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tracer, ok := m.tracers[dbType]
	return tracer, ok
}

// DetectDatabaseType attempts to detect the database type from a process.
func DetectDatabaseType(pid int) DatabaseType {
	// Read process executable name
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	exe, err := os.Readlink(exePath)
	if err != nil {
		return DBTypeUnknown
	}

	baseName := strings.ToLower(filepath.Base(exe))

	// Check for common database client processes
	switch {
	case strings.Contains(baseName, "postgres") || strings.Contains(baseName, "psql"):
		return DBTypePostgreSQL
	case strings.Contains(baseName, "mysql") || strings.Contains(baseName, "mariadb"):
		return DBTypeMySQL
	case strings.Contains(baseName, "oracle") || strings.Contains(baseName, "sqlplus"):
		return DBTypeOracle
	case strings.Contains(baseName, "redis"):
		return DBTypeRedis
	case strings.Contains(baseName, "kafka"):
		return DBTypeKafka
	}

	// Check loaded libraries via /proc/PID/maps
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return DBTypeUnknown
	}

	maps := string(data)
	switch {
	case strings.Contains(maps, "libpq.so"):
		return DBTypePostgreSQL
	case strings.Contains(maps, "libmysqlclient.so") || strings.Contains(maps, "libmariadb.so"):
		return DBTypeMySQL
	case strings.Contains(maps, "libclntsh.so") || strings.Contains(maps, "libocci.so"):
		return DBTypeOracle
	case strings.Contains(maps, "libhiredis.so"):
		return DBTypeRedis
	case strings.Contains(maps, "librdkafka.so"):
		return DBTypeKafka
	}

	return DBTypeUnknown
}

// FindLibrary searches for a library in the given paths.
func FindLibrary(name string, paths []string) (string, bool) {
	for _, dir := range paths {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
		// Also check with version suffixes
		matches, _ := filepath.Glob(path + ".*")
		if len(matches) > 0 {
			return matches[0], true
		}
	}
	return "", false
}
