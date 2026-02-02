// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package ebpf provides eBPF program lifecycle management.
package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// ProgramType represents the type of eBPF program
type ProgramType string

const (
	ProgramKprobe        ProgramType = "kprobe"
	ProgramKretprobe     ProgramType = "kretprobe"
	ProgramUprobe        ProgramType = "uprobe"
	ProgramUretprobe     ProgramType = "uretprobe"
	ProgramTracepoint    ProgramType = "tracepoint"
	ProgramRawTracepoint ProgramType = "raw_tracepoint"
	ProgramPerfEvent     ProgramType = "perf_event"
	ProgramSocketFilter  ProgramType = "socket_filter"
	ProgramTC            ProgramType = "tc"
	ProgramXDP           ProgramType = "xdp"
	ProgramIter          ProgramType = "iter"
)

// ProgramInfo holds information about a loaded eBPF program
type ProgramInfo struct {
	Name        string
	Type        ProgramType
	Tag         string
	ID          uint32
	LoadedAt    time.Time
	AttachPoint string
}

// ManagerConfig holds eBPF manager configuration
type ManagerConfig struct {
	// BTFPath is an optional path to a BTF file
	BTFPath string `mapstructure:"btf_path"`

	// PinPath is the path for pinning BPF objects
	PinPath string `mapstructure:"pin_path"`

	// LogLevel for eBPF verifier (0-2)
	LogLevel int `mapstructure:"log_level"`

	// LogSize for verifier log buffer
	LogSize int `mapstructure:"log_size"`

	// RemoveRlimit removes memory rlimit for BPF
	RemoveRlimit bool `mapstructure:"remove_rlimit"`
}

// DefaultManagerConfig returns default configuration
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		PinPath:      "/sys/fs/bpf/telegen",
		LogLevel:     0,
		LogSize:      64 * 1024,
		RemoveRlimit: true,
	}
}

// Manager manages the lifecycle of eBPF programs
type Manager struct {
	cfg ManagerConfig
	log *slog.Logger
	st  *selftelemetry.Metrics

	// Loaded programs and their links
	mu       sync.RWMutex
	specs    map[string]*ebpf.CollectionSpec
	colls    map[string]*ebpf.Collection
	programs map[string]*ebpf.Program
	links    map[string]link.Link
	closers  []io.Closer

	// Shared maps
	maps *MapManager

	// Running state
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup //nolint:unused // reserved for graceful shutdown coordination
}

// NewManager creates a new eBPF program manager
func NewManager(cfg ManagerConfig, log *slog.Logger, st *selftelemetry.Metrics) (*Manager, error) {
	if cfg.RemoveRlimit {
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Warn("failed to remove memlock rlimit", "error", err)
		}
	}

	m := &Manager{
		cfg:      cfg,
		log:      log.With("component", "ebpf_manager"),
		st:       st,
		specs:    make(map[string]*ebpf.CollectionSpec),
		colls:    make(map[string]*ebpf.Collection),
		programs: make(map[string]*ebpf.Program),
		links:    make(map[string]link.Link),
		stopCh:   make(chan struct{}),
	}

	// Initialize map manager
	var err error
	m.maps, err = NewMapManager(cfg.PinPath, log, st)
	if err != nil {
		return nil, fmt.Errorf("failed to create map manager: %w", err)
	}

	// Ensure pin path exists
	if cfg.PinPath != "" {
		if err := os.MkdirAll(cfg.PinPath, 0755); err != nil {
			log.Warn("failed to create BPF pin path", "path", cfg.PinPath, "error", err)
		}
	}

	return m, nil
}

// Start initializes the manager
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return errors.New("manager already running")
	}

	m.log.Info("starting eBPF manager")
	m.running = true

	return nil
}

// Stop shuts down all loaded programs and releases resources
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.log.Info("stopping eBPF manager")
	close(m.stopCh)

	var errs []error

	// Close all links first
	for name, l := range m.links {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing link %s: %w", name, err))
		}
	}
	m.links = make(map[string]link.Link)

	// Close all programs
	for name, prog := range m.programs {
		if err := prog.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing program %s: %w", name, err))
		}
	}
	m.programs = make(map[string]*ebpf.Program)

	// Close all collections
	for name, coll := range m.colls {
		coll.Close()
		m.log.Debug("closed collection", "name", name)
	}
	m.colls = make(map[string]*ebpf.Collection)

	// Close additional closers
	for _, c := range m.closers {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	m.closers = nil

	// Close map manager
	if m.maps != nil {
		if err := m.maps.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	m.running = false

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}
	return nil
}

// LoadSpec loads an eBPF collection spec from bytes
func (m *Manager) LoadSpec(name string, spec *ebpf.CollectionSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.specs[name]; exists {
		return fmt.Errorf("spec %s already loaded", name)
	}

	m.specs[name] = spec
	m.log.Debug("loaded collection spec", "name", name)

	if m.st != nil {
		m.st.EBPFSpecsLoaded.Inc()
	}

	return nil
}

// LoadCollection creates a collection from a spec with optional options
func (m *Manager) LoadCollection(name string, opts *ebpf.CollectionOptions) (*ebpf.Collection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	spec, ok := m.specs[name]
	if !ok {
		return nil, fmt.Errorf("spec %s not found", name)
	}

	if opts == nil {
		opts = &ebpf.CollectionOptions{}
	}

	// Apply manager-level settings
	if m.cfg.LogLevel > 0 {
		opts.Programs.LogLevel = ebpf.LogLevel(m.cfg.LogLevel)
		if m.cfg.LogSize > 0 {
			opts.Programs.LogSizeStart = uint32(m.cfg.LogSize)
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
	if err != nil {
		if m.st != nil {
			m.st.EBPFLoadErrors.Inc()
		}
		return nil, fmt.Errorf("failed to load collection %s: %w", name, err)
	}

	m.colls[name] = coll
	m.log.Info("loaded eBPF collection", "name", name)

	if m.st != nil {
		m.st.EBPFCollectionsLoaded.Inc()
	}

	return coll, nil
}

// GetProgram retrieves a program by name
func (m *Manager) GetProgram(collName, progName string) (*ebpf.Program, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	coll, ok := m.colls[collName]
	if !ok {
		return nil, fmt.Errorf("collection %s not found", collName)
	}

	prog := coll.Programs[progName]
	if prog == nil {
		return nil, fmt.Errorf("program %s not found in collection %s", progName, collName)
	}

	return prog, nil
}

// AttachKprobe attaches a kprobe to a kernel function
func (m *Manager) AttachKprobe(collName, progName, symbol string) (link.Link, error) {
	prog, err := m.GetProgram(collName, progName)
	if err != nil {
		return nil, err
	}

	l, err := link.Kprobe(symbol, prog, nil)
	if err != nil {
		if m.st != nil {
			m.st.EBPFAttachErrors.Inc()
		}
		return nil, fmt.Errorf("failed to attach kprobe to %s: %w", symbol, err)
	}

	m.mu.Lock()
	linkName := fmt.Sprintf("%s/%s/%s", collName, progName, symbol)
	m.links[linkName] = l
	m.mu.Unlock()

	m.log.Debug("attached kprobe", "symbol", symbol, "program", progName)
	if m.st != nil {
		m.st.EBPFLinksActive.Inc()
	}

	return l, nil
}

// AttachKretprobe attaches a kretprobe to a kernel function
func (m *Manager) AttachKretprobe(collName, progName, symbol string) (link.Link, error) {
	prog, err := m.GetProgram(collName, progName)
	if err != nil {
		return nil, err
	}

	l, err := link.Kretprobe(symbol, prog, nil)
	if err != nil {
		if m.st != nil {
			m.st.EBPFAttachErrors.Inc()
		}
		return nil, fmt.Errorf("failed to attach kretprobe to %s: %w", symbol, err)
	}

	m.mu.Lock()
	linkName := fmt.Sprintf("%s/%s/%s_ret", collName, progName, symbol)
	m.links[linkName] = l
	m.mu.Unlock()

	m.log.Debug("attached kretprobe", "symbol", symbol, "program", progName)
	if m.st != nil {
		m.st.EBPFLinksActive.Inc()
	}

	return l, nil
}

// AttachTracepoint attaches a tracepoint program
func (m *Manager) AttachTracepoint(collName, progName, group, name string) (link.Link, error) {
	prog, err := m.GetProgram(collName, progName)
	if err != nil {
		return nil, err
	}

	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		if m.st != nil {
			m.st.EBPFAttachErrors.Inc()
		}
		return nil, fmt.Errorf("failed to attach tracepoint %s:%s: %w", group, name, err)
	}

	m.mu.Lock()
	linkName := fmt.Sprintf("%s/%s/%s:%s", collName, progName, group, name)
	m.links[linkName] = l
	m.mu.Unlock()

	m.log.Debug("attached tracepoint", "group", group, "name", name, "program", progName)
	if m.st != nil {
		m.st.EBPFLinksActive.Inc()
	}

	return l, nil
}

// AttachUprobe attaches a uprobe to a user-space function
func (m *Manager) AttachUprobe(collName, progName, path string, offset uint64) (link.Link, error) {
	prog, err := m.GetProgram(collName, progName)
	if err != nil {
		return nil, err
	}

	ex, err := link.OpenExecutable(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open executable %s: %w", path, err)
	}

	l, err := ex.Uprobe("", prog, &link.UprobeOptions{Offset: offset})
	if err != nil {
		if m.st != nil {
			m.st.EBPFAttachErrors.Inc()
		}
		return nil, fmt.Errorf("failed to attach uprobe: %w", err)
	}

	m.mu.Lock()
	linkName := fmt.Sprintf("%s/%s/uprobe_%d", collName, progName, offset)
	m.links[linkName] = l
	m.mu.Unlock()

	m.log.Debug("attached uprobe", "path", path, "offset", offset, "program", progName)
	if m.st != nil {
		m.st.EBPFLinksActive.Inc()
	}

	return l, nil
}

// DetachLink detaches a specific link
func (m *Manager) DetachLink(linkName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.links[linkName]
	if !ok {
		return fmt.Errorf("link %s not found", linkName)
	}

	if err := l.Close(); err != nil {
		return fmt.Errorf("failed to close link %s: %w", linkName, err)
	}

	delete(m.links, linkName)
	if m.st != nil {
		m.st.EBPFLinksActive.Dec()
	}

	return nil
}

// AddCloser adds a closer to be called on shutdown
func (m *Manager) AddCloser(c io.Closer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closers = append(m.closers, c)
}

// MapManager returns the map manager
func (m *Manager) MapManager() *MapManager {
	return m.maps
}

// ListPrograms returns information about all loaded programs
func (m *Manager) ListPrograms() []ProgramInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var infos []ProgramInfo
	for collName, coll := range m.colls {
		for progName, prog := range coll.Programs {
			info, err := prog.Info()
			if err != nil {
				continue
			}

			tag := info.Tag
			id, _ := info.ID()

			infos = append(infos, ProgramInfo{
				Name: fmt.Sprintf("%s/%s", collName, progName),
				ID:   uint32(id),
				Tag:  tag,
			})
		}
	}

	return infos
}

// Stats returns manager statistics
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return ManagerStats{
		SpecsLoaded:       len(m.specs),
		CollectionsLoaded: len(m.colls),
		ProgramsLoaded:    m.countPrograms(),
		LinksActive:       len(m.links),
	}
}

func (m *Manager) countPrograms() int {
	count := 0
	for _, coll := range m.colls {
		count += len(coll.Programs)
	}
	return count
}

// ManagerStats holds manager statistics
type ManagerStats struct {
	SpecsLoaded       int
	CollectionsLoaded int
	ProgramsLoaded    int
	LinksActive       int
}
