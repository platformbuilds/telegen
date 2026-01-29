// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// MapType represents the type of BPF map
type MapType string

const (
	MapTypeHash        MapType = "hash"
	MapTypeArray       MapType = "array"
	MapTypePerfEvent   MapType = "perf_event"
	MapTypeRingbuf     MapType = "ringbuf"
	MapTypeLRUHash     MapType = "lru_hash"
	MapTypePercpuHash  MapType = "percpu_hash"
	MapTypePercpuArray MapType = "percpu_array"
	MapTypeLPMTrie     MapType = "lpm_trie"
)

// MapInfo holds information about a BPF map
type MapInfo struct {
	Name       string
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	Pinned     bool
	PinPath    string
}

// MapSpec defines a map to be created
type MapSpec struct {
	Name       string
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	Pinning    bool
}

// MapManager manages BPF maps and their lifecycle
type MapManager struct {
	log     *slog.Logger
	st      *selftelemetry.Metrics
	pinPath string

	mu   sync.RWMutex
	maps map[string]*ebpf.Map
}

// NewMapManager creates a new map manager
func NewMapManager(pinPath string, log *slog.Logger, st *selftelemetry.Metrics) (*MapManager, error) {
	m := &MapManager{
		log:     log.With("component", "map_manager"),
		st:      st,
		pinPath: pinPath,
		maps:    make(map[string]*ebpf.Map),
	}

	// Ensure pin path exists
	if pinPath != "" {
		if err := os.MkdirAll(pinPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create pin path: %w", err)
		}
	}

	return m, nil
}

// CreateMap creates a new BPF map
func (m *MapManager) CreateMap(spec MapSpec) (*ebpf.Map, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already exists
	if existing, ok := m.maps[spec.Name]; ok {
		return existing, nil
	}

	ebpfSpec := &ebpf.MapSpec{
		Name:       spec.Name,
		Type:       spec.Type,
		KeySize:    spec.KeySize,
		ValueSize:  spec.ValueSize,
		MaxEntries: spec.MaxEntries,
		Flags:      spec.Flags,
	}

	// Try to load from pin first if pinning is enabled
	if spec.Pinning && m.pinPath != "" {
		pinPath := filepath.Join(m.pinPath, spec.Name)
		if pinnedMap, err := ebpf.LoadPinnedMap(pinPath, nil); err == nil {
			m.maps[spec.Name] = pinnedMap
			m.log.Debug("loaded pinned map", "name", spec.Name, "path", pinPath)
			if m.st != nil {
				m.st.EBPFMapsLoaded.Inc()
			}
			return pinnedMap, nil
		}
	}

	// Create new map
	newMap, err := ebpf.NewMap(ebpfSpec)
	if err != nil {
		if m.st != nil {
			m.st.EBPFMapErrors.Inc()
		}
		return nil, fmt.Errorf("failed to create map %s: %w", spec.Name, err)
	}

	// Pin if requested
	if spec.Pinning && m.pinPath != "" {
		pinPath := filepath.Join(m.pinPath, spec.Name)
		if err := newMap.Pin(pinPath); err != nil {
			m.log.Warn("failed to pin map", "name", spec.Name, "error", err)
		}
	}

	m.maps[spec.Name] = newMap
	m.log.Debug("created map", "name", spec.Name, "type", spec.Type)

	if m.st != nil {
		m.st.EBPFMapsLoaded.Inc()
	}

	return newMap, nil
}

// GetMap retrieves a map by name
func (m *MapManager) GetMap(name string) (*ebpf.Map, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mp, ok := m.maps[name]
	return mp, ok
}

// RegisterMap registers an externally created map
func (m *MapManager) RegisterMap(name string, mp *ebpf.Map) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.maps[name] = mp
	m.log.Debug("registered external map", "name", name)
}

// LoadPinnedMap loads a map from the pin path
func (m *MapManager) LoadPinnedMap(name string) (*ebpf.Map, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pinPath == "" {
		return nil, fmt.Errorf("no pin path configured")
	}

	pinPath := filepath.Join(m.pinPath, name)
	mp, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load pinned map %s: %w", name, err)
	}

	m.maps[name] = mp
	m.log.Debug("loaded pinned map", "name", name, "path", pinPath)

	if m.st != nil {
		m.st.EBPFMapsLoaded.Inc()
	}

	return mp, nil
}

// DeleteMap removes and closes a map
func (m *MapManager) DeleteMap(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mp, ok := m.maps[name]
	if !ok {
		return nil
	}

	// Unpin if pinned
	if m.pinPath != "" {
		pinPath := filepath.Join(m.pinPath, name)
		_ = os.Remove(pinPath)
	}

	if err := mp.Close(); err != nil {
		return fmt.Errorf("failed to close map %s: %w", name, err)
	}

	delete(m.maps, name)
	m.log.Debug("deleted map", "name", name)

	if m.st != nil {
		m.st.EBPFMapsLoaded.Dec()
	}

	return nil
}

// UpdateMap updates a value in a map
func (m *MapManager) UpdateMap(name string, key, value interface{}, flags uint64) error {
	mp, ok := m.GetMap(name)
	if !ok {
		return fmt.Errorf("map %s not found", name)
	}

	if err := mp.Update(key, value, ebpf.MapUpdateFlags(flags)); err != nil {
		if m.st != nil {
			m.st.EBPFMapErrors.Inc()
		}
		return fmt.Errorf("failed to update map %s: %w", name, err)
	}

	return nil
}

// LookupMap looks up a value in a map
func (m *MapManager) LookupMap(name string, key, value interface{}) error {
	mp, ok := m.GetMap(name)
	if !ok {
		return fmt.Errorf("map %s not found", name)
	}

	if err := mp.Lookup(key, value); err != nil {
		return err
	}

	return nil
}

// DeleteFromMap deletes a key from a map
func (m *MapManager) DeleteFromMap(name string, key interface{}) error {
	mp, ok := m.GetMap(name)
	if !ok {
		return fmt.Errorf("map %s not found", name)
	}

	if err := mp.Delete(key); err != nil {
		return fmt.Errorf("failed to delete from map %s: %w", name, err)
	}

	return nil
}

// ListMaps returns information about all managed maps
func (m *MapManager) ListMaps() []MapInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var infos []MapInfo
	for name, mp := range m.maps {
		info, err := mp.Info()
		if err != nil {
			continue
		}

		infos = append(infos, MapInfo{
			Name:       name,
			Type:       mapTypeToString(info.Type),
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
			MaxEntries: info.MaxEntries,
			Flags:      info.Flags,
		})
	}

	return infos
}

// Close closes all managed maps
func (m *MapManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for name, mp := range m.maps {
		if err := mp.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing map %s: %w", name, err))
		}
	}
	m.maps = make(map[string]*ebpf.Map)

	if len(errs) > 0 {
		return fmt.Errorf("errors closing maps: %v", errs)
	}
	return nil
}

// Stats returns map manager statistics
func (m *MapManager) Stats() MapManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return MapManagerStats{
		MapsLoaded: len(m.maps),
	}
}

// MapManagerStats holds map manager statistics
type MapManagerStats struct {
	MapsLoaded int
}

func mapTypeToString(t ebpf.MapType) MapType {
	switch t {
	case ebpf.Hash:
		return MapTypeHash
	case ebpf.Array:
		return MapTypeArray
	case ebpf.PerfEventArray:
		return MapTypePerfEvent
	case ebpf.RingBuf:
		return MapTypeRingbuf
	case ebpf.LRUHash:
		return MapTypeLRUHash
	case ebpf.PerCPUHash:
		return MapTypePercpuHash
	case ebpf.PerCPUArray:
		return MapTypePercpuArray
	case ebpf.LPMTrie:
		return MapTypeLPMTrie
	default:
		return MapType(fmt.Sprintf("unknown(%d)", t))
	}
}
