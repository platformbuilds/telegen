// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package redis provides Redis-specific database tracing utilities.
package redis

import (
	"container/heap"
	"hash/fnv"
	"sync"
	"time"
)

// HotKeyConfig holds configuration for hot key detection.
type HotKeyConfig struct {
	// MaxTrackedKeys is the maximum number of keys to track.
	MaxTrackedKeys int

	// DecayInterval is how often to apply decay to access counts.
	DecayInterval time.Duration

	// DecayFactor is multiplied with counts during decay (0-1).
	DecayFactor float64

	// ThresholdMultiplier defines how many times above average to be "hot".
	ThresholdMultiplier float64

	// MinAccessCount is the minimum accesses to be considered for hot key.
	MinAccessCount uint64
}

// DefaultHotKeyConfig returns the default hot key configuration.
func DefaultHotKeyConfig() HotKeyConfig {
	return HotKeyConfig{
		MaxTrackedKeys:      100000,
		DecayInterval:       1 * time.Minute,
		DecayFactor:         0.5,
		ThresholdMultiplier: 10.0,
		MinAccessCount:      100,
	}
}

// KeyStats holds statistics for a single key.
type KeyStats struct {
	Key         string
	KeyHash     uint64
	AccessCount uint64
	LastAccess  time.Time
	Command     string // Most recent command used with this key
	Size        uint32 // Estimated size (if available)

	// For heap implementation
	index int
}

// HotKeyTracker tracks hot keys by access frequency.
type HotKeyTracker struct {
	config     HotKeyConfig
	mu         sync.RWMutex
	keys       map[uint64]*KeyStats
	keyHeap    keyHeap
	totalCount uint64
	done       chan struct{}
}

// NewHotKeyTracker creates a new hot key tracker.
func NewHotKeyTracker(config HotKeyConfig) *HotKeyTracker {
	tracker := &HotKeyTracker{
		config:  config,
		keys:    make(map[uint64]*KeyStats),
		keyHeap: make(keyHeap, 0),
		done:    make(chan struct{}),
	}
	heap.Init(&tracker.keyHeap)
	return tracker
}

// Start starts background tasks for the hot key tracker.
func (hkt *HotKeyTracker) Start() {
	go hkt.decayLoop()
}

// Stop stops the hot key tracker.
func (hkt *HotKeyTracker) Stop() {
	close(hkt.done)
}

// RecordAccess records an access to a key.
func (hkt *HotKeyTracker) RecordAccess(key string, command string) {
	hash := hashKey(key)

	hkt.mu.Lock()
	defer hkt.mu.Unlock()

	hkt.totalCount++

	stats, exists := hkt.keys[hash]
	if exists {
		stats.AccessCount++
		stats.LastAccess = time.Now()
		stats.Command = command
		heap.Fix(&hkt.keyHeap, stats.index)
	} else {
		// Create new entry
		stats = &KeyStats{
			Key:         key,
			KeyHash:     hash,
			AccessCount: 1,
			LastAccess:  time.Now(),
			Command:     command,
		}

		// Check if we need to evict
		if len(hkt.keys) >= hkt.config.MaxTrackedKeys {
			hkt.evictLowest()
		}

		hkt.keys[hash] = stats
		heap.Push(&hkt.keyHeap, stats)
	}
}

// RecordAccessWithSize records an access with size information.
func (hkt *HotKeyTracker) RecordAccessWithSize(key string, command string, size uint32) {
	hash := hashKey(key)

	hkt.mu.Lock()
	defer hkt.mu.Unlock()

	hkt.totalCount++

	stats, exists := hkt.keys[hash]
	if exists {
		stats.AccessCount++
		stats.LastAccess = time.Now()
		stats.Command = command
		stats.Size = size
		heap.Fix(&hkt.keyHeap, stats.index)
	} else {
		stats = &KeyStats{
			Key:         key,
			KeyHash:     hash,
			AccessCount: 1,
			LastAccess:  time.Now(),
			Command:     command,
			Size:        size,
		}

		if len(hkt.keys) >= hkt.config.MaxTrackedKeys {
			hkt.evictLowest()
		}

		hkt.keys[hash] = stats
		heap.Push(&hkt.keyHeap, stats)
	}
}

// evictLowest removes the key with the lowest access count.
func (hkt *HotKeyTracker) evictLowest() {
	if len(hkt.keyHeap) == 0 {
		return
	}
	lowest := heap.Pop(&hkt.keyHeap).(*KeyStats)
	delete(hkt.keys, lowest.KeyHash)
}

// decayLoop periodically applies decay to access counts.
func (hkt *HotKeyTracker) decayLoop() {
	ticker := time.NewTicker(hkt.config.DecayInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hkt.applyDecay()
		case <-hkt.done:
			return
		}
	}
}

// applyDecay applies decay factor to all access counts.
func (hkt *HotKeyTracker) applyDecay() {
	hkt.mu.Lock()
	defer hkt.mu.Unlock()

	for _, stats := range hkt.keys {
		stats.AccessCount = uint64(float64(stats.AccessCount) * hkt.config.DecayFactor)
		if stats.AccessCount == 0 {
			stats.AccessCount = 1 // Keep at least 1
		}
	}

	hkt.totalCount = uint64(float64(hkt.totalCount) * hkt.config.DecayFactor)

	// Rebuild heap after decay
	hkt.keyHeap = make(keyHeap, 0, len(hkt.keys))
	for _, stats := range hkt.keys {
		heap.Push(&hkt.keyHeap, stats)
	}
}

// GetHotKeys returns keys that exceed the hot key threshold.
func (hkt *HotKeyTracker) GetHotKeys() []*KeyStats {
	hkt.mu.RLock()
	defer hkt.mu.RUnlock()

	if len(hkt.keys) == 0 {
		return nil
	}

	// Calculate average access count
	avgCount := hkt.totalCount / uint64(len(hkt.keys))
	threshold := uint64(float64(avgCount) * hkt.config.ThresholdMultiplier)
	if threshold < hkt.config.MinAccessCount {
		threshold = hkt.config.MinAccessCount
	}

	hotKeys := make([]*KeyStats, 0)
	for _, stats := range hkt.keys {
		if stats.AccessCount >= threshold {
			// Copy stats
			copy := *stats
			hotKeys = append(hotKeys, &copy)
		}
	}

	// Sort by access count (descending)
	for i := 0; i < len(hotKeys); i++ {
		for j := i + 1; j < len(hotKeys); j++ {
			if hotKeys[j].AccessCount > hotKeys[i].AccessCount {
				hotKeys[i], hotKeys[j] = hotKeys[j], hotKeys[i]
			}
		}
	}

	return hotKeys
}

// GetTopKeys returns the top N keys by access count.
func (hkt *HotKeyTracker) GetTopKeys(n int) []*KeyStats {
	hkt.mu.RLock()
	defer hkt.mu.RUnlock()

	if len(hkt.keys) == 0 {
		return nil
	}

	// Collect all keys
	all := make([]*KeyStats, 0, len(hkt.keys))
	for _, stats := range hkt.keys {
		copy := *stats
		all = append(all, &copy)
	}

	// Sort by access count (descending)
	for i := 0; i < len(all) && i < n; i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].AccessCount > all[i].AccessCount {
				all[i], all[j] = all[j], all[i]
			}
		}
	}

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// GetKeyStats returns stats for a specific key.
func (hkt *HotKeyTracker) GetKeyStats(key string) *KeyStats {
	hash := hashKey(key)

	hkt.mu.RLock()
	defer hkt.mu.RUnlock()

	stats, exists := hkt.keys[hash]
	if !exists {
		return nil
	}

	copy := *stats
	return &copy
}

// GetTotalCount returns the total access count.
func (hkt *HotKeyTracker) GetTotalCount() uint64 {
	hkt.mu.RLock()
	defer hkt.mu.RUnlock()
	return hkt.totalCount
}

// GetKeyCount returns the number of tracked keys.
func (hkt *HotKeyTracker) GetKeyCount() int {
	hkt.mu.RLock()
	defer hkt.mu.RUnlock()
	return len(hkt.keys)
}

// Reset clears all tracked keys.
func (hkt *HotKeyTracker) Reset() {
	hkt.mu.Lock()
	defer hkt.mu.Unlock()

	hkt.keys = make(map[uint64]*KeyStats)
	hkt.keyHeap = make(keyHeap, 0)
	hkt.totalCount = 0
	heap.Init(&hkt.keyHeap)
}

// hashKey computes a hash of the key.
func hashKey(key string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	return h.Sum64()
}

// keyHeap implements a min-heap for KeyStats by access count.
type keyHeap []*KeyStats

func (h keyHeap) Len() int           { return len(h) }
func (h keyHeap) Less(i, j int) bool { return h[i].AccessCount < h[j].AccessCount }

func (h keyHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *keyHeap) Push(x interface{}) {
	n := len(*h)
	stats := x.(*KeyStats)
	stats.index = n
	*h = append(*h, stats)
}

func (h *keyHeap) Pop() interface{} {
	old := *h
	n := len(old)
	stats := old[n-1]
	old[n-1] = nil
	stats.index = -1
	*h = old[0 : n-1]
	return stats
}

// CommandStats holds statistics for Redis commands.
type CommandStats struct {
	Command       string
	Count         uint64
	TotalDuration time.Duration
	AvgDuration   time.Duration
	MaxDuration   time.Duration
	ErrorCount    uint64
}

// CommandTracker tracks Redis command statistics.
type CommandTracker struct {
	mu       sync.RWMutex
	commands map[string]*CommandStats
}

// NewCommandTracker creates a new command tracker.
func NewCommandTracker() *CommandTracker {
	return &CommandTracker{
		commands: make(map[string]*CommandStats),
	}
}

// RecordCommand records a command execution.
func (ct *CommandTracker) RecordCommand(command string, duration time.Duration, hasError bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	stats, exists := ct.commands[command]
	if !exists {
		stats = &CommandStats{
			Command:     command,
			MaxDuration: duration,
		}
		ct.commands[command] = stats
	}

	stats.Count++
	stats.TotalDuration += duration
	if duration > stats.MaxDuration {
		stats.MaxDuration = duration
	}
	stats.AvgDuration = stats.TotalDuration / time.Duration(stats.Count)

	if hasError {
		stats.ErrorCount++
	}
}

// GetCommandStats returns stats for a specific command.
func (ct *CommandTracker) GetCommandStats(command string) *CommandStats {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	stats, exists := ct.commands[command]
	if !exists {
		return nil
	}
	copy := *stats
	return &copy
}

// GetAllCommandStats returns stats for all commands.
func (ct *CommandTracker) GetAllCommandStats() map[string]*CommandStats {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make(map[string]*CommandStats)
	for cmd, stats := range ct.commands {
		copy := *stats
		result[cmd] = &copy
	}
	return result
}

// GetTopCommands returns the top N commands by execution count.
func (ct *CommandTracker) GetTopCommands(n int) []*CommandStats {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	all := make([]*CommandStats, 0, len(ct.commands))
	for _, stats := range ct.commands {
		copy := *stats
		all = append(all, &copy)
	}

	// Sort by count (descending)
	for i := 0; i < len(all) && i < n; i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].Count > all[i].Count {
				all[i], all[j] = all[j], all[i]
			}
		}
	}

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// GetSlowestCommands returns the top N commands by average duration.
func (ct *CommandTracker) GetSlowestCommands(n int) []*CommandStats {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	all := make([]*CommandStats, 0, len(ct.commands))
	for _, stats := range ct.commands {
		copy := *stats
		all = append(all, &copy)
	}

	// Sort by avg duration (descending)
	for i := 0; i < len(all) && i < n; i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].AvgDuration > all[i].AvgDuration {
				all[i], all[j] = all[j], all[i]
			}
		}
	}

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// Reset clears all command stats.
func (ct *CommandTracker) Reset() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.commands = make(map[string]*CommandStats)
}
