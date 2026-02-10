// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"container/list"
	"sync"
	"time"
)

// LRUCache is a thread-safe bounded LRU cache for process symbols
type LRUCache struct {
	mu       sync.RWMutex
	capacity int
	items    map[uint32]*cacheEntry
	lru      *list.List
	ttl      time.Duration
}

type cacheEntry struct {
	pid       uint32
	symbols   *ProcessSymbols
	element   *list.Element
	createdAt time.Time
	lastUsed  time.Time
}

// NewLRUCache creates a new LRU cache with the given capacity and TTL
func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	if capacity <= 0 {
		capacity = 1000 // Default capacity
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute // Default TTL
	}
	return &LRUCache{
		capacity: capacity,
		items:    make(map[uint32]*cacheEntry, capacity),
		lru:      list.New(),
		ttl:      ttl,
	}
}

// Get retrieves symbols for a PID
func (c *LRUCache) Get(pid uint32) (*ProcessSymbols, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[pid]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Since(entry.createdAt) > c.ttl {
		c.removeEntry(entry)
		return nil, false
	}

	// Move to front of LRU
	c.lru.MoveToFront(entry.element)
	entry.lastUsed = time.Now()
	return entry.symbols, true
}

// Put adds symbols for a PID to the cache
func (c *LRUCache) Put(pid uint32, symbols *ProcessSymbols) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Update existing entry
	if entry, ok := c.items[pid]; ok {
		entry.symbols = symbols
		entry.lastUsed = now
		c.lru.MoveToFront(entry.element)
		return
	}

	// Evict if at capacity
	if len(c.items) >= c.capacity {
		c.evictOldest()
	}

	// Add new entry
	entry := &cacheEntry{
		pid:       pid,
		symbols:   symbols,
		createdAt: now,
		lastUsed:  now,
	}
	entry.element = c.lru.PushFront(entry)
	c.items[pid] = entry
}

// Delete removes symbols for a PID
func (c *LRUCache) Delete(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[pid]; ok {
		c.removeEntry(entry)
	}
}

// Clear removes all entries
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[uint32]*cacheEntry, c.capacity)
	c.lru.Init()
}

// Size returns the current cache size
func (c *LRUCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// CleanExpired removes expired entries
func (c *LRUCache) CleanExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for pid, entry := range c.items {
		if now.Sub(entry.createdAt) > c.ttl {
			c.removeEntry(entry)
			removed++
			delete(c.items, pid)
		}
	}

	return removed
}

func (c *LRUCache) evictOldest() {
	element := c.lru.Back()
	if element != nil {
		entry := element.Value.(*cacheEntry)
		c.removeEntry(entry)
	}
}

func (c *LRUCache) removeEntry(entry *cacheEntry) {
	c.lru.Remove(entry.element)
	delete(c.items, entry.pid)
}

// Stats returns cache statistics
func (c *LRUCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := CacheStats{
		Size:     len(c.items),
		Capacity: c.capacity,
	}

	now := time.Now()
	for _, entry := range c.items {
		age := now.Sub(entry.createdAt)
		if age < stats.OldestAge || stats.OldestAge == 0 {
			stats.OldestAge = age
		}
	}

	return stats
}

// CacheStats holds cache statistics
type CacheStats struct {
	Size      int
	Capacity  int
	OldestAge time.Duration
}
