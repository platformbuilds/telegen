// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package profiler provides CPU/off-CPU/allocation/mutex/wall profiling for Telegen.
// StackTraceIDCache maps symbolic stack trace signatures to stable integer IDs using
// a dual-map aging strategy to bound memory usage while preserving cross-period ID
// consistency for flamegraph aggregation.
//
// Ported from Pixie's StackTraceIDCache
// (src/stirling/source_connectors/perf_profiler/stack_trace_id_cache.{h,cc}).
package profiler

import (
	"sync"
)

// StackTraceIDCache assigns stable uint64 IDs to symbolic stack traces, deduplicating
// repeated stacks within and across profiling periods.
//
// Design (identical to Pixie):
//   - Two maps: current and previous.
//   - Lookup checks current first, then previous (moving the entry to current on hit).
//   - New entries always go into current.
//   - AgeTick() rotates: previous ← current, current ← empty.
//   - Memory is bounded to 2× the active working set per period.
//
// ID stability guarantee: a stack trace seen in period N will receive the same ID in
// period N+1 if it is still active, because the previous map is checked before
// assigning a new ID.
type StackTraceIDCache struct {
	mu       sync.Mutex
	current  map[string]uint64
	previous map[string]uint64
	nextID   uint64
}

// NewStackTraceIDCache creates an empty cache. The first ID assigned will be 1.
func NewStackTraceIDCache() *StackTraceIDCache {
	return &StackTraceIDCache{
		current:  make(map[string]uint64),
		previous: make(map[string]uint64),
	}
}

// Lookup returns the existing ID for sig, or assigns a new one.
//
// Algorithm mirrors Pixie's stack_trace_id_cache.cc:
//  1. Check current map — O(1) cache hit.
//  2. Check previous map — if found, migrate entry to current (ID reuse).
//  3. Otherwise assign nextID++ and store in current.
func (c *StackTraceIDCache) Lookup(sig string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Fast path: already in current period.
	if id, ok := c.current[sig]; ok {
		return id
	}

	// Warm path: in previous period — promote without allocating a new ID.
	if id, ok := c.previous[sig]; ok {
		c.current[sig] = id
		return id
	}

	// Cold path: genuinely new stack trace.
	c.nextID++
	c.current[sig] = c.nextID
	return c.nextID
}

// AgeTick rotates the maps at the end of a profiling period.
// After rotation:
//   - current is empty (ready for the next period).
//   - previous holds the entries from the just-finished period.
//
// Entries that appeared in the old previous map and were NOT seen in the just-finished
// period are dropped, bounding maximum memory to 2× peak working set.
func (c *StackTraceIDCache) AgeTick() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.previous = c.current
	c.current = make(map[string]uint64, len(c.previous))
}

// Size returns the current and previous map sizes (for diagnostic purposes).
func (c *StackTraceIDCache) Size() (current, previous int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.current), len(c.previous)
}

// Reset clears all state without resetting the ID counter.
// Use during tests or when a process is restarted.
func (c *StackTraceIDCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = make(map[string]uint64)
	c.previous = make(map[string]uint64)
}
