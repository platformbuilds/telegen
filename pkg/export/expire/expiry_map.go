// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expire // import "github.com/mirastacklabs-ai/telegen/pkg/export/expire"

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

type Clock func() time.Time

// ExpiryMap stores elements in a synchronized map, and removes them if they haven't been
// accessed/updated for a given time period
// TODO: optimize to minimize memory generation
type ExpiryMap[T any] struct {
	clock   Clock
	mt      sync.RWMutex
	ttl     time.Duration
	entries map[uint64][]*entry[T]
}

type entry[T any] struct {
	lastAccessNanos atomic.Int64
	labelValues     []string
	val             T
}

// NewExpiryMap creates an expiry map given a Clock implementation and a TTL.
// Its labeled instances are dropped if they haven't been updated during the
// last timeout period
func NewExpiryMap[T any](clock Clock, ttl time.Duration) *ExpiryMap[T] {
	em := &ExpiryMap[T]{
		ttl:     ttl,
		entries: map[uint64][]*entry[T]{},
		clock:   clock,
	}
	return em
}

// GetOrCreate returns the stored object for the given slice of label
// values. If that combination of
// label values is accessed for the first time, a new instance is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *ExpiryMap[T]) GetOrCreate(lbls []string, instancer func() T) T {
	now := ex.clock()

	h := labelsKeyHash(lbls)
	ex.mt.RLock()
	bucket, ok := ex.entries[h]
	ex.mt.RUnlock()
	if ok {
		for _, e := range bucket {
			if labelValuesEqual(e.labelValues, lbls) {
				e.lastAccessNanos.Store(now.UnixNano())
				return e.val
			}
		}
	}

	ex.mt.Lock()
	defer ex.mt.Unlock()
	// Re-check under write lock in case another goroutine created it.
	bucket = ex.entries[h]
	for _, e := range bucket {
		if labelValuesEqual(e.labelValues, lbls) {
			e.lastAccessNanos.Store(now.UnixNano())
			return e.val
		}
	}
	instance := instancer()
	newEntry := &entry[T]{
		labelValues: append([]string(nil), lbls...),
		val:         instance,
	}
	newEntry.lastAccessNanos.Store(now.UnixNano())
	ex.entries[h] = append(bucket, newEntry)
	return instance
}

// DeleteExpired entries and return their label set
func (ex *ExpiryMap[T]) DeleteExpired() []T {
	// If TTL is 0, disable expiration completely
	if ex.ttl == 0 {
		return nil
	}

	var delEntries []T
	ex.mt.Lock()
	defer ex.mt.Unlock()
	now := ex.clock()
	for k, bucket := range ex.entries {
		next := bucket[:0]
		for _, e := range bucket {
			lastAccess := time.Unix(0, e.lastAccessNanos.Load())
			if now.Sub(lastAccess) > ex.ttl {
				delEntries = append(delEntries, e.val)
				continue
			}
			next = append(next, e)
		}
		if len(next) == 0 {
			delete(ex.entries, k)
		} else {
			ex.entries[k] = next
		}
	}
	return delEntries
}

// DeleteAll cleans the map and returns a slice with its deleted elements
func (ex *ExpiryMap[T]) DeleteAll() []T {
	ex.mt.Lock()
	defer ex.mt.Unlock()
	entries := make([]T, 0, len(ex.entries))
	for k, bucket := range ex.entries {
		for _, e := range bucket {
			entries = append(entries, e.val)
		}
		delete(ex.entries, k)
	}
	return entries
}

// All returns an array with all the stored entries. It might contain expired entries
// if DeleteExpired is not invoked before it.
// TODO: use https://tip.golang.org/wiki/RangefuncExperiment when available
func (ex *ExpiryMap[T]) All() []T {
	ex.mt.RLock()
	items := make([]T, 0, len(ex.entries))
	for _, bucket := range ex.entries {
		for _, e := range bucket {
			items = append(items, e.val)
		}
	}
	ex.mt.RUnlock()
	return items
}

func labelsKeyHash(lbls []string) uint64 {
	h := fnv.New64a()
	for i := range lbls {
		_, _ = h.Write([]byte(lbls[i]))
		_, _ = h.Write([]byte{0xff})
	}
	return h.Sum64()
}

func labelValuesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
