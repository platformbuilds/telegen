// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"io"
	"sync"

	"k8s.io/client-go/tools/cache"
)

// MetricsStore implements cache.Store interface and stores generated metrics
type MetricsStore struct {
	mu sync.RWMutex

	// metrics stores the serialized metrics for each object
	// key: object key (namespace/name or just name)
	// value: serialized metrics bytes
	metrics map[string][]byte

	// headers contains the HELP/TYPE lines for all metrics
	headers []byte

	// generateMetricsFunc generates metrics from an object
	generateMetricsFunc func(obj interface{}) []byte

	// keyFunc extracts a key from an object
	keyFunc cache.KeyFunc
}

// NewMetricsStore creates a new MetricsStore
func NewMetricsStore(
	headers []byte,
	generateMetricsFunc func(obj interface{}) []byte,
) *MetricsStore {
	return &MetricsStore{
		metrics:             make(map[string][]byte),
		headers:             headers,
		generateMetricsFunc: generateMetricsFunc,
		keyFunc:             cache.DeletionHandlingMetaNamespaceKeyFunc,
	}
}

// NewMetricsStoreWithKey creates a new MetricsStore with a custom key function
func NewMetricsStoreWithKey(
	headers []byte,
	generateMetricsFunc func(obj interface{}) []byte,
	keyFunc cache.KeyFunc,
) *MetricsStore {
	return &MetricsStore{
		metrics:             make(map[string][]byte),
		headers:             headers,
		generateMetricsFunc: generateMetricsFunc,
		keyFunc:             keyFunc,
	}
}

// Add adds an object to the store
func (s *MetricsStore) Add(obj interface{}) error {
	key, err := s.keyFunc(obj)
	if err != nil {
		return err
	}

	metrics := s.generateMetricsFunc(obj)

	s.mu.Lock()
	s.metrics[key] = metrics
	s.mu.Unlock()

	return nil
}

// Update updates an object in the store
func (s *MetricsStore) Update(obj interface{}) error {
	return s.Add(obj)
}

// Delete removes an object from the store
func (s *MetricsStore) Delete(obj interface{}) error {
	key, err := s.keyFunc(obj)
	if err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.metrics, key)
	s.mu.Unlock()

	return nil
}

// List returns all objects in the store (not implemented, returns nil)
func (s *MetricsStore) List() []interface{} {
	return nil
}

// ListKeys returns all keys in the store
func (s *MetricsStore) ListKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.metrics))
	for key := range s.metrics {
		keys = append(keys, key)
	}
	return keys
}

// Get returns an object from the store (not implemented, returns nil)
func (s *MetricsStore) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, false, nil
}

// GetByKey returns an object by key (not implemented, returns nil)
func (s *MetricsStore) GetByKey(key string) (item interface{}, exists bool, err error) {
	return nil, false, nil
}

// Replace replaces all objects in the store
func (s *MetricsStore) Replace(list []interface{}, _ string) error {
	s.mu.Lock()
	s.metrics = make(map[string][]byte, len(list))
	s.mu.Unlock()

	for _, obj := range list {
		if err := s.Add(obj); err != nil {
			return err
		}
	}
	return nil
}

// Resync is a no-op for this store
func (s *MetricsStore) Resync() error {
	return nil
}

// WriteAll writes all metrics to the writer
func (s *MetricsStore) WriteAll(w io.Writer) error {
	// Write headers first
	if len(s.headers) > 0 {
		if _, err := w.Write(s.headers); err != nil {
			return err
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, data := range s.metrics {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}

	return nil
}

// Size returns the number of objects in the store
func (s *MetricsStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.metrics)
}

// GetMetricsByKey returns serialized metrics for a specific key
func (s *MetricsStore) GetMetricsByKey(key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.metrics[key]
	return data, ok
}

// ComposedMetricsStore combines multiple MetricsStores
type ComposedMetricsStore struct {
	stores []*MetricsStore
}

// NewComposedMetricsStore creates a new ComposedMetricsStore
func NewComposedMetricsStore(stores ...*MetricsStore) *ComposedMetricsStore {
	return &ComposedMetricsStore{stores: stores}
}

// WriteAll writes all metrics from all stores
func (c *ComposedMetricsStore) WriteAll(w io.Writer) error {
	for _, store := range c.stores {
		if err := store.WriteAll(w); err != nil {
			return err
		}
	}
	return nil
}

// Size returns total size across all stores
func (c *ComposedMetricsStore) Size() int {
	total := 0
	for _, store := range c.stores {
		total += store.Size()
	}
	return total
}
