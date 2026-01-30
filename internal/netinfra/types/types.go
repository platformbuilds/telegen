// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package types provides shared types for network infrastructure observability.
package types

import (
	"context"
	"time"
)

// NetworkMetric represents a metric collected from network infrastructure
type NetworkMetric struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels"`
	Timestamp time.Time         `json:"timestamp"`
	Type      MetricType        `json:"type"`
}

// MetricType represents the type of metric
type MetricType string

const (
	// MetricTypeGauge represents a gauge metric
	MetricTypeGauge MetricType = "gauge"
	// MetricTypeCounter represents a counter metric
	MetricTypeCounter MetricType = "counter"
)

// NewMetric creates a new network metric with default values
func NewMetric(name string, value float64, labels map[string]string) *NetworkMetric {
	return &NetworkMetric{
		Name:      name,
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
		Type:      MetricTypeGauge,
	}
}

// NewCounterMetric creates a new counter metric
func NewCounterMetric(name string, value float64, labels map[string]string) *NetworkMetric {
	return &NetworkMetric{
		Name:      name,
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
		Type:      MetricTypeCounter,
	}
}

// Clone creates a copy of the metric
func (m *NetworkMetric) Clone() *NetworkMetric {
	labels := make(map[string]string, len(m.Labels))
	for k, v := range m.Labels {
		labels[k] = v
	}
	return &NetworkMetric{
		Name:      m.Name,
		Value:     m.Value,
		Labels:    labels,
		Timestamp: m.Timestamp,
		Type:      m.Type,
	}
}

// Collector defines the interface for network infrastructure collectors
type Collector interface {
	// Name returns the collector name
	Name() string
	// Collect gathers metrics from the infrastructure
	Collect(ctx context.Context) ([]*NetworkMetric, error)
	// Close releases any resources held by the collector
	Close() error
}

// CollectorConfig defines common collector configuration
type CollectorConfig struct {
	Name            string            `mapstructure:"name" yaml:"name"`
	Enabled         bool              `mapstructure:"enabled" yaml:"enabled"`
	CollectInterval time.Duration     `mapstructure:"collect_interval" yaml:"collect_interval"`
	Timeout         time.Duration     `mapstructure:"timeout" yaml:"timeout"`
	Labels          map[string]string `mapstructure:"labels" yaml:"labels"`
}

// DefaultCollectorConfig returns sensible defaults
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		Enabled:         true,
		CollectInterval: 30 * time.Second,
		Timeout:         15 * time.Second,
		Labels:          make(map[string]string),
	}
}
