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
	Name              string            `json:"name"`
	Value             float64           `json:"value"`
	Labels            map[string]string `json:"labels"`
	Timestamp         time.Time         `json:"timestamp"`          // Source timestamp (from gNMI, SNMP, etc.)
	ObservedTimestamp time.Time         `json:"observed_timestamp"` // Collection instant (time.Now() at collection time)
	Type              MetricType        `json:"type"`
}

// MetricType represents the type of metric
type MetricType string

const (
	// MetricTypeGauge represents a gauge metric
	MetricTypeGauge MetricType = "gauge"
	// MetricTypeCounter represents a counter metric
	MetricTypeCounter MetricType = "counter"
)

// NewMetricAt creates a new gauge metric with an explicit timestamp.
//
// The timestamp is mandatory by design. A clock-reading constructor used to
// exist here and was removed: because it sampled the clock once per metric, a
// collection cycle that walked hundreds of interfaces smeared its metrics
// across the cycle's full duration, and for counters that smear divides the
// delta by a wrong dt and corrupts every derived rate.
//
// Callers pass one instant hoisted per collection cycle, or the source
// system's own sample time when it provides one. See telegen/AGENTS.md
// "Timestamp Provenance".
func NewMetricAt(name string, value float64, labels map[string]string, timestamp time.Time) *NetworkMetric {
	return &NetworkMetric{
		Name:      name,
		Value:     value,
		Labels:    labels,
		Timestamp: timestamp,
		Type:      MetricTypeGauge,
	}
}

// NewCounterMetricAt creates a new counter metric with an explicit timestamp.
// The timestamp is mandatory for the reasons documented on NewMetricAt.
func NewCounterMetricAt(name string, value float64, labels map[string]string, timestamp time.Time) *NetworkMetric {
	return &NetworkMetric{
		Name:      name,
		Value:     value,
		Labels:    labels,
		Timestamp: timestamp,
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
