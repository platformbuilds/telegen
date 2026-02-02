// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package collector provides the core collector framework for node_exporter
// compatible metrics collection. This package is adapted from the Prometheus
// node_exporter project with modifications to use telegen's configuration system.
package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Namespace is the default metric namespace.
const Namespace = "node"

// Collector is the interface a collector has to implement.
type Collector interface {
	// Update gets new metrics and exposes them via prometheus registry.
	Update(ch chan<- prometheus.Metric) error
}

// CollectorConfig holds the configuration for a collector.
type CollectorConfig struct {
	// Paths holds path configuration
	Paths PathConfig

	// Logger for the collector
	Logger *slog.Logger

	// CollectorTimeout is the maximum time for a collector to complete
	CollectorTimeout time.Duration

	// CPUConfig holds CPU-specific configuration
	CPUConfig *CPUCollectorConfig

	// Extra holds collector-specific configuration
	Extra map[string]interface{}
}

// typedDesc wraps a prometheus.Desc with a value type for convenience.
type typedDesc struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

// mustNewConstMetric creates a new const metric, panicking on error.
func (d *typedDesc) mustNewConstMetric(value float64, labels ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(d.desc, d.valueType, value, labels...)
}

// ErrNoData indicates the collector found no data to collect, but had no other error.
var ErrNoData = errors.New("collector returned no data")

// IsNoDataError checks if an error is a no-data error.
func IsNoDataError(err error) bool {
	return errors.Is(err, ErrNoData)
}

// NodeCollector implements the prometheus.Collector interface.
type NodeCollector struct {
	Collectors       map[string]Collector
	logger           *slog.Logger
	namespace        string
	collectorTimeout time.Duration
	continueOnError  bool

	// Metrics about collection
	scrapeDurationDesc *prometheus.Desc
	scrapeSuccessDesc  *prometheus.Desc
}

// NewNodeCollector creates a new NodeCollector with the given collectors.
func NewNodeCollector(
	namespace string,
	collectors map[string]Collector,
	logger *slog.Logger,
	collectorTimeout time.Duration,
	continueOnError bool,
) *NodeCollector {
	return &NodeCollector{
		Collectors:       collectors,
		logger:           logger,
		namespace:        namespace,
		collectorTimeout: collectorTimeout,
		continueOnError:  continueOnError,
		scrapeDurationDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "scrape", "collector_duration_seconds"),
			"Duration of a collector scrape.",
			[]string{"collector"},
			nil,
		),
		scrapeSuccessDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "scrape", "collector_success"),
			"Whether a collector succeeded.",
			[]string{"collector"},
			nil,
		),
	}
}

// Describe implements the prometheus.Collector interface.
func (n *NodeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- n.scrapeDurationDesc
	ch <- n.scrapeSuccessDesc
}

// Collect implements the prometheus.Collector interface.
func (n *NodeCollector) Collect(ch chan<- prometheus.Metric) {
	wg := sync.WaitGroup{}
	wg.Add(len(n.Collectors))
	for name, c := range n.Collectors {
		go func(name string, c Collector) {
			defer wg.Done()
			n.execute(name, c, ch)
		}(name, c)
	}
	wg.Wait()
}

// execute runs a single collector with timing and error handling.
func (n *NodeCollector) execute(name string, c Collector, ch chan<- prometheus.Metric) {
	begin := time.Now()

	// Create a channel for the result
	done := make(chan error, 1)
	go func() {
		done <- c.Update(ch)
	}()

	var err error
	select {
	case err = <-done:
		// Collector completed
	case <-time.After(n.collectorTimeout):
		err = fmt.Errorf("collector timeout after %s", n.collectorTimeout)
	}

	duration := time.Since(begin)
	var success float64

	if err != nil {
		if IsNoDataError(err) {
			n.logger.Debug("collector returned no data",
				"collector", name,
				"duration_seconds", duration.Seconds(),
				"err", err)
		} else {
			n.logger.Error("collector failed",
				"collector", name,
				"duration_seconds", duration.Seconds(),
				"err", err)
		}
		success = 0
	} else {
		n.logger.Debug("collector succeeded",
			"collector", name,
			"duration_seconds", duration.Seconds())
		success = 1
	}

	ch <- prometheus.MustNewConstMetric(n.scrapeDurationDesc, prometheus.GaugeValue, duration.Seconds(), name)
	ch <- prometheus.MustNewConstMetric(n.scrapeSuccessDesc, prometheus.GaugeValue, success, name)
}

// pushMetric helps construct and convert a variety of value types into Prometheus float64 metrics.
func pushMetric(ch chan<- prometheus.Metric, fieldDesc *prometheus.Desc, name string, value interface{}, valueType prometheus.ValueType, labelValues ...string) {
	var fVal float64
	switch val := value.(type) {
	case uint8:
		fVal = float64(val)
	case uint16:
		fVal = float64(val)
	case uint32:
		fVal = float64(val)
	case uint64:
		fVal = float64(val)
	case int64:
		fVal = float64(val)
	case float64:
		fVal = val
	case *uint8:
		if val == nil {
			return
		}
		fVal = float64(*val)
	case *uint16:
		if val == nil {
			return
		}
		fVal = float64(*val)
	case *uint32:
		if val == nil {
			return
		}
		fVal = float64(*val)
	case *uint64:
		if val == nil {
			return
		}
		fVal = float64(*val)
	case *int64:
		if val == nil {
			return
		}
		fVal = float64(*val)
	case *float64:
		if val == nil {
			return
		}
		fVal = *val
	default:
		return
	}
	ch <- prometheus.MustNewConstMetric(fieldDesc, valueType, fVal, labelValues...)
}
