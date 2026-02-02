// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector

import (
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

const entropyCollectorName = "entropy"

func init() {
	Register(entropyCollectorName, true, NewEntropyCollector)
}

// entropyCollector exports entropy pool statistics.
type entropyCollector struct {
	fs              procfs.FS
	entropyAvail    *prometheus.Desc
	entropyPoolSize *prometheus.Desc
	logger          *slog.Logger
}

// NewEntropyCollector returns a new entropy collector.
func NewEntropyCollector(config CollectorConfig) (Collector, error) {
	fs, err := procfs.NewFS(config.Paths.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	return &entropyCollector{
		fs: fs,
		entropyAvail: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "entropy_available_bits"),
			"Bits of available entropy.",
			nil, nil,
		),
		entropyPoolSize: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "entropy_pool_size_bits"),
			"Bits of entropy pool.",
			nil, nil,
		),
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes entropy statistics.
func (c *entropyCollector) Update(ch chan<- prometheus.Metric) error {
	stats, err := c.fs.KernelRandom()
	if err != nil {
		return fmt.Errorf("failed to get kernel random stats: %w", err)
	}

	if stats.EntropyAvaliable == nil {
		return fmt.Errorf("couldn't get entropy_avail")
	}
	ch <- prometheus.MustNewConstMetric(
		c.entropyAvail, prometheus.GaugeValue, float64(*stats.EntropyAvaliable))

	if stats.PoolSize == nil {
		return fmt.Errorf("couldn't get entropy poolsize")
	}
	ch <- prometheus.MustNewConstMetric(
		c.entropyPoolSize, prometheus.GaugeValue, float64(*stats.PoolSize))

	return nil
}
