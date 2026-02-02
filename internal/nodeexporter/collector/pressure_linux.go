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

const pressureCollectorName = "pressure"

func init() {
	Register(pressureCollectorName, false, NewPressureCollector)
}

// pressureCollector exports PSI (Pressure Stall Information) stats.
type pressureCollector struct {
	fs     procfs.FS
	logger *slog.Logger

	cpuSome    *prometheus.Desc
	cpuFull    *prometheus.Desc
	memorySome *prometheus.Desc
	memoryFull *prometheus.Desc
	ioSome     *prometheus.Desc
	ioFull     *prometheus.Desc
}

// NewPressureCollector returns a new Collector exposing PSI stats.
func NewPressureCollector(config CollectorConfig) (Collector, error) {
	fs, err := procfs.NewFS(config.Paths.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	return &pressureCollector{
		fs:     fs,
		logger: config.Logger,
		cpuSome: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "pressure", "cpu_waiting_seconds_total"),
			"Total time in seconds that processes have been waiting for CPU time.",
			nil, nil,
		),
		memorySome: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "pressure", "memory_waiting_seconds_total"),
			"Total time in seconds that processes have been waiting for memory.",
			nil, nil,
		),
		memoryFull: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "pressure", "memory_stalled_seconds_total"),
			"Total time in seconds that all processes have been stalled waiting for memory.",
			nil, nil,
		),
		ioSome: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "pressure", "io_waiting_seconds_total"),
			"Total time in seconds that processes have been waiting for I/O.",
			nil, nil,
		),
		ioFull: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "pressure", "io_stalled_seconds_total"),
			"Total time in seconds that all processes have been stalled waiting for I/O.",
			nil, nil,
		),
	}, nil
}

// Update implements Collector and exposes PSI stats.
func (c *pressureCollector) Update(ch chan<- prometheus.Metric) error {
	// Get CPU pressure
	cpuStats, err := c.fs.PSIStatsForResource("cpu")
	if err != nil {
		c.logger.Debug("couldn't get CPU pressure stats", "error", err)
	} else {
		if cpuStats.Some != nil {
			ch <- prometheus.MustNewConstMetric(
				c.cpuSome,
				prometheus.CounterValue,
				float64(cpuStats.Some.Total)/1e6, // Convert from microseconds to seconds
			)
		}
	}

	// Get memory pressure
	memStats, err := c.fs.PSIStatsForResource("memory")
	if err != nil {
		c.logger.Debug("couldn't get memory pressure stats", "error", err)
	} else {
		if memStats.Some != nil {
			ch <- prometheus.MustNewConstMetric(
				c.memorySome,
				prometheus.CounterValue,
				float64(memStats.Some.Total)/1e6,
			)
		}
		if memStats.Full != nil {
			ch <- prometheus.MustNewConstMetric(
				c.memoryFull,
				prometheus.CounterValue,
				float64(memStats.Full.Total)/1e6,
			)
		}
	}

	// Get I/O pressure
	ioStats, err := c.fs.PSIStatsForResource("io")
	if err != nil {
		c.logger.Debug("couldn't get I/O pressure stats", "error", err)
	} else {
		if ioStats.Some != nil {
			ch <- prometheus.MustNewConstMetric(
				c.ioSome,
				prometheus.CounterValue,
				float64(ioStats.Some.Total)/1e6,
			)
		}
		if ioStats.Full != nil {
			ch <- prometheus.MustNewConstMetric(
				c.ioFull,
				prometheus.CounterValue,
				float64(ioStats.Full.Total)/1e6,
			)
		}
	}

	return nil
}
