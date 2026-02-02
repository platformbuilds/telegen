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

const filefdCollectorName = "filefd"

func init() {
	Register(filefdCollectorName, true, NewFilefdCollector)
}

// filefdCollector exports file descriptor statistics.
type filefdCollector struct {
	fs     procfs.FS
	logger *slog.Logger
}

// NewFilefdCollector returns a new Collector exposing file descriptor stats.
func NewFilefdCollector(config CollectorConfig) (Collector, error) {
	fs, err := procfs.NewFS(config.Paths.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	return &filefdCollector{
		fs:     fs,
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes file descriptor statistics.
func (c *filefdCollector) Update(ch chan<- prometheus.Metric) error {
	fileFDStat, err := c.fs.FileDescriptorsStats()
	if err != nil {
		return fmt.Errorf("couldn't get file-nr: %w", err)
	}

	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "filefd", "allocated"),
			"File descriptor statistics: allocated.",
			nil, nil,
		),
		prometheus.GaugeValue,
		float64(fileFDStat.Allocated),
	)
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "filefd", "maximum"),
			"File descriptor statistics: maximum.",
			nil, nil,
		),
		prometheus.GaugeValue,
		float64(fileFDStat.Maximum),
	)

	return nil
}
