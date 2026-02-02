// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const filefdCollectorName = "filefd"

func init() {
	Register(filefdCollectorName, true, NewFilefdCollector)
}

// filefdCollector exports file descriptor statistics.
type filefdCollector struct {
	procPath string
	logger   *slog.Logger
}

// NewFilefdCollector returns a new Collector exposing file descriptor stats.
func NewFilefdCollector(config CollectorConfig) (Collector, error) {
	return &filefdCollector{
		procPath: config.Paths.ProcPath,
		logger:   config.Logger,
	}, nil
}

// Update implements Collector and exposes file descriptor statistics.
func (c *filefdCollector) Update(ch chan<- prometheus.Metric) error {
	allocated, maximum, err := c.readFileNr()
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
		float64(allocated),
	)
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "filefd", "maximum"),
			"File descriptor statistics: maximum.",
			nil, nil,
		),
		prometheus.GaugeValue,
		float64(maximum),
	)

	return nil
}

// readFileNr reads /proc/sys/fs/file-nr and returns allocated and maximum file descriptors.
func (c *filefdCollector) readFileNr() (allocated, maximum uint64, err error) {
	path := filepath.Join(c.procPath, "sys", "fs", "file-nr")
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			allocated, err = strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("failed to parse allocated: %w", err)
			}
			maximum, err = strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("failed to parse maximum: %w", err)
			}
		}
	}

	return allocated, maximum, scanner.Err()
}
