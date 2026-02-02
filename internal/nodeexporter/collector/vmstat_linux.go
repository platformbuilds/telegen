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

const vmstatCollectorName = "vmstat"

func init() {
	Register(vmstatCollectorName, true, NewVmstatCollector)
}

// vmstatCollector implements the Collector interface.
type vmstatCollector struct {
	procPath string
	logger   *slog.Logger
}

// NewVmstatCollector returns a new Collector exposing vmstat stats.
func NewVmstatCollector(config CollectorConfig) (Collector, error) {
	return &vmstatCollector{
		procPath: config.Paths.ProcPath,
		logger:   config.Logger,
	}, nil
}

// Update reads /proc/vmstat and exposes all fields as prometheus metrics.
func (c *vmstatCollector) Update(ch chan<- prometheus.Metric) error {
	file, err := os.Open(filepath.Join(c.procPath, "vmstat"))
	if err != nil {
		return fmt.Errorf("failed to open vmstat: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		name := parts[0]
		value, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			c.logger.Debug("failed to parse vmstat value",
				"field", name,
				"value", parts[1],
				"error", err)
			continue
		}

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "vmstat", name),
				fmt.Sprintf("vmstat information field %s.", name),
				nil, nil,
			),
			prometheus.UntypedValue,
			value,
		)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading vmstat: %w", err)
	}

	return nil
}
