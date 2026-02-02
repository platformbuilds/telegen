// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const thermalZoneCollectorName = "thermal_zone"

func init() {
	Register(thermalZoneCollectorName, true, NewThermalZoneCollector)
}

// thermalZoneCollector exports thermal zone temperatures.
type thermalZoneCollector struct {
	sysPath string
	temp    *prometheus.Desc
	logger  *slog.Logger
}

// NewThermalZoneCollector returns a new Collector exposing thermal zone temperatures.
func NewThermalZoneCollector(config CollectorConfig) (Collector, error) {
	return &thermalZoneCollector{
		sysPath: config.Paths.SysPath,
		temp: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "thermal_zone", "temp"),
			"Zone temperature in Celsius.",
			[]string{"zone", "type"}, nil,
		),
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes thermal zone temperatures.
func (c *thermalZoneCollector) Update(ch chan<- prometheus.Metric) error {
	thermalPath := filepath.Join(c.sysPath, "class/thermal")

	// Find all thermal zones
	entries, err := os.ReadDir(thermalPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Debug("thermal zone path not found", "path", thermalPath)
			return ErrNoData
		}
		return fmt.Errorf("couldn't read thermal zones: %w", err)
	}

	var foundZones bool
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "thermal_zone") {
			continue
		}

		zonePath := filepath.Join(thermalPath, entry.Name())

		// Read temperature
		tempBytes, err := os.ReadFile(filepath.Join(zonePath, "temp"))
		if err != nil {
			c.logger.Debug("couldn't read temperature",
				"zone", entry.Name(),
				"error", err)
			continue
		}

		temp, err := strconv.ParseFloat(strings.TrimSpace(string(tempBytes)), 64)
		if err != nil {
			c.logger.Debug("couldn't parse temperature",
				"zone", entry.Name(),
				"value", string(tempBytes),
				"error", err)
			continue
		}

		// Read zone type
		typeBytes, err := os.ReadFile(filepath.Join(zonePath, "type"))
		zoneType := "unknown"
		if err == nil {
			zoneType = strings.TrimSpace(string(typeBytes))
		}

		// Temperature is in millidegrees
		ch <- prometheus.MustNewConstMetric(
			c.temp,
			prometheus.GaugeValue,
			temp/1000.0,
			entry.Name(),
			zoneType,
		)
		foundZones = true
	}

	if !foundZones {
		return ErrNoData
	}

	return nil
}
