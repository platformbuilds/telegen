// Copyright 2015 The Prometheus Authors
// Copyright 2024 The Telegen Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const bondingCollectorName = "bonding"

func init() {
	Register(bondingCollectorName, true, NewBondingCollector)
}

// bondingCollector exports bonding interface metrics.
type bondingCollector struct {
	slaves  *prometheus.Desc
	active  *prometheus.Desc
	logger  *slog.Logger
	sysPath string
}

// NewBondingCollector returns a new bonding collector.
func NewBondingCollector(config CollectorConfig) (Collector, error) {
	return &bondingCollector{
		slaves: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "bonding", "slaves"),
			"Number of configured slaves per bonding interface.",
			[]string{"master"}, nil,
		),
		active: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "bonding", "active"),
			"Number of active slaves per bonding interface.",
			[]string{"master"}, nil,
		),
		logger:  config.Logger,
		sysPath: config.Paths.SysPath,
	}, nil
}

// Update implements Collector and exposes bonding metrics.
func (c *bondingCollector) Update(ch chan<- prometheus.Metric) error {
	bondingPath := filepath.Join(c.sysPath, "class/net")

	entries, err := os.ReadDir(bondingPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Debug("bonding not available on this system")
			return ErrNoData
		}
		return fmt.Errorf("failed to read bonding interfaces: %w", err)
	}

	bondingFound := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		master := entry.Name()
		bondingDir := filepath.Join(bondingPath, master, "bonding")

		// Check if this is a bonding interface
		if _, err := os.Stat(bondingDir); os.IsNotExist(err) {
			continue
		}

		bondingFound = true

		// Read slaves
		slavesPath := filepath.Join(bondingDir, "slaves")
		slavesData, err := os.ReadFile(slavesPath)
		if err != nil {
			c.logger.Debug("failed to read bonding slaves", "master", master, "err", err)
			continue
		}

		slaves := strings.Fields(string(slavesData))
		ch <- prometheus.MustNewConstMetric(
			c.slaves,
			prometheus.GaugeValue,
			float64(len(slaves)),
			master,
		)

		// Count active slaves by checking their MII status
		activeCount := 0
		for _, slave := range slaves {
			miiPath := filepath.Join(c.sysPath, "class/net", slave, "bonding_slave", "mii_status")
			miiData, err := os.ReadFile(miiPath)
			if err != nil {
				// Try alternate path
				miiPath = filepath.Join(c.sysPath, "class/net", slave, "operstate")
				miiData, err = os.ReadFile(miiPath)
				if err != nil {
					continue
				}
			}
			status := strings.TrimSpace(string(miiData))
			if status == "up" || status == "1" {
				activeCount++
			}
		}

		ch <- prometheus.MustNewConstMetric(
			c.active,
			prometheus.GaugeValue,
			float64(activeCount),
			master,
		)
	}

	if !bondingFound {
		return ErrNoData
	}

	return nil
}
