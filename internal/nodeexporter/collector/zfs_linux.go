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
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const zfsCollectorName = "zfs"

func init() {
	Register(zfsCollectorName, true, NewZFSCollector)
}

// zfsCollector exports ZFS metrics from /proc/spl/kstat/zfs.
type zfsCollector struct {
	logger   *slog.Logger
	procPath string
}

// NewZFSCollector returns a new ZFS collector.
func NewZFSCollector(config CollectorConfig) (Collector, error) {
	return &zfsCollector{
		logger:   config.Logger,
		procPath: config.Paths.ProcPath,
	}, nil
}

// Update implements Collector and exposes ZFS metrics.
func (c *zfsCollector) Update(ch chan<- prometheus.Metric) error {
	zfsPath := filepath.Join(c.procPath, "spl/kstat/zfs")

	// Check if ZFS is available
	if _, err := os.Stat(zfsPath); os.IsNotExist(err) {
		c.logger.Debug("ZFS not available on this system")
		return ErrNoData
	}

	// Export ARC stats
	if err := c.updateArcStats(ch, zfsPath); err != nil {
		c.logger.Debug("failed to get ARC stats", "err", err)
	}

	// Export pool stats
	if err := c.updatePoolStats(ch, zfsPath); err != nil {
		c.logger.Debug("failed to get pool stats", "err", err)
	}

	return nil
}

// updateArcStats reads and exports ARC (Adaptive Replacement Cache) statistics.
func (c *zfsCollector) updateArcStats(ch chan<- prometheus.Metric, zfsPath string) error {
	arcstatsPath := filepath.Join(zfsPath, "arcstats")
	stats, err := c.parseKstat(arcstatsPath)
	if err != nil {
		return err
	}

	for name, value := range stats {
		// Determine if it's a counter or gauge based on naming conventions
		metricType := prometheus.GaugeValue
		if strings.HasSuffix(name, "_total") || strings.HasSuffix(name, "_count") ||
			strings.Contains(name, "hits") || strings.Contains(name, "misses") {
			metricType = prometheus.CounterValue
		}

		desc := prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "zfs_arc", name),
			fmt.Sprintf("ZFS ARC statistic %s.", name),
			nil, nil,
		)
		ch <- prometheus.MustNewConstMetric(desc, metricType, value)
	}

	return nil
}

// updatePoolStats reads and exports per-pool statistics.
func (c *zfsCollector) updatePoolStats(ch chan<- prometheus.Metric, zfsPath string) error {
	entries, err := os.ReadDir(zfsPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		poolName := entry.Name()
		// Skip non-pool directories
		if poolName == "." || poolName == ".." {
			continue
		}

		poolPath := filepath.Join(zfsPath, poolName)

		// Try to read io stats
		iostatPath := filepath.Join(poolPath, "io")
		if stats, err := c.parseKstat(iostatPath); err == nil {
			for name, value := range stats {
				metricType := prometheus.CounterValue
				if strings.Contains(name, "queue") || strings.Contains(name, "running") {
					metricType = prometheus.GaugeValue
				}

				desc := prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "zfs_pool", name),
					fmt.Sprintf("ZFS pool IO statistic %s.", name),
					[]string{"pool"}, nil,
				)
				ch <- prometheus.MustNewConstMetric(desc, metricType, value, poolName)
			}
		}

		// Try to read objset stats
		objsetPath := filepath.Join(poolPath, "objset-0x1")
		if stats, err := c.parseKstat(objsetPath); err == nil {
			for name, value := range stats {
				metricType := prometheus.CounterValue

				desc := prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "zfs_pool_objset", name),
					fmt.Sprintf("ZFS pool objset statistic %s.", name),
					[]string{"pool"}, nil,
				)
				ch <- prometheus.MustNewConstMetric(desc, metricType, value, poolName)
			}
		}
	}

	return nil
}

// parseKstat parses a kstat file and returns key-value pairs.
func (c *zfsCollector) parseKstat(path string) (map[string]float64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats := make(map[string]float64)
	scanner := bufio.NewScanner(file)

	// Skip header lines
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		// First two lines are typically headers
		if lineNum <= 2 {
			continue
		}

		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name := fields[0]
		// Skip non-numeric types
		valueStr := fields[2]
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			continue
		}

		// Normalize name
		name = strings.ReplaceAll(name, "-", "_")
		stats[name] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return stats, nil
}
