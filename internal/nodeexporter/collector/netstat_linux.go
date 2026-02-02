// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

const netstatCollectorName = "netstat"

func init() {
	Register(netstatCollectorName, true, NewNetstatCollector)
}

// netstatCollector implements the Collector interface.
type netstatCollector struct {
	fs     procfs.FS
	logger *slog.Logger
}

// NewNetstatCollector returns a new Collector exposing network statistics.
func NewNetstatCollector(config CollectorConfig) (Collector, error) {
	fs, err := procfs.NewFS(config.Paths.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	return &netstatCollector{
		fs:     fs,
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes netstat stats.
func (c *netstatCollector) Update(ch chan<- prometheus.Metric) error {
	// Get netstat metrics - NetStat() returns []NetStat
	netStats, err := c.fs.NetStat()
	if err != nil {
		return fmt.Errorf("couldn't get netstat: %w", err)
	}

	// Each NetStat has Filename and Stats map[string][]uint64
	for _, ns := range netStats {
		// Extract protocol from filename (e.g., "netstat" -> "TcpExt", "snmp" -> "Ip", "Tcp", etc.)
		protocol := extractProtocol(ns.Filename)

		for statName, values := range ns.Stats {
			// Take first value if available
			if len(values) > 0 {
				metricName := sanitizeMetricName(protocol + "_" + statName)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(Namespace, "netstat", metricName),
						fmt.Sprintf("Statistic %s from %s.", statName, ns.Filename),
						nil, nil,
					),
					prometheus.UntypedValue,
					float64(values[0]),
				)
			}
		}
	}

	return nil
}

// extractProtocol extracts a protocol prefix from the filename.
func extractProtocol(filename string) string {
	// Common file patterns: /proc/net/netstat, /proc/net/snmp, etc.
	parts := strings.Split(filename, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "unknown"
}

// sanitizeMetricName cleans the name for prometheus compatibility.
func sanitizeMetricName(name string) string {
	// Replace any non-alphanumeric chars with underscore
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}
