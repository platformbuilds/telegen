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

const sockstatCollectorName = "sockstat"

func init() {
	Register(sockstatCollectorName, true, NewSockstatCollector)
}

// sockstatCollector implements the Collector interface.
type sockstatCollector struct {
	fs     procfs.FS
	logger *slog.Logger
}

// NewSockstatCollector returns a new Collector exposing socket statistics.
func NewSockstatCollector(config CollectorConfig) (Collector, error) {
	fs, err := procfs.NewFS(config.Paths.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	return &sockstatCollector{
		fs:     fs,
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes socket statistics.
func (c *sockstatCollector) Update(ch chan<- prometheus.Metric) error {
	// Get IPv4 socket stats
	stat, err := c.fs.NetSockstat()
	if err != nil {
		return fmt.Errorf("couldn't get sockstat: %w", err)
	}

	// Used sockets
	if stat.Used != nil {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "sockstat", "sockets_used"),
				"Number of used sockets.",
				nil, nil,
			),
			prometheus.GaugeValue,
			float64(*stat.Used),
		)
	}

	// Per-protocol stats
	for _, ps := range stat.Protocols {
		prefix := "sockstat_" + ps.Protocol + "_"

		if ps.InUse != 0 {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "", prefix+"inuse"),
					fmt.Sprintf("Number of %s sockets in use.", ps.Protocol),
					nil, nil,
				),
				prometheus.GaugeValue,
				float64(ps.InUse),
			)
		}
		if ps.Orphan != nil {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "", prefix+"orphan"),
					fmt.Sprintf("Number of %s orphaned sockets.", ps.Protocol),
					nil, nil,
				),
				prometheus.GaugeValue,
				float64(*ps.Orphan),
			)
		}
		if ps.TW != nil {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "", prefix+"tw"),
					fmt.Sprintf("Number of %s TIME_WAIT sockets.", ps.Protocol),
					nil, nil,
				),
				prometheus.GaugeValue,
				float64(*ps.TW),
			)
		}
		if ps.Alloc != nil {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "", prefix+"alloc"),
					fmt.Sprintf("Number of %s sockets allocated.", ps.Protocol),
					nil, nil,
				),
				prometheus.GaugeValue,
				float64(*ps.Alloc),
			)
		}
		if ps.Mem != nil {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "", prefix+"mem"),
					fmt.Sprintf("Memory used by %s sockets in pages.", ps.Protocol),
					nil, nil,
				),
				prometheus.GaugeValue,
				float64(*ps.Mem),
			)
		}
		if ps.Memory != nil {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "", prefix+"memory"),
					fmt.Sprintf("Memory used by %s sockets in bytes.", ps.Protocol),
					nil, nil,
				),
				prometheus.GaugeValue,
				float64(*ps.Memory),
			)
		}
	}

	return nil
}
