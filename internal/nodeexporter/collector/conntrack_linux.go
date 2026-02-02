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
	"github.com/prometheus/procfs"
)

const conntrackCollectorName = "conntrack"

func init() {
	Register(conntrackCollectorName, true, NewConntrackCollector)
}

// conntrackCollector exports conntrack statistics.
type conntrackCollector struct {
	current *prometheus.Desc
	limit   *prometheus.Desc
	found   *prometheus.Desc
	invalid *prometheus.Desc
	ignore  *prometheus.Desc
	insert  *prometheus.Desc
	delete  *prometheus.Desc
	drop    *prometheus.Desc
	logger  *slog.Logger
	fs      procfs.FS
}

// NewConntrackCollector returns a new Collector exposing conntrack statistics.
func NewConntrackCollector(config CollectorConfig) (Collector, error) {
	fs, err := procfs.NewFS(config.Paths.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	return &conntrackCollector{
		current: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "nf_conntrack", "entries"),
			"Number of currently allocated flow entries for connection tracking.",
			nil, nil,
		),
		limit: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "nf_conntrack", "entries_limit"),
			"Maximum size of connection tracking table.",
			nil, nil,
		),
		found: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "nf_conntrack", "stat_found"),
			"Number of searched entries which were found.",
			nil, nil,
		),
		invalid: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "nf_conntrack", "stat_invalid"),
			"Number of packets seen which can not be tracked.",
			nil, nil,
		),
		ignore: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "nf_conntrack", "stat_ignore"),
			"Number of packets seen which are already connected to a conntrack entry.",
			nil, nil,
		),
		insert: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "nf_conntrack", "stat_insert"),
			"Number of entries inserted into the list.",
			nil, nil,
		),
		delete: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "nf_conntrack", "stat_delete"),
			"Number of entries deleted from the list.",
			nil, nil,
		),
		drop: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "nf_conntrack", "stat_drop"),
			"Number of conntrack entries dropped due to full table.",
			nil, nil,
		),
		logger: config.Logger,
		fs:     fs,
	}, nil
}

// readConntrackValue reads a single uint64 value from a proc file.
func (c *conntrackCollector) readConntrackValue(filename string) (uint64, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// Update implements Collector and exposes conntrack statistics.
func (c *conntrackCollector) Update(ch chan<- prometheus.Metric) error {
	// Get current entries count from /proc/sys/net/netfilter/nf_conntrack_count
	countPath := filepath.Join("/proc", "sys/net/netfilter/nf_conntrack_count")
	current, err := c.readConntrackValue(countPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Debug("conntrack count file not found")
			return ErrNoData
		}
		return fmt.Errorf("couldn't get conntrack count: %w", err)
	}
	ch <- prometheus.MustNewConstMetric(c.current, prometheus.GaugeValue, float64(current))

	// Get max entries from /proc/sys/net/netfilter/nf_conntrack_max
	maxPath := filepath.Join("/proc", "sys/net/netfilter/nf_conntrack_max")
	limit, err := c.readConntrackValue(maxPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Debug("conntrack max file not found")
		} else {
			return fmt.Errorf("couldn't get conntrack max: %w", err)
		}
	} else {
		ch <- prometheus.MustNewConstMetric(c.limit, prometheus.GaugeValue, float64(limit))
	}

	// Get conntrack stats
	stats, err := c.fs.ConntrackStat()
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Debug("conntrack stat file not found")
			return nil
		}
		return fmt.Errorf("couldn't get conntrack stats: %w", err)
	}

	// Sum up stats from all CPUs
	var found, invalid, ignore, insert, del, drop uint64
	for _, s := range stats {
		found += s.Found
		invalid += s.Invalid
		ignore += s.Ignore
		insert += s.Insert
		del += s.Delete
		drop += s.Drop
	}

	ch <- prometheus.MustNewConstMetric(c.found, prometheus.CounterValue, float64(found))
	ch <- prometheus.MustNewConstMetric(c.invalid, prometheus.CounterValue, float64(invalid))
	ch <- prometheus.MustNewConstMetric(c.ignore, prometheus.CounterValue, float64(ignore))
	ch <- prometheus.MustNewConstMetric(c.insert, prometheus.CounterValue, float64(insert))
	ch <- prometheus.MustNewConstMetric(c.delete, prometheus.CounterValue, float64(del))
	ch <- prometheus.MustNewConstMetric(c.drop, prometheus.CounterValue, float64(drop))

	return nil
}
