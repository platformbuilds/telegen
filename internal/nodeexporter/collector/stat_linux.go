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

const statCollectorName = "stat"

func init() {
	Register(statCollectorName, true, NewStatCollector)
}

// statCollector exports system-wide statistics from /proc/stat.
type statCollector struct {
	fs           procfs.FS
	intr         *prometheus.Desc
	ctxt         *prometheus.Desc
	forks        *prometheus.Desc
	btime        *prometheus.Desc
	procsRunning *prometheus.Desc
	procsBlocked *prometheus.Desc
	softIRQ      *prometheus.Desc
	logger       *slog.Logger
}

// NewStatCollector returns a new Collector exposing system statistics.
func NewStatCollector(config CollectorConfig) (Collector, error) {
	fs, err := procfs.NewFS(config.Paths.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	return &statCollector{
		fs: fs,
		intr: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "intr_total"),
			"Total number of interrupts serviced.",
			nil, nil,
		),
		ctxt: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "context_switches_total"),
			"Total number of context switches.",
			nil, nil,
		),
		forks: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "forks_total"),
			"Total number of forks.",
			nil, nil,
		),
		btime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "boot_time_seconds"),
			"Node boot time, in unixtime.",
			nil, nil,
		),
		procsRunning: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "procs_running"),
			"Number of processes in runnable state.",
			nil, nil,
		),
		procsBlocked: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "procs_blocked"),
			"Number of processes blocked waiting for I/O to complete.",
			nil, nil,
		),
		softIRQ: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "softirqs_total"),
			"Number of softirq calls.",
			[]string{"type"}, nil,
		),
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes system statistics.
func (c *statCollector) Update(ch chan<- prometheus.Metric) error {
	stat, err := c.fs.Stat()
	if err != nil {
		return fmt.Errorf("couldn't get stat: %w", err)
	}

	ch <- prometheus.MustNewConstMetric(c.intr, prometheus.CounterValue, float64(stat.IRQTotal))
	ch <- prometheus.MustNewConstMetric(c.ctxt, prometheus.CounterValue, float64(stat.ContextSwitches))
	ch <- prometheus.MustNewConstMetric(c.forks, prometheus.CounterValue, float64(stat.ProcessCreated))
	ch <- prometheus.MustNewConstMetric(c.btime, prometheus.GaugeValue, float64(stat.BootTime))
	ch <- prometheus.MustNewConstMetric(c.procsRunning, prometheus.GaugeValue, float64(stat.ProcessesRunning))
	ch <- prometheus.MustNewConstMetric(c.procsBlocked, prometheus.GaugeValue, float64(stat.ProcessesBlocked))

	// Softirq stats
	softirqNames := []string{
		"hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
		"tasklet", "sched", "hrtimer", "rcu",
	}
	for i, name := range softirqNames {
		if i < len(stat.SoftIRQ.All) {
			ch <- prometheus.MustNewConstMetric(
				c.softIRQ,
				prometheus.CounterValue,
				float64(stat.SoftIRQ.All[i]),
				name,
			)
		}
	}

	return nil
}
