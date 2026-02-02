// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const timeCollectorName = "time"

func init() {
	Register(timeCollectorName, true, NewTimeCollector)
}

// timeCollector exports system time metrics.
type timeCollector struct {
	now    *prometheus.Desc
	zone   *prometheus.Desc
	logger *slog.Logger
}

// NewTimeCollector returns a new Collector exposing system time metrics.
func NewTimeCollector(config CollectorConfig) (Collector, error) {
	return &timeCollector{
		now: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "time", "seconds"),
			"System time in seconds since epoch (1970).",
			nil, nil,
		),
		zone: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "time", "zone_offset_seconds"),
			"System timezone offset in seconds.",
			[]string{"time_zone"}, nil,
		),
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes system time metrics.
func (c *timeCollector) Update(ch chan<- prometheus.Metric) error {
	now := time.Now()

	ch <- prometheus.MustNewConstMetric(
		c.now,
		prometheus.GaugeValue,
		float64(now.Unix())+float64(now.Nanosecond())/1e9,
	)

	// Get timezone info
	zone, offset := now.Zone()
	ch <- prometheus.MustNewConstMetric(
		c.zone,
		prometheus.GaugeValue,
		float64(offset),
		zone,
	)

	// Add clocksource info via timex
	var timex unix.Timex
	status, err := unix.Adjtimex(&timex)
	if err != nil {
		c.logger.Debug("couldn't get timex info", "error", err)
	} else {
		// NTP sync status
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "timex", "sync_status"),
				"NTP synchronization status (0=unsync, 1=synced).",
				nil, nil,
			),
			prometheus.GaugeValue,
			func() float64 {
				if status == unix.TIME_OK {
					return 1
				}
				return 0
			}(),
		)

		// Frequency offset
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "timex", "frequency_adjustment_ratio"),
				"Frequency adjustment to the system clock.",
				nil, nil,
			),
			prometheus.GaugeValue,
			float64(timex.Freq)/65536.0/1e6,
		)

		// Offset from reference
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "timex", "offset_seconds"),
				"Time offset from reference source.",
				nil, nil,
			),
			prometheus.GaugeValue,
			float64(timex.Offset)/1e6,
		)

		// Maximum error
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "timex", "maxerror_seconds"),
				"Maximum error in seconds.",
				nil, nil,
			),
			prometheus.GaugeValue,
			float64(timex.Maxerror)/1e6,
		)

		// Estimated error
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "timex", "estimated_error_seconds"),
				"Estimated error in seconds.",
				nil, nil,
			),
			prometheus.GaugeValue,
			float64(timex.Esterror)/1e6,
		)
	}

	return nil
}
