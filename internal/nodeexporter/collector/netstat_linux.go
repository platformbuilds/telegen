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
	// Get netstat metrics
	netStats, err := c.fs.NetStat()
	if err != nil {
		return fmt.Errorf("couldn't get netstat: %w", err)
	}

	for protocol, stats := range netStats {
		for name, value := range stats {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, "netstat", protocol+"_"+name),
					fmt.Sprintf("Statistic %s_%s.", protocol, name),
					nil, nil,
				),
				prometheus.UntypedValue,
				value,
			)
		}
	}

	// Get SNMP metrics
	snmpStats, err := c.fs.Snmp()
	if err != nil {
		c.logger.Debug("couldn't get SNMP stats", "error", err)
	} else {
		// IP stats
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Ip_Forwarding"),
				"IP forwarding status.",
				nil, nil,
			),
			prometheus.GaugeValue,
			float64(snmpStats.Ip.Forwarding),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Ip_InReceives"),
				"IP packets received.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Ip.InReceives),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Ip_OutRequests"),
				"IP packets sent.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Ip.OutRequests),
		)

		// TCP stats
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Tcp_ActiveOpens"),
				"TCP active opens.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Tcp.ActiveOpens),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Tcp_PassiveOpens"),
				"TCP passive opens.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Tcp.PassiveOpens),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Tcp_CurrEstab"),
				"TCP current established connections.",
				nil, nil,
			),
			prometheus.GaugeValue,
			float64(snmpStats.Tcp.CurrEstab),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Tcp_InSegs"),
				"TCP segments received.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Tcp.InSegs),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Tcp_OutSegs"),
				"TCP segments sent.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Tcp.OutSegs),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Tcp_RetransSegs"),
				"TCP segments retransmitted.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Tcp.RetransSegs),
		)

		// UDP stats
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Udp_InDatagrams"),
				"UDP datagrams received.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Udp.InDatagrams),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Udp_OutDatagrams"),
				"UDP datagrams sent.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Udp.OutDatagrams),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Udp_NoPorts"),
				"UDP packets received to unknown port.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Udp.NoPorts),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "netstat", "Udp_InErrors"),
				"UDP receive errors.",
				nil, nil,
			),
			prometheus.CounterValue,
			float64(snmpStats.Udp.InErrors),
		)
	}

	return nil
}
