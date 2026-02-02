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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

const mdadmCollectorName = "mdadm"

func init() {
	Register(mdadmCollectorName, true, NewMdadmCollector)
}

// mdadmCollector exports mdadm (software RAID) metrics.
type mdadmCollector struct {
	isActive     *prometheus.Desc
	disksActive  *prometheus.Desc
	disksTotal   *prometheus.Desc
	disksFailed  *prometheus.Desc
	disksSpare   *prometheus.Desc
	blocksTotal  *prometheus.Desc
	blocksSynced *prometheus.Desc
	logger       *slog.Logger
	procPath     string
}

// NewMdadmCollector returns a new mdadm collector.
func NewMdadmCollector(config CollectorConfig) (Collector, error) {
	return &mdadmCollector{
		isActive: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "md", "is_active"),
			"Indicates if the md device is active. 1 if active, 0 if inactive.",
			[]string{"device"}, nil,
		),
		disksActive: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "md", "disks_active"),
			"Number of active disks in the array.",
			[]string{"device"}, nil,
		),
		disksTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "md", "disks"),
			"Total number of disks in the array.",
			[]string{"device"}, nil,
		),
		disksFailed: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "md", "disks_failed"),
			"Number of failed disks in the array.",
			[]string{"device"}, nil,
		),
		disksSpare: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "md", "disks_spare"),
			"Number of spare disks in the array.",
			[]string{"device"}, nil,
		),
		blocksTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "md", "blocks"),
			"Total number of blocks in the array.",
			[]string{"device"}, nil,
		),
		blocksSynced: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "md", "blocks_synced"),
			"Number of blocks synced in the array.",
			[]string{"device"}, nil,
		),
		logger:   config.Logger,
		procPath: config.Paths.ProcPath,
	}, nil
}

// Update implements Collector and exposes mdadm metrics.
func (c *mdadmCollector) Update(ch chan<- prometheus.Metric) error {
	fs, err := procfs.NewFS(c.procPath)
	if err != nil {
		return fmt.Errorf("failed to open procfs: %w", err)
	}

	mdstat, err := fs.MDStat()
	if err != nil {
		c.logger.Debug("failed to get mdstat", "err", err)
		return ErrNoData
	}

	if len(mdstat) == 0 {
		return ErrNoData
	}

	for _, md := range mdstat {
		device := md.Name

		// Is active
		isActive := 0.0
		if md.ActivityState == "active" || md.ActivityState == "started" {
			isActive = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.isActive,
			prometheus.GaugeValue,
			isActive,
			device,
		)

		// Disks active
		ch <- prometheus.MustNewConstMetric(
			c.disksActive,
			prometheus.GaugeValue,
			float64(md.DisksActive),
			device,
		)

		// Disks total
		ch <- prometheus.MustNewConstMetric(
			c.disksTotal,
			prometheus.GaugeValue,
			float64(md.DisksTotal),
			device,
		)

		// Disks failed
		ch <- prometheus.MustNewConstMetric(
			c.disksFailed,
			prometheus.GaugeValue,
			float64(md.DisksFailed),
			device,
		)

		// Disks spare
		ch <- prometheus.MustNewConstMetric(
			c.disksSpare,
			prometheus.GaugeValue,
			float64(md.DisksSpare),
			device,
		)

		// Blocks total
		ch <- prometheus.MustNewConstMetric(
			c.blocksTotal,
			prometheus.GaugeValue,
			float64(md.BlocksTotal),
			device,
		)

		// Blocks synced
		ch <- prometheus.MustNewConstMetric(
			c.blocksSynced,
			prometheus.GaugeValue,
			float64(md.BlocksSynced),
			device,
		)
	}

	return nil
}
