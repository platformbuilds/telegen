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
	"github.com/prometheus/procfs/blockdevice"
)

const (
	diskstatsCollectorName = "diskstats"
	diskSubsystem          = "disk"

	secondsPerTick = 1.0 / 1000.0

	// Read sectors and write sectors are the "standard UNIX 512-byte sectors"
	unixSectorSize = 512.0

	diskstatsDefaultIgnoredDevices = "^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$"

	// Udev device property prefix
	udevDevicePropertyPrefix = "E:"

	// Udev device properties
	udevDMLVLayer               = "DM_LV_LAYER"
	udevDMLVName                = "DM_LV_NAME"
	udevDMName                  = "DM_NAME"
	udevDMUUID                  = "DM_UUID"
	udevDMVGName                = "DM_VG_NAME"
	udevIDATA                   = "ID_ATA"
	udevIDATARotationRateRPM    = "ID_ATA_ROTATION_RATE_RPM"
	udevIDATASATA               = "ID_ATA_SATA"
	udevIDATASATASignalRateGen1 = "ID_ATA_SATA_SIGNAL_RATE_GEN1"
	udevIDATASATASignalRateGen2 = "ID_ATA_SATA_SIGNAL_RATE_GEN2"
	udevIDATAWriteCache         = "ID_ATA_WRITE_CACHE"
	udevIDATAWriteCacheEnabled  = "ID_ATA_WRITE_CACHE_ENABLED"
	udevIDFSType                = "ID_FS_TYPE"
	udevIDFSUsage               = "ID_FS_USAGE"
	udevIDFSUUID                = "ID_FS_UUID"
	udevIDFSVersion             = "ID_FS_VERSION"
	udevIDModel                 = "ID_MODEL"
	udevIDPath                  = "ID_PATH"
	udevIDRevision              = "ID_REVISION"
	udevIDSerial                = "ID_SERIAL"
	udevIDSerialShort           = "ID_SERIAL_SHORT"
	udevIDWWN                   = "ID_WWN"
	udevSCSIIdentSerial         = "SCSI_IDENT_SERIAL"
)

// DiskstatsCollectorConfig holds diskstats-specific configuration.
type DiskstatsCollectorConfig struct {
	IgnoredDevices string
	AcceptDevices  string
}

// DefaultDiskstatsCollectorConfig returns default diskstats configuration.
func DefaultDiskstatsCollectorConfig() DiskstatsCollectorConfig {
	return DiskstatsCollectorConfig{
		IgnoredDevices: diskstatsDefaultIgnoredDevices,
		AcceptDevices:  "",
	}
}

type udevInfo map[string]string

func init() {
	Register(diskstatsCollectorName, true, NewDiskstatsCollector)
}

// diskstatsCollector exports disk device statistics.
type diskstatsCollector struct {
	deviceFilter            DeviceFilter
	fs                      blockdevice.FS
	pathConfig              PathConfig
	infoDesc                typedDesc
	descs                   []typedDesc
	filesystemInfoDesc      typedDesc
	deviceMapperInfoDesc    typedDesc
	ataDescs                map[string]typedDesc
	logger                  *slog.Logger
	getUdevDeviceProperties func(pathConfig PathConfig, major, minor uint32) (udevInfo, error)
}

// NewDiskstatsCollector returns a new Collector exposing disk device stats.
func NewDiskstatsCollector(cfg CollectorConfig) (Collector, error) {
	var diskLabelNames = []string{"device"}
	fs, err := blockdevice.NewFS(cfg.Paths.ProcPath, cfg.Paths.SysPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sysfs: %w", err)
	}

	// Get diskstats config from Extra or use defaults
	diskConfig := DefaultDiskstatsCollectorConfig()
	if cfg.Extra != nil {
		if dc, ok := cfg.Extra["diskstats"].(DiskstatsCollectorConfig); ok {
			diskConfig = dc
		}
	}

	deviceFilter := NewDeviceFilter(diskConfig.IgnoredDevices, diskConfig.AcceptDevices)

	collector := &diskstatsCollector{
		deviceFilter: deviceFilter,
		fs:           fs,
		pathConfig:   cfg.Paths,
		infoDesc: typedDesc{
			desc: prometheus.NewDesc(prometheus.BuildFQName(Namespace, diskSubsystem, "info"),
				"Info of /sys/block/<block_device>.",
				[]string{"device", "major", "minor", "path", "wwn", "model", "serial", "revision", "rotational"},
				nil,
			), valueType: prometheus.GaugeValue,
		},
		descs: []typedDesc{
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "reads_completed_total"),
					"The total number of reads completed successfully.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "reads_merged_total"),
					"The total number of reads merged.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "read_bytes_total"),
					"The total number of bytes read successfully.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "read_time_seconds_total"),
					"The total number of seconds spent reading.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "writes_completed_total"),
					"The total number of writes completed successfully.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "writes_merged_total"),
					"The number of writes merged.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "written_bytes_total"),
					"The total number of bytes written successfully.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "write_time_seconds_total"),
					"The total number of seconds spent writing.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "io_now"),
					"The number of I/Os currently in progress.",
					diskLabelNames,
					nil,
				), valueType: prometheus.GaugeValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "io_time_seconds_total"),
					"Total seconds spent doing I/Os.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "io_time_weighted_seconds_total"),
					"The weighted # of seconds spent doing I/Os.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "discards_completed_total"),
					"The total number of discards completed successfully.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "discards_merged_total"),
					"The total number of discards merged.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "discarded_sectors_total"),
					"The total number of sectors discarded successfully.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "discard_time_seconds_total"),
					"This is the total number of seconds spent by all discards.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "flush_requests_total"),
					"The total number of flush requests completed successfully",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
			{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(Namespace, diskSubsystem, "flush_requests_time_seconds_total"),
					"This is the total number of seconds spent by all flush requests.",
					diskLabelNames,
					nil,
				), valueType: prometheus.CounterValue,
			},
		},
		filesystemInfoDesc: typedDesc{
			desc: prometheus.NewDesc(prometheus.BuildFQName(Namespace, diskSubsystem, "filesystem_info"),
				"Info about disk filesystem.",
				[]string{"device", "type", "usage", "uuid", "version"},
				nil,
			), valueType: prometheus.GaugeValue,
		},
		deviceMapperInfoDesc: typedDesc{
			desc: prometheus.NewDesc(prometheus.BuildFQName(Namespace, diskSubsystem, "device_mapper_info"),
				"Info about disk device mapper.",
				[]string{"device", "name", "uuid", "vg_name", "lv_name", "lv_layer"},
				nil,
			), valueType: prometheus.GaugeValue,
		},
		ataDescs: map[string]typedDesc{
			udevIDATAWriteCache: {
				desc: prometheus.NewDesc(prometheus.BuildFQName(Namespace, diskSubsystem, "ata_write_cache"),
					"ATA disk has a write cache.",
					[]string{"device"},
					nil,
				), valueType: prometheus.GaugeValue,
			},
			udevIDATAWriteCacheEnabled: {
				desc: prometheus.NewDesc(prometheus.BuildFQName(Namespace, diskSubsystem, "ata_write_cache_enabled"),
					"ATA disk has its write cache enabled.",
					[]string{"device"},
					nil,
				), valueType: prometheus.GaugeValue,
			},
			udevIDATARotationRateRPM: {
				desc: prometheus.NewDesc(prometheus.BuildFQName(Namespace, diskSubsystem, "ata_rotation_rate_rpm"),
					"ATA disk rotation rate in RPMs (0 for SSDs).",
					[]string{"device"},
					nil,
				), valueType: prometheus.GaugeValue,
			},
		},
		logger: cfg.Logger,
	}

	// Only enable getting device properties from udev if the directory is readable.
	if stat, err := os.Stat(cfg.Paths.UdevPath); err != nil || !stat.IsDir() {
		cfg.Logger.Debug("Failed to open udev directory, disabling udev device properties", "path", cfg.Paths.UdevPath)
	} else {
		collector.getUdevDeviceProperties = getUdevDeviceProperties
	}

	return collector, nil
}

// Update implements the Collector interface.
func (c *diskstatsCollector) Update(ch chan<- prometheus.Metric) error {
	diskStats, err := c.fs.ProcDiskstats()
	if err != nil {
		return fmt.Errorf("couldn't get diskstats: %w", err)
	}

	for _, stats := range diskStats {
		dev := stats.DeviceName
		if c.deviceFilter.Ignored(dev) {
			continue
		}

		var info udevInfo
		if c.getUdevDeviceProperties != nil {
			info, err = c.getUdevDeviceProperties(c.pathConfig, stats.MajorNumber, stats.MinorNumber)
			if err != nil {
				c.logger.Debug("Failed to parse udev info", "err", err)
				info = make(udevInfo)
			}
		} else {
			info = make(udevInfo)
		}

		// This is usually the serial printed on the disk label.
		serial := info[udevSCSIIdentSerial]
		if serial == "" {
			serial = info[udevIDSerialShort]
		}
		if serial == "" {
			serial = info[udevIDSerial]
		}

		queueStats, err := c.fs.SysBlockDeviceQueueStats(dev)
		if err != nil && !os.IsNotExist(err) {
			c.logger.Debug("Failed to get block device queue stats", "device", dev, "err", err)
		}

		ch <- c.infoDesc.mustNewConstMetric(1.0, dev,
			fmt.Sprint(stats.MajorNumber),
			fmt.Sprint(stats.MinorNumber),
			info[udevIDPath],
			info[udevIDWWN],
			info[udevIDModel],
			serial,
			info[udevIDRevision],
			strconv.FormatUint(queueStats.Rotational, 2),
		)

		statCount := stats.IoStatsCount - 3

		for i, val := range []float64{
			float64(stats.ReadIOs),
			float64(stats.ReadMerges),
			float64(stats.ReadSectors) * unixSectorSize,
			float64(stats.ReadTicks) * secondsPerTick,
			float64(stats.WriteIOs),
			float64(stats.WriteMerges),
			float64(stats.WriteSectors) * unixSectorSize,
			float64(stats.WriteTicks) * secondsPerTick,
			float64(stats.IOsInProgress),
			float64(stats.IOsTotalTicks) * secondsPerTick,
			float64(stats.WeightedIOTicks) * secondsPerTick,
			float64(stats.DiscardIOs),
			float64(stats.DiscardMerges),
			float64(stats.DiscardSectors),
			float64(stats.DiscardTicks) * secondsPerTick,
			float64(stats.FlushRequestsCompleted),
			float64(stats.TimeSpentFlushing) * secondsPerTick,
		} {
			if i >= statCount {
				break
			}
			ch <- c.descs[i].mustNewConstMetric(val, dev)
		}

		if fsType := info[udevIDFSType]; fsType != "" {
			ch <- c.filesystemInfoDesc.mustNewConstMetric(1.0, dev,
				fsType,
				info[udevIDFSUsage],
				info[udevIDFSUUID],
				info[udevIDFSVersion],
			)
		}

		if name := info[udevDMName]; name != "" {
			ch <- c.deviceMapperInfoDesc.mustNewConstMetric(1.0, dev,
				name,
				info[udevDMUUID],
				info[udevDMVGName],
				info[udevDMLVName],
				info[udevDMLVLayer],
			)
		}

		if ata := info[udevIDATA]; ata != "" {
			for attr, desc := range c.ataDescs {
				str, ok := info[attr]
				if !ok {
					c.logger.Debug("Udev attribute does not exist", "attribute", attr)
					continue
				}
				if value, err := strconv.ParseFloat(str, 64); err == nil {
					ch <- desc.mustNewConstMetric(value, dev)
				} else {
					c.logger.Debug("Failed to parse ATA value", "attribute", attr, "err", err)
				}
			}
		}
	}
	return nil
}

func getUdevDeviceProperties(pathConfig PathConfig, major, minor uint32) (udevInfo, error) {
	filename := filepath.Join(pathConfig.UdevPath, fmt.Sprintf("b%d:%d", major, minor))

	data, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = data.Close() }()

	info := make(udevInfo)

	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, udevDevicePropertyPrefix) {
			continue
		}

		line = strings.TrimPrefix(line, udevDevicePropertyPrefix)

		if name, value, found := strings.Cut(line, "="); found {
			info[name] = value
		}
	}

	return info, nil
}
