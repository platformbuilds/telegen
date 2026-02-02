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
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

const (
	filesystemCollectorName       = "filesystem"
	filesystemSubsystem           = "filesystem"
	defMountPointsExcluded        = "^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)"
	defFSTypesExcluded            = "^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|erofs|sysfs|tracefs)$"
	defaultFilesystemMountTimeout = 5 * time.Second
	defaultFilesystemStatWorkers  = 4
)

// FilesystemCollectorConfig holds filesystem-specific configuration.
type FilesystemCollectorConfig struct {
	MountPointsExclude string
	MountPointsInclude string
	FSTypesExclude     string
	FSTypesInclude     string
	MountTimeout       time.Duration
	StatWorkers        int
}

// DefaultFilesystemCollectorConfig returns default filesystem configuration.
func DefaultFilesystemCollectorConfig() FilesystemCollectorConfig {
	return FilesystemCollectorConfig{
		MountPointsExclude: defMountPointsExcluded,
		MountPointsInclude: "",
		FSTypesExclude:     defFSTypesExcluded,
		FSTypesInclude:     "",
		MountTimeout:       defaultFilesystemMountTimeout,
		StatWorkers:        defaultFilesystemStatWorkers,
	}
}

var filesystemLabelNames = []string{"device", "mountpoint", "fstype", "device_error"}

type filesystemCollector struct {
	mountPointFilter              DeviceFilter
	fsTypeFilter                  DeviceFilter
	sizeDesc, freeDesc, availDesc *prometheus.Desc
	filesDesc, filesFreeDesc      *prometheus.Desc
	roDesc, deviceErrorDesc       *prometheus.Desc
	mountInfoDesc                 *prometheus.Desc
	logger                        *slog.Logger
	pathConfig                    PathConfig
	fsConfig                      FilesystemCollectorConfig
	stuckMounts                   map[string]struct{}
	stuckMountsMtx                *sync.Mutex
}

type filesystemLabels struct {
	device, mountPoint, fsType, mountOptions, superOptions, deviceError, major, minor string
}

type filesystemStats struct {
	labels            filesystemLabels
	size, free, avail float64
	files, filesFree  float64
	ro, deviceError   float64
}

func init() {
	Register(filesystemCollectorName, true, NewFilesystemCollector)
}

// NewFilesystemCollector returns a new Collector exposing filesystems stats.
func NewFilesystemCollector(cfg CollectorConfig) (Collector, error) {
	sizeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, filesystemSubsystem, "size_bytes"),
		"Filesystem size in bytes.",
		filesystemLabelNames, nil,
	)

	freeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, filesystemSubsystem, "free_bytes"),
		"Filesystem free space in bytes.",
		filesystemLabelNames, nil,
	)

	availDesc := prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, filesystemSubsystem, "avail_bytes"),
		"Filesystem space available to non-root users in bytes.",
		filesystemLabelNames, nil,
	)

	filesDesc := prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, filesystemSubsystem, "files"),
		"Filesystem total file nodes.",
		filesystemLabelNames, nil,
	)

	filesFreeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, filesystemSubsystem, "files_free"),
		"Filesystem total free file nodes.",
		filesystemLabelNames, nil,
	)

	roDesc := prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, filesystemSubsystem, "readonly"),
		"Filesystem read-only status.",
		filesystemLabelNames, nil,
	)

	deviceErrorDesc := prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, filesystemSubsystem, "device_error"),
		"Whether an error occurred while getting statistics for the given device.",
		filesystemLabelNames, nil,
	)

	mountInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, filesystemSubsystem, "mount_info"),
		"Filesystem mount information.",
		[]string{"device", "major", "minor", "mountpoint"},
		nil,
	)

	// Get filesystem config from Extra or use defaults
	fsConfig := DefaultFilesystemCollectorConfig()
	if cfg.Extra != nil {
		if fc, ok := cfg.Extra["filesystem"].(FilesystemCollectorConfig); ok {
			fsConfig = fc
		}
	}

	mountPointFilter := NewDeviceFilter(fsConfig.MountPointsExclude, fsConfig.MountPointsInclude)
	fsTypeFilter := NewDeviceFilter(fsConfig.FSTypesExclude, fsConfig.FSTypesInclude)

	return &filesystemCollector{
		mountPointFilter: mountPointFilter,
		fsTypeFilter:     fsTypeFilter,
		sizeDesc:         sizeDesc,
		freeDesc:         freeDesc,
		availDesc:        availDesc,
		filesDesc:        filesDesc,
		filesFreeDesc:    filesFreeDesc,
		roDesc:           roDesc,
		deviceErrorDesc:  deviceErrorDesc,
		mountInfoDesc:    mountInfoDesc,
		logger:           cfg.Logger,
		pathConfig:       cfg.Paths,
		fsConfig:         fsConfig,
		stuckMounts:      make(map[string]struct{}),
		stuckMountsMtx:   &sync.Mutex{},
	}, nil
}

// Update implements the Collector interface.
func (c *filesystemCollector) Update(ch chan<- prometheus.Metric) error {
	stats, err := c.getStats()
	if err != nil {
		return err
	}

	// Make sure we expose a metric once, even if there are multiple mounts
	seen := map[filesystemLabels]bool{}
	for _, s := range stats {
		if seen[s.labels] {
			continue
		}
		seen[s.labels] = true

		ch <- prometheus.MustNewConstMetric(
			c.deviceErrorDesc, prometheus.GaugeValue,
			s.deviceError, s.labels.device, s.labels.mountPoint, s.labels.fsType, s.labels.deviceError,
		)
		ch <- prometheus.MustNewConstMetric(
			c.roDesc, prometheus.GaugeValue,
			s.ro, s.labels.device, s.labels.mountPoint, s.labels.fsType, s.labels.deviceError,
		)

		if s.deviceError > 0 {
			continue
		}

		ch <- prometheus.MustNewConstMetric(
			c.sizeDesc, prometheus.GaugeValue,
			s.size, s.labels.device, s.labels.mountPoint, s.labels.fsType, s.labels.deviceError,
		)
		ch <- prometheus.MustNewConstMetric(
			c.freeDesc, prometheus.GaugeValue,
			s.free, s.labels.device, s.labels.mountPoint, s.labels.fsType, s.labels.deviceError,
		)
		ch <- prometheus.MustNewConstMetric(
			c.availDesc, prometheus.GaugeValue,
			s.avail, s.labels.device, s.labels.mountPoint, s.labels.fsType, s.labels.deviceError,
		)
		ch <- prometheus.MustNewConstMetric(
			c.filesDesc, prometheus.GaugeValue,
			s.files, s.labels.device, s.labels.mountPoint, s.labels.fsType, s.labels.deviceError,
		)
		ch <- prometheus.MustNewConstMetric(
			c.filesFreeDesc, prometheus.GaugeValue,
			s.filesFree, s.labels.device, s.labels.mountPoint, s.labels.fsType, s.labels.deviceError,
		)
		ch <- prometheus.MustNewConstMetric(
			c.mountInfoDesc, prometheus.GaugeValue,
			1.0, s.labels.device, s.labels.major, s.labels.minor, s.labels.mountPoint,
		)
	}
	return nil
}

// getStats returns filesystem stats.
func (c *filesystemCollector) getStats() ([]filesystemStats, error) {
	mps, err := c.mountPointDetails()
	if err != nil {
		return nil, err
	}

	stats := []filesystemStats{}
	labelChan := make(chan filesystemLabels)
	statChan := make(chan filesystemStats)
	wg := sync.WaitGroup{}

	workerCount := max(c.fsConfig.StatWorkers, 1)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for labels := range labelChan {
				statChan <- c.processStat(labels)
			}
		}()
	}

	go func() {
		for _, labels := range mps {
			if c.mountPointFilter.Ignored(labels.mountPoint) {
				c.logger.Debug("Ignoring mount point", "mountpoint", labels.mountPoint)
				continue
			}
			if c.fsTypeFilter.Ignored(labels.fsType) {
				c.logger.Debug("Ignoring fs type", "type", labels.fsType)
				continue
			}

			c.stuckMountsMtx.Lock()
			if _, ok := c.stuckMounts[labels.mountPoint]; ok {
				labels.deviceError = "mountpoint timeout"
				stats = append(stats, filesystemStats{
					labels:      labels,
					deviceError: 1,
				})
				c.logger.Debug("Mount point is in an unresponsive state", "mountpoint", labels.mountPoint)
				c.stuckMountsMtx.Unlock()
				continue
			}

			c.stuckMountsMtx.Unlock()
			labelChan <- labels
		}
		close(labelChan)
		wg.Wait()
		close(statChan)
	}()

	for stat := range statChan {
		stats = append(stats, stat)
	}
	return stats, nil
}

func (c *filesystemCollector) processStat(labels filesystemLabels) filesystemStats {
	var ro float64
	if c.isFilesystemReadOnly(labels) {
		ro = 1
	}

	success := make(chan struct{})
	go c.stuckMountWatcher(labels.mountPoint, success)

	mountPath := filepath.Join(c.pathConfig.RootfsPath, labels.mountPoint)
	buf := new(unix.Statfs_t)
	err := unix.Statfs(mountPath, buf)

	c.stuckMountsMtx.Lock()
	close(success)

	// If the mount has been marked as stuck, unmark it and log it's recovery.
	if _, ok := c.stuckMounts[labels.mountPoint]; ok {
		c.logger.Debug("Mount point has recovered, monitoring will resume", "mountpoint", labels.mountPoint)
		delete(c.stuckMounts, labels.mountPoint)
	}
	c.stuckMountsMtx.Unlock()

	// Remove options from labels
	labels.mountOptions = ""
	labels.superOptions = ""

	if err != nil {
		labels.deviceError = err.Error()
		c.logger.Debug("Error on statfs() system call", "path", mountPath, "err", err)
		return filesystemStats{
			labels:      labels,
			deviceError: 1,
			ro:          ro,
		}
	}

	return filesystemStats{
		labels:    labels,
		size:      float64(buf.Blocks) * float64(buf.Bsize),
		free:      float64(buf.Bfree) * float64(buf.Bsize),
		avail:     float64(buf.Bavail) * float64(buf.Bsize),
		files:     float64(buf.Files),
		filesFree: float64(buf.Ffree),
		ro:        ro,
	}
}

func (c *filesystemCollector) stuckMountWatcher(mountPoint string, success chan struct{}) {
	mountCheckTimer := time.NewTimer(c.fsConfig.MountTimeout)
	defer mountCheckTimer.Stop()
	select {
	case <-success:
		// Success
	case <-mountCheckTimer.C:
		// Timed out, mark mount as stuck
		c.stuckMountsMtx.Lock()
		select {
		case <-success:
			// Success came in just after the timeout was reached
		default:
			c.logger.Debug("Mount point timed out, it is being labeled as stuck", "mountpoint", mountPoint)
			c.stuckMounts[mountPoint] = struct{}{}
		}
		c.stuckMountsMtx.Unlock()
	}
}

func (c *filesystemCollector) mountPointDetails() ([]filesystemLabels, error) {
	fs, err := procfs.NewFS(c.pathConfig.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	mountInfo, err := fs.GetProcMounts(1)
	if errors.Is(err, os.ErrNotExist) {
		c.logger.Debug("Reading root mounts failed, falling back to self mounts", "err", err)
		mountInfo, err = fs.GetMounts()
	}
	if err != nil {
		return nil, err
	}

	return c.parseFilesystemLabels(mountInfo)
}

func (c *filesystemCollector) parseFilesystemLabels(mountInfo []*procfs.MountInfo) ([]filesystemLabels, error) {
	var filesystems []filesystemLabels

	for _, mount := range mountInfo {
		major, minor := 0, 0
		_, err := fmt.Sscanf(mount.MajorMinorVer, "%d:%d", &major, &minor)
		if err != nil {
			return nil, fmt.Errorf("malformed mount point MajorMinorVer: %q", mount.MajorMinorVer)
		}

		// Handle translation of \040 and \011 as per fstab(5)
		mountPoint := strings.ReplaceAll(mount.MountPoint, "\\040", " ")
		mountPoint = strings.ReplaceAll(mountPoint, "\\011", "\t")

		// Strip rootfs prefix
		if c.pathConfig.RootfsPath != "/" && c.pathConfig.RootfsPath != "" {
			mountPoint = strings.TrimPrefix(mountPoint, c.pathConfig.RootfsPath)
			if mountPoint == "" {
				mountPoint = "/"
			}
		}

		filesystems = append(filesystems, filesystemLabels{
			device:       mount.Source,
			mountPoint:   mountPoint,
			fsType:       mount.FSType,
			mountOptions: mountOptionsString(mount.Options),
			superOptions: mountOptionsString(mount.SuperOptions),
			major:        strconv.Itoa(major),
			minor:        strconv.Itoa(minor),
			deviceError:  "",
		})
	}

	return filesystems, nil
}

func (c *filesystemCollector) isFilesystemReadOnly(labels filesystemLabels) bool {
	if slices.Contains(strings.Split(labels.mountOptions, ","), "ro") ||
		slices.Contains(strings.Split(labels.superOptions, ","), "ro") {
		return true
	}
	return false
}

func mountOptionsString(m map[string]string) string {
	b := new(bytes.Buffer)
	for key, value := range m {
		if value == "" {
			fmt.Fprintf(b, "%s", key)
		} else {
			fmt.Fprintf(b, "%s=%s", key, value)
		}
	}
	return b.String()
}
