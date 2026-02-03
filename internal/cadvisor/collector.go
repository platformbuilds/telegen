// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cadvisor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// Collector collects cAdvisor-equivalent metrics from cgroups
type Collector struct {
	config *Config
	reader *CgroupReader
	logger *slog.Logger

	// Container info cache
	containers   map[string]*ContainerInfo
	containersMu sync.RWMutex

	// Stats cache for rate calculation
	prevStats   map[string]*ContainerStats
	prevStatsMu sync.RWMutex

	// Running state
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ContainerInfo holds metadata about a container
type ContainerInfo struct {
	ContainerID   string
	ContainerName string
	PodUID        string
	PodName       string
	PodNamespace  string
	NodeName      string
	CgroupPath    string
	PID           int
	Labels        map[string]string
	CreatedAt     time.Time
}

// NewCollector creates a new cAdvisor metrics collector
func NewCollector(config *Config, logger *slog.Logger) (*Collector, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	reader, err := NewCgroupReader(config.CgroupRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to create cgroup reader: %w", err)
	}

	return &Collector{
		config:     config,
		reader:     reader,
		logger:     logger,
		containers: make(map[string]*ContainerInfo),
		prevStats:  make(map[string]*ContainerStats),
	}, nil
}

// Start begins the metrics collection
func (c *Collector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Initial container discovery
	if err := c.discoverContainers(); err != nil {
		c.logger.Warn("initial container discovery failed", "error", err)
	}

	// Start housekeeping goroutine
	c.wg.Add(1)
	go c.housekeepingLoop()

	c.logger.Info("cadvisor collector started",
		"cgroupRoot", c.config.CgroupRoot,
		"cgroupVersion", c.reader.Version(),
		"containers", len(c.containers))

	return nil
}

// Stop stops the metrics collection
func (c *Collector) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	c.logger.Info("cadvisor collector stopped")
}

// housekeepingLoop periodically discovers new containers and cleans up old ones
func (c *Collector) housekeepingLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.HousekeepingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.discoverContainers(); err != nil {
				c.logger.Warn("container discovery failed", "error", err)
			}
		}
	}
}

// discoverContainers finds all container cgroups
func (c *Collector) discoverContainers() error {
	cgroups, err := c.reader.ListContainerCgroups()
	if err != nil {
		return fmt.Errorf("failed to list container cgroups: %w", err)
	}

	c.containersMu.Lock()
	defer c.containersMu.Unlock()

	// Track which containers we've seen
	seen := make(map[string]bool)

	for _, cg := range cgroups {
		seen[cg.ContainerID] = true

		if _, exists := c.containers[cg.ContainerID]; !exists {
			// New container
			info := &ContainerInfo{
				ContainerID:  cg.ContainerID,
				PodUID:       cg.PodUID,
				PodName:      cg.PodName,
				PodNamespace: cg.Namespace,
				CgroupPath:   cg.Path,
				CreatedAt:    time.Now(),
			}

			// Try to get PID
			if pid, err := GetContainerPID(cg.Path); err == nil {
				info.PID = pid
			}

			c.containers[cg.ContainerID] = info
		}
	}

	// Clean up containers that no longer exist
	for containerID := range c.containers {
		if !seen[containerID] {
			delete(c.containers, containerID)
			c.prevStatsMu.Lock()
			delete(c.prevStats, containerID)
			c.prevStatsMu.Unlock()
		}
	}

	return nil
}

// CollectAll collects metrics for all containers
func (c *Collector) CollectAll() ([]*ContainerStats, error) {
	c.containersMu.RLock()
	containers := make([]*ContainerInfo, 0, len(c.containers))
	for _, info := range c.containers {
		containers = append(containers, info)
	}
	c.containersMu.RUnlock()

	stats := make([]*ContainerStats, 0, len(containers))
	for _, info := range containers {
		s, err := c.CollectContainer(info)
		if err != nil {
			c.logger.Debug("failed to collect container stats",
				"containerID", info.ContainerID,
				"error", err)
			continue
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// CollectContainer collects metrics for a single container
func (c *Collector) CollectContainer(info *ContainerInfo) (*ContainerStats, error) {
	stats := &ContainerStats{
		Container: ContainerCgroup{
			ContainerID:   info.ContainerID,
			ContainerName: info.ContainerName,
			PodUID:        info.PodUID,
			PodName:       info.PodName,
			Namespace:     info.PodNamespace,
		},
		Timestamp: time.Now(),
	}

	var err error

	// Collect CPU stats
	stats.CPU, err = c.reader.ReadCPUStats(info.CgroupPath)
	if err != nil {
		c.logger.Debug("failed to read CPU stats", "error", err)
	}

	// Collect memory stats
	stats.Memory, err = c.reader.ReadMemoryStats(info.CgroupPath)
	if err != nil {
		c.logger.Debug("failed to read memory stats", "error", err)
	}

	// Collect disk I/O stats
	if c.config.DiskIOEnabled {
		stats.DiskIO, err = c.reader.ReadDiskIOStats(info.CgroupPath)
		if err != nil {
			c.logger.Debug("failed to read disk I/O stats", "error", err)
		}
	}

	// Collect network stats (requires PID)
	if c.config.NetworkEnabled && info.PID > 0 {
		stats.Network, err = c.reader.ReadNetworkStats(info.PID)
		if err != nil {
			c.logger.Debug("failed to read network stats", "error", err)
		}
	}

	return stats, nil
}

// ServeHTTP implements http.Handler for Prometheus metrics endpoint
func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	stats, err := c.CollectAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.WriteMetrics(w, stats)
}

// WriteMetrics writes all metrics in Prometheus format
func (c *Collector) WriteMetrics(w io.Writer, stats []*ContainerStats) {
	buf := &bytes.Buffer{}

	// Write metric headers and values
	c.writeCPUMetrics(buf, stats)
	c.writeMemoryMetrics(buf, stats)
	c.writeDiskIOMetrics(buf, stats)
	c.writeNetworkMetrics(buf, stats)

	_, _ = w.Write(buf.Bytes())
}

func (c *Collector) writeCPUMetrics(buf *bytes.Buffer, stats []*ContainerStats) {
	// container_cpu_usage_seconds_total
	buf.WriteString("# HELP container_cpu_usage_seconds_total Cumulative cpu time consumed in seconds.\n")
	buf.WriteString("# TYPE container_cpu_usage_seconds_total counter\n")
	for _, s := range stats {
		if s.CPU == nil {
			continue
		}
		labels := c.formatLabels(s)
		seconds := float64(s.CPU.UsageNanoseconds) / 1e9
		fmt.Fprintf(buf, "container_cpu_usage_seconds_total{%s} %g\n", labels, seconds)
	}

	// container_cpu_user_seconds_total
	buf.WriteString("# HELP container_cpu_user_seconds_total Cumulative user cpu time consumed in seconds.\n")
	buf.WriteString("# TYPE container_cpu_user_seconds_total counter\n")
	for _, s := range stats {
		if s.CPU == nil {
			continue
		}
		labels := c.formatLabels(s)
		seconds := float64(s.CPU.UserNanoseconds) / 1e9
		fmt.Fprintf(buf, "container_cpu_user_seconds_total{%s} %g\n", labels, seconds)
	}

	// container_cpu_system_seconds_total
	buf.WriteString("# HELP container_cpu_system_seconds_total Cumulative system cpu time consumed in seconds.\n")
	buf.WriteString("# TYPE container_cpu_system_seconds_total counter\n")
	for _, s := range stats {
		if s.CPU == nil {
			continue
		}
		labels := c.formatLabels(s)
		seconds := float64(s.CPU.SystemNanoseconds) / 1e9
		fmt.Fprintf(buf, "container_cpu_system_seconds_total{%s} %g\n", labels, seconds)
	}

	// container_cpu_cfs_throttled_periods_total
	buf.WriteString("# HELP container_cpu_cfs_throttled_periods_total Number of throttled period intervals.\n")
	buf.WriteString("# TYPE container_cpu_cfs_throttled_periods_total counter\n")
	for _, s := range stats {
		if s.CPU == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_cpu_cfs_throttled_periods_total{%s} %d\n", labels, s.CPU.ThrottledPeriods)
	}

	// container_cpu_cfs_throttled_seconds_total
	buf.WriteString("# HELP container_cpu_cfs_throttled_seconds_total Total time duration the container has been throttled.\n")
	buf.WriteString("# TYPE container_cpu_cfs_throttled_seconds_total counter\n")
	for _, s := range stats {
		if s.CPU == nil {
			continue
		}
		labels := c.formatLabels(s)
		seconds := float64(s.CPU.ThrottledNanoseconds) / 1e9
		fmt.Fprintf(buf, "container_cpu_cfs_throttled_seconds_total{%s} %g\n", labels, seconds)
	}
}

func (c *Collector) writeMemoryMetrics(buf *bytes.Buffer, stats []*ContainerStats) {
	// container_memory_usage_bytes
	buf.WriteString("# HELP container_memory_usage_bytes Current memory usage in bytes, including all memory regardless of when it was accessed.\n")
	buf.WriteString("# TYPE container_memory_usage_bytes gauge\n")
	for _, s := range stats {
		if s.Memory == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_memory_usage_bytes{%s} %d\n", labels, s.Memory.UsageBytes)
	}

	// container_memory_working_set_bytes
	buf.WriteString("# HELP container_memory_working_set_bytes Current working set in bytes.\n")
	buf.WriteString("# TYPE container_memory_working_set_bytes gauge\n")
	for _, s := range stats {
		if s.Memory == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_memory_working_set_bytes{%s} %d\n", labels, s.Memory.WorkingSetBytes)
	}

	// container_memory_rss
	buf.WriteString("# HELP container_memory_rss Size of RSS in bytes.\n")
	buf.WriteString("# TYPE container_memory_rss gauge\n")
	for _, s := range stats {
		if s.Memory == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_memory_rss{%s} %d\n", labels, s.Memory.RSSBytes)
	}

	// container_memory_cache
	buf.WriteString("# HELP container_memory_cache Number of bytes of page cache memory.\n")
	buf.WriteString("# TYPE container_memory_cache gauge\n")
	for _, s := range stats {
		if s.Memory == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_memory_cache{%s} %d\n", labels, s.Memory.CacheBytes)
	}

	// container_memory_swap
	buf.WriteString("# HELP container_memory_swap Container swap usage in bytes.\n")
	buf.WriteString("# TYPE container_memory_swap gauge\n")
	for _, s := range stats {
		if s.Memory == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_memory_swap{%s} %d\n", labels, s.Memory.SwapBytes)
	}

	// container_memory_max_usage_bytes
	buf.WriteString("# HELP container_memory_max_usage_bytes Maximum memory usage recorded in bytes.\n")
	buf.WriteString("# TYPE container_memory_max_usage_bytes gauge\n")
	for _, s := range stats {
		if s.Memory == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_memory_max_usage_bytes{%s} %d\n", labels, s.Memory.MaxUsageBytes)
	}

	// container_memory_failcnt
	buf.WriteString("# HELP container_memory_failcnt Number of memory usage hits limits.\n")
	buf.WriteString("# TYPE container_memory_failcnt counter\n")
	for _, s := range stats {
		if s.Memory == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_memory_failcnt{%s} %d\n", labels, s.Memory.OOMKills)
	}

	// container_oom_events_total
	buf.WriteString("# HELP container_oom_events_total Count of out of memory events observed for the container.\n")
	buf.WriteString("# TYPE container_oom_events_total counter\n")
	for _, s := range stats {
		if s.Memory == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_oom_events_total{%s} %d\n", labels, s.Memory.OOMKills)
	}
}

func (c *Collector) writeDiskIOMetrics(buf *bytes.Buffer, stats []*ContainerStats) {
	// container_fs_reads_bytes_total
	buf.WriteString("# HELP container_fs_reads_bytes_total Cumulative count of bytes read.\n")
	buf.WriteString("# TYPE container_fs_reads_bytes_total counter\n")
	for _, s := range stats {
		if s.DiskIO == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_fs_reads_bytes_total{%s} %d\n", labels, s.DiskIO.ReadBytes)
	}

	// container_fs_writes_bytes_total
	buf.WriteString("# HELP container_fs_writes_bytes_total Cumulative count of bytes written.\n")
	buf.WriteString("# TYPE container_fs_writes_bytes_total counter\n")
	for _, s := range stats {
		if s.DiskIO == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_fs_writes_bytes_total{%s} %d\n", labels, s.DiskIO.WriteBytes)
	}

	// container_fs_reads_total
	buf.WriteString("# HELP container_fs_reads_total Cumulative count of reads completed.\n")
	buf.WriteString("# TYPE container_fs_reads_total counter\n")
	for _, s := range stats {
		if s.DiskIO == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_fs_reads_total{%s} %d\n", labels, s.DiskIO.ReadOps)
	}

	// container_fs_writes_total
	buf.WriteString("# HELP container_fs_writes_total Cumulative count of writes completed.\n")
	buf.WriteString("# TYPE container_fs_writes_total counter\n")
	for _, s := range stats {
		if s.DiskIO == nil {
			continue
		}
		labels := c.formatLabels(s)
		fmt.Fprintf(buf, "container_fs_writes_total{%s} %d\n", labels, s.DiskIO.WriteOps)
	}
}

func (c *Collector) writeNetworkMetrics(buf *bytes.Buffer, stats []*ContainerStats) {
	// container_network_receive_bytes_total
	buf.WriteString("# HELP container_network_receive_bytes_total Cumulative count of bytes received.\n")
	buf.WriteString("# TYPE container_network_receive_bytes_total counter\n")
	for _, s := range stats {
		if s.Network == nil {
			continue
		}
		for ifaceName, iface := range s.Network.Interfaces {
			labels := c.formatLabelsWithInterface(s, ifaceName)
			fmt.Fprintf(buf, "container_network_receive_bytes_total{%s} %d\n", labels, iface.RxBytes)
		}
	}

	// container_network_transmit_bytes_total
	buf.WriteString("# HELP container_network_transmit_bytes_total Cumulative count of bytes transmitted.\n")
	buf.WriteString("# TYPE container_network_transmit_bytes_total counter\n")
	for _, s := range stats {
		if s.Network == nil {
			continue
		}
		for ifaceName, iface := range s.Network.Interfaces {
			labels := c.formatLabelsWithInterface(s, ifaceName)
			fmt.Fprintf(buf, "container_network_transmit_bytes_total{%s} %d\n", labels, iface.TxBytes)
		}
	}

	// container_network_receive_packets_total
	buf.WriteString("# HELP container_network_receive_packets_total Cumulative count of packets received.\n")
	buf.WriteString("# TYPE container_network_receive_packets_total counter\n")
	for _, s := range stats {
		if s.Network == nil {
			continue
		}
		for ifaceName, iface := range s.Network.Interfaces {
			labels := c.formatLabelsWithInterface(s, ifaceName)
			fmt.Fprintf(buf, "container_network_receive_packets_total{%s} %d\n", labels, iface.RxPackets)
		}
	}

	// container_network_transmit_packets_total
	buf.WriteString("# HELP container_network_transmit_packets_total Cumulative count of packets transmitted.\n")
	buf.WriteString("# TYPE container_network_transmit_packets_total counter\n")
	for _, s := range stats {
		if s.Network == nil {
			continue
		}
		for ifaceName, iface := range s.Network.Interfaces {
			labels := c.formatLabelsWithInterface(s, ifaceName)
			fmt.Fprintf(buf, "container_network_transmit_packets_total{%s} %d\n", labels, iface.TxPackets)
		}
	}

	// container_network_receive_errors_total
	buf.WriteString("# HELP container_network_receive_errors_total Cumulative count of errors encountered while receiving.\n")
	buf.WriteString("# TYPE container_network_receive_errors_total counter\n")
	for _, s := range stats {
		if s.Network == nil {
			continue
		}
		for ifaceName, iface := range s.Network.Interfaces {
			labels := c.formatLabelsWithInterface(s, ifaceName)
			fmt.Fprintf(buf, "container_network_receive_errors_total{%s} %d\n", labels, iface.RxErrors)
		}
	}

	// container_network_transmit_errors_total
	buf.WriteString("# HELP container_network_transmit_errors_total Cumulative count of errors encountered while transmitting.\n")
	buf.WriteString("# TYPE container_network_transmit_errors_total counter\n")
	for _, s := range stats {
		if s.Network == nil {
			continue
		}
		for ifaceName, iface := range s.Network.Interfaces {
			labels := c.formatLabelsWithInterface(s, ifaceName)
			fmt.Fprintf(buf, "container_network_transmit_errors_total{%s} %d\n", labels, iface.TxErrors)
		}
	}

	// container_network_receive_packets_dropped_total
	buf.WriteString("# HELP container_network_receive_packets_dropped_total Cumulative count of packets dropped while receiving.\n")
	buf.WriteString("# TYPE container_network_receive_packets_dropped_total counter\n")
	for _, s := range stats {
		if s.Network == nil {
			continue
		}
		for ifaceName, iface := range s.Network.Interfaces {
			labels := c.formatLabelsWithInterface(s, ifaceName)
			fmt.Fprintf(buf, "container_network_receive_packets_dropped_total{%s} %d\n", labels, iface.RxDropped)
		}
	}

	// container_network_transmit_packets_dropped_total
	buf.WriteString("# HELP container_network_transmit_packets_dropped_total Cumulative count of packets dropped while transmitting.\n")
	buf.WriteString("# TYPE container_network_transmit_packets_dropped_total counter\n")
	for _, s := range stats {
		if s.Network == nil {
			continue
		}
		for ifaceName, iface := range s.Network.Interfaces {
			labels := c.formatLabelsWithInterface(s, ifaceName)
			fmt.Fprintf(buf, "container_network_transmit_packets_dropped_total{%s} %d\n", labels, iface.TxDropped)
		}
	}
}

// formatLabels formats container labels for Prometheus output
func (c *Collector) formatLabels(s *ContainerStats) string {
	return fmt.Sprintf(`container_id="%s",pod="%s",namespace="%s",container="%s"`,
		escapeLabel(s.Container.ContainerID),
		escapeLabel(s.Container.PodName),
		escapeLabel(s.Container.Namespace),
		escapeLabel(s.Container.ContainerName))
}

// formatLabelsWithInterface formats container labels with interface name
func (c *Collector) formatLabelsWithInterface(s *ContainerStats, iface string) string {
	return fmt.Sprintf(`container_id="%s",pod="%s",namespace="%s",container="%s",interface="%s"`,
		escapeLabel(s.Container.ContainerID),
		escapeLabel(s.Container.PodName),
		escapeLabel(s.Container.Namespace),
		escapeLabel(s.Container.ContainerName),
		escapeLabel(iface))
}

// escapeLabel escapes a Prometheus label value
func escapeLabel(s string) string {
	var buf bytes.Buffer
	for _, c := range s {
		switch c {
		case '\\':
			buf.WriteString("\\\\")
		case '"':
			buf.WriteString("\\\"")
		case '\n':
			buf.WriteString("\\n")
		default:
			buf.WriteRune(c)
		}
	}
	return buf.String()
}

// Stats returns current collector statistics
func (c *Collector) Stats() map[string]interface{} {
	c.containersMu.RLock()
	containerCount := len(c.containers)
	c.containersMu.RUnlock()

	return map[string]interface{}{
		"containers":    containerCount,
		"cgroupVersion": c.reader.Version(),
		"cgroupRoot":    c.config.CgroupRoot,
	}
}

// IsHealthy returns true if the collector is healthy
func (c *Collector) IsHealthy() bool {
	// Check if we can read from the cgroup root
	_, err := os.Stat(c.config.CgroupRoot)
	return err == nil
}
