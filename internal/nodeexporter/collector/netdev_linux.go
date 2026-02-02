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
	"net"
	"strconv"
	"sync"

	"github.com/jsimonetti/rtnetlink/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/sysfs"
)

const (
	netdevCollectorName = "netdev"
	netdevSubsystem     = "network"
)

// NetdevCollectorConfig holds netdev-specific configuration.
type NetdevCollectorConfig struct {
	DeviceInclude   string
	DeviceExclude   string
	AddressInfo     bool
	DetailedMetrics bool
	UseNetlink      bool
	LabelIfAlias    bool
}

// DefaultNetdevCollectorConfig returns default netdev configuration.
func DefaultNetdevCollectorConfig() NetdevCollectorConfig {
	return NetdevCollectorConfig{
		DeviceInclude:   "",
		DeviceExclude:   "",
		AddressInfo:     false,
		DetailedMetrics: false,
		UseNetlink:      true,
		LabelIfAlias:    false,
	}
}

type netDevStats map[string]map[string]uint64

func init() {
	Register(netdevCollectorName, true, NewNetDevCollector)
}

// netDevCollector exports network device statistics.
type netDevCollector struct {
	subsystem        string
	deviceFilter     DeviceFilter
	metricDescsMutex sync.Mutex
	metricDescs      map[string]*prometheus.Desc
	logger           *slog.Logger
	pathConfig       PathConfig
	netdevConfig     NetdevCollectorConfig
}

// NewNetDevCollector returns a new Collector exposing network device stats.
func NewNetDevCollector(cfg CollectorConfig) (Collector, error) {
	// Get netdev config from Extra or use defaults
	netdevConfig := DefaultNetdevCollectorConfig()
	if cfg.Extra != nil {
		if nc, ok := cfg.Extra["netdev"].(NetdevCollectorConfig); ok {
			netdevConfig = nc
		}
	}

	deviceFilter := NewDeviceFilter(netdevConfig.DeviceExclude, netdevConfig.DeviceInclude)

	return &netDevCollector{
		subsystem:    netdevSubsystem,
		deviceFilter: deviceFilter,
		metricDescs:  map[string]*prometheus.Desc{},
		logger:       cfg.Logger,
		pathConfig:   cfg.Paths,
		netdevConfig: netdevConfig,
	}, nil
}

func (c *netDevCollector) metricDesc(key string, labels []string) *prometheus.Desc {
	c.metricDescsMutex.Lock()
	defer c.metricDescsMutex.Unlock()

	if _, ok := c.metricDescs[key]; !ok {
		c.metricDescs[key] = prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, c.subsystem, key+"_total"),
			fmt.Sprintf("Network device statistic %s.", key),
			labels,
			nil,
		)
	}

	return c.metricDescs[key]
}

// Update implements the Collector interface.
func (c *netDevCollector) Update(ch chan<- prometheus.Metric) error {
	netDev, err := c.getNetDevStats()
	if err != nil {
		return fmt.Errorf("couldn't get netstats: %w", err)
	}

	netDevLabels, err := c.getNetDevLabels()
	if err != nil {
		return fmt.Errorf("couldn't get netdev labels: %w", err)
	}

	for dev, devStats := range netDev {
		if !c.netdevConfig.DetailedMetrics {
			c.legacy(devStats)
		}

		labels := []string{"device"}
		labelValues := []string{dev}
		if devLabels, exists := netDevLabels[dev]; exists {
			for labelName, labelValue := range devLabels {
				labels = append(labels, labelName)
				labelValues = append(labelValues, labelValue)
			}
		}

		for key, value := range devStats {
			desc := c.metricDesc(key, labels)
			ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(value), labelValues...)
		}
	}

	if c.netdevConfig.AddressInfo {
		interfaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("could not get network interfaces: %w", err)
		}

		desc := prometheus.NewDesc(prometheus.BuildFQName(Namespace, "network_address",
			"info"), "node network address by device",
			[]string{"device", "address", "netmask", "scope"}, nil)

		for _, addr := range c.getAddrsInfo(interfaces) {
			ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1,
				addr.device, addr.addr, addr.netmask, addr.scope)
		}
	}
	return nil
}

func (c *netDevCollector) getNetDevStats() (netDevStats, error) {
	if c.netdevConfig.UseNetlink {
		return c.netlinkStats()
	}
	return c.procNetDevStats()
}

func (c *netDevCollector) netlinkStats() (netDevStats, error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	links, err := conn.Link.List()
	if err != nil {
		return nil, err
	}

	return c.parseNetlinkStats(links), nil
}

func (c *netDevCollector) parseNetlinkStats(links []rtnetlink.LinkMessage) netDevStats {
	metrics := netDevStats{}

	for _, msg := range links {
		if msg.Attributes == nil {
			c.logger.Debug("No netlink attributes, skipping")
			continue
		}
		name := msg.Attributes.Name
		stats := msg.Attributes.Stats64

		if stats32 := msg.Attributes.Stats; stats == nil && stats32 != nil {
			stats = &rtnetlink.LinkStats64{
				RXPackets:          uint64(stats32.RXPackets),
				TXPackets:          uint64(stats32.TXPackets),
				RXBytes:            uint64(stats32.RXBytes),
				TXBytes:            uint64(stats32.TXBytes),
				RXErrors:           uint64(stats32.RXErrors),
				TXErrors:           uint64(stats32.TXErrors),
				RXDropped:          uint64(stats32.RXDropped),
				TXDropped:          uint64(stats32.TXDropped),
				Multicast:          uint64(stats32.Multicast),
				Collisions:         uint64(stats32.Collisions),
				RXLengthErrors:     uint64(stats32.RXLengthErrors),
				RXOverErrors:       uint64(stats32.RXOverErrors),
				RXCRCErrors:        uint64(stats32.RXCRCErrors),
				RXFrameErrors:      uint64(stats32.RXFrameErrors),
				RXFIFOErrors:       uint64(stats32.RXFIFOErrors),
				RXMissedErrors:     uint64(stats32.RXMissedErrors),
				TXAbortedErrors:    uint64(stats32.TXAbortedErrors),
				TXCarrierErrors:    uint64(stats32.TXCarrierErrors),
				TXFIFOErrors:       uint64(stats32.TXFIFOErrors),
				TXHeartbeatErrors:  uint64(stats32.TXHeartbeatErrors),
				TXWindowErrors:     uint64(stats32.TXWindowErrors),
				RXCompressed:       uint64(stats32.RXCompressed),
				TXCompressed:       uint64(stats32.TXCompressed),
				RXNoHandler:        uint64(stats32.RXNoHandler),
				RXOtherhostDropped: 0,
			}
		}

		if c.deviceFilter.Ignored(name) {
			c.logger.Debug("Ignoring device", "device", name)
			continue
		}

		if stats == nil {
			c.logger.Debug("No netlink stats, skipping")
			continue
		}

		metrics[name] = map[string]uint64{
			"receive_packets":  stats.RXPackets,
			"transmit_packets": stats.TXPackets,
			"receive_bytes":    stats.RXBytes,
			"transmit_bytes":   stats.TXBytes,
			"receive_errors":   stats.RXErrors,
			"transmit_errors":  stats.TXErrors,
			"receive_dropped":  stats.RXDropped,
			"transmit_dropped": stats.TXDropped,
			"multicast":        stats.Multicast,
			"collisions":       stats.Collisions,

			// detailed rx_errors
			"receive_length_errors": stats.RXLengthErrors,
			"receive_over_errors":   stats.RXOverErrors,
			"receive_crc_errors":    stats.RXCRCErrors,
			"receive_frame_errors":  stats.RXFrameErrors,
			"receive_fifo_errors":   stats.RXFIFOErrors,
			"receive_missed_errors": stats.RXMissedErrors,

			// detailed tx_errors
			"transmit_aborted_errors":   stats.TXAbortedErrors,
			"transmit_carrier_errors":   stats.TXCarrierErrors,
			"transmit_fifo_errors":      stats.TXFIFOErrors,
			"transmit_heartbeat_errors": stats.TXHeartbeatErrors,
			"transmit_window_errors":    stats.TXWindowErrors,

			// for cslip etc
			"receive_compressed":  stats.RXCompressed,
			"transmit_compressed": stats.TXCompressed,
			"receive_nohandler":   stats.RXNoHandler,
		}
	}

	return metrics
}

func (c *netDevCollector) procNetDevStats() (netDevStats, error) {
	metrics := netDevStats{}

	fs, err := procfs.NewFS(c.pathConfig.ProcPath)
	if err != nil {
		return metrics, fmt.Errorf("failed to open procfs: %w", err)
	}

	netDev, err := fs.NetDev()
	if err != nil {
		return metrics, fmt.Errorf("failed to parse /proc/net/dev: %w", err)
	}

	for _, stats := range netDev {
		name := stats.Name

		if c.deviceFilter.Ignored(name) {
			c.logger.Debug("Ignoring device", "device", name)
			continue
		}

		metrics[name] = map[string]uint64{
			"receive_bytes":       stats.RxBytes,
			"receive_packets":     stats.RxPackets,
			"receive_errors":      stats.RxErrors,
			"receive_dropped":     stats.RxDropped,
			"receive_fifo":        stats.RxFIFO,
			"receive_frame":       stats.RxFrame,
			"receive_compressed":  stats.RxCompressed,
			"receive_multicast":   stats.RxMulticast,
			"transmit_bytes":      stats.TxBytes,
			"transmit_packets":    stats.TxPackets,
			"transmit_errors":     stats.TxErrors,
			"transmit_dropped":    stats.TxDropped,
			"transmit_fifo":       stats.TxFIFO,
			"transmit_colls":      stats.TxCollisions,
			"transmit_carrier":    stats.TxCarrier,
			"transmit_compressed": stats.TxCompressed,
		}
	}

	return metrics, nil
}

func (c *netDevCollector) getNetDevLabels() (map[string]map[string]string, error) {
	if !c.netdevConfig.LabelIfAlias {
		return nil, nil
	}

	fs, err := sysfs.NewFS(c.pathConfig.SysPath)
	if err != nil {
		return nil, err
	}

	interfaces, err := fs.NetClass()
	if err != nil {
		return nil, err
	}

	labels := make(map[string]map[string]string)
	for iface, ifaceData := range interfaces {
		if c.deviceFilter.Ignored(iface) {
			continue
		}
		labels[iface] = map[string]string{
			"ifalias": ifaceData.IfAlias,
		}
	}

	return labels, nil
}

// legacy converts new metric names to legacy names for backwards compatibility.
func (c *netDevCollector) legacy(devStats map[string]uint64) {
	// Merge detailed stats into summary stats for legacy compatibility
	if rx, ok := devStats["receive_length_errors"]; ok {
		devStats["receive_errs"] = devStats["receive_errors"]
		delete(devStats, "receive_length_errors")
		_ = rx
	}
	delete(devStats, "receive_over_errors")
	delete(devStats, "receive_crc_errors")
	delete(devStats, "receive_frame_errors")
	delete(devStats, "receive_fifo_errors")
	delete(devStats, "receive_missed_errors")
	delete(devStats, "transmit_aborted_errors")
	delete(devStats, "transmit_carrier_errors")
	delete(devStats, "transmit_fifo_errors")
	delete(devStats, "transmit_heartbeat_errors")
	delete(devStats, "transmit_window_errors")
}

type addrInfo struct {
	device  string
	addr    string
	scope   string
	netmask string
}

func (c *netDevCollector) getAddrsInfo(interfaces []net.Interface) []addrInfo {
	var res []addrInfo

	for _, ifs := range interfaces {
		if c.deviceFilter.Ignored(ifs.Name) {
			c.logger.Debug("Ignoring device", "device", ifs.Name)
			continue
		}
		addrs, _ := ifs.Addrs()
		for _, addr := range addrs {
			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			size, _ := ipNet.Mask.Size()

			res = append(res, addrInfo{
				device:  ifs.Name,
				addr:    ip.String(),
				scope:   c.scope(ip),
				netmask: strconv.Itoa(size),
			})
		}
	}

	return res
}

func (c *netDevCollector) scope(ip net.IP) string {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link-local"
	}

	if ip.IsInterfaceLocalMulticast() {
		return "interface-local"
	}

	if ip.IsGlobalUnicast() {
		return "global"
	}

	return ""
}
