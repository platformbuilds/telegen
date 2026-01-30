// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-006 - GPU NVLink Metrics
package nvidia

// NVLinkMetrics holds NVLink interconnect metrics for multi-GPU systems
type NVLinkMetrics struct {
	// Number of NVLink connections
	LinkCount uint32

	// Links holds metrics for each NVLink connection
	Links []NVLinkStatus

	// Total TX throughput across all links in KB/s
	TotalTxThroughput uint64

	// Total RX throughput across all links in KB/s
	TotalRxThroughput uint64

	// NVLink version
	Version uint32
}

// NVLinkStatus holds status for a single NVLink connection
type NVLinkStatus struct {
	// Link index
	Index uint32

	// Whether the link is active
	Active bool

	// Remote GPU index (-1 if not connected to GPU)
	RemoteGPUIndex int

	// Remote device type
	RemoteDeviceType NVLinkDeviceType

	// TX throughput in KB/s
	TxThroughput uint64

	// RX throughput in KB/s
	RxThroughput uint64

	// Replay error counter
	ReplayErrors uint64

	// Recovery error counter
	RecoveryErrors uint64

	// CRC FLIT error counter
	CRCFlitErrors uint64

	// CRC data error counter
	CRCDataErrors uint64

	// Link capability (bandwidth in GB/s)
	Capability float64
}

// NVLinkDeviceType represents the type of device at the remote end
type NVLinkDeviceType int

const (
	NVLinkDeviceGPU    NVLinkDeviceType = 0
	NVLinkDeviceSwitch NVLinkDeviceType = 1
	NVLinkDeviceBridge NVLinkDeviceType = 2
)

// NVLink version bandwidth (per link in GB/s, bidirectional)
var NVLinkVersionBandwidth = map[uint32]float64{
	1: 40,  // NVLink 1.0: 40 GB/s bidirectional
	2: 50,  // NVLink 2.0: 50 GB/s bidirectional
	3: 50,  // NVLink 3.0: 50 GB/s bidirectional
	4: 100, // NVLink 4.0: 100 GB/s bidirectional (Hopper)
}

// collectNVLink collects NVLink metrics
func (c *Collector) collectNVLink(device *Device, m *GPUMetrics) error {
	// In production, these would use NVML calls:
	// nvml.DeviceGetNvLinkState(device.handle, link) -> active
	// nvml.DeviceGetNvLinkRemotePciInfo(device.handle, link) -> remotePci
	// nvml.DeviceGetNvLinkCapability(device.handle, link, cap) -> capability
	// nvml.DeviceGetNvLinkUtilizationCounter(device.handle, link, counter) -> utilization
	// nvml.DeviceGetNvLinkErrorCounter(device.handle, link, counter) -> errors
	// nvml.DeviceGetNvLinkVersion(device.handle, link) -> version

	m.NVLink = NVLinkMetrics{
		LinkCount:         0,
		Links:             nil,
		TotalTxThroughput: 0,
		TotalRxThroughput: 0,
		Version:           0,
	}

	return nil
}

// GetTotalNVLinkBandwidth returns total theoretical NVLink bandwidth in GB/s
func GetTotalNVLinkBandwidth(version, linkCount uint32) float64 {
	if bw, ok := NVLinkVersionBandwidth[version]; ok {
		return bw * float64(linkCount)
	}
	return 0
}

// GetNVLinkUtilization calculates NVLink bandwidth utilization percentage
func GetNVLinkUtilization(metrics *NVLinkMetrics) float64 {
	if metrics.LinkCount == 0 || metrics.Version == 0 {
		return 0
	}

	maxBandwidth := GetTotalNVLinkBandwidth(metrics.Version, metrics.LinkCount)
	if maxBandwidth == 0 {
		return 0
	}

	// Convert throughput from KB/s to GB/s
	totalThroughput := float64(metrics.TotalTxThroughput+metrics.TotalRxThroughput) / (1024 * 1024)
	return (totalThroughput / maxBandwidth) * 100.0
}

// HasNVLinkErrors checks if there are any NVLink errors
func HasNVLinkErrors(metrics *NVLinkMetrics) bool {
	for _, link := range metrics.Links {
		if link.ReplayErrors > 0 || link.RecoveryErrors > 0 ||
			link.CRCFlitErrors > 0 || link.CRCDataErrors > 0 {
			return true
		}
	}
	return false
}
