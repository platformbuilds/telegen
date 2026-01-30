// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-005 - GPU PCIe Metrics
package nvidia

// PCIeMetrics holds GPU PCIe bus metrics
type PCIeMetrics struct {
	// PCIe link generation (1, 2, 3, 4, 5)
	LinkGeneration uint32

	// Maximum PCIe link generation
	MaxLinkGeneration uint32

	// PCIe link width (x1, x4, x8, x16)
	LinkWidth uint32

	// Maximum PCIe link width
	MaxLinkWidth uint32

	// PCIe TX throughput in KB/s
	TxThroughput uint32

	// PCIe RX throughput in KB/s
	RxThroughput uint32

	// PCIe replay counter (errors that required retransmission)
	ReplayCounter uint32

	// PCIe replay rollover counter
	ReplayRolloverCounter uint32

	// PCI bus ID
	BusID string

	// PCI device ID
	DeviceID uint32

	// PCI subsystem ID
	SubsystemID uint32
}

// PCIe generation bandwidth (theoretical max in GB/s per lane)
var PCIeGenBandwidth = map[uint32]float64{
	1: 0.25,  // PCIe 1.0: 250 MB/s per lane
	2: 0.5,   // PCIe 2.0: 500 MB/s per lane
	3: 0.985, // PCIe 3.0: 985 MB/s per lane
	4: 1.969, // PCIe 4.0: 1969 MB/s per lane
	5: 3.938, // PCIe 5.0: 3938 MB/s per lane
}

// collectPCIe collects GPU PCIe metrics
func (c *Collector) collectPCIe(device *Device, m *GPUMetrics) error {
	// In production, these would use NVML calls:
	// nvml.DeviceGetCurrPcieLinkGeneration(device.handle) -> linkGen
	// nvml.DeviceGetMaxPcieLinkGeneration(device.handle) -> maxLinkGen
	// nvml.DeviceGetCurrPcieLinkWidth(device.handle) -> linkWidth
	// nvml.DeviceGetMaxPcieLinkWidth(device.handle) -> maxLinkWidth
	// nvml.DeviceGetPcieThroughput(device.handle, PCIE_UTIL_TX_BYTES) -> txBytes
	// nvml.DeviceGetPcieThroughput(device.handle, PCIE_UTIL_RX_BYTES) -> rxBytes
	// nvml.DeviceGetPcieReplayCounter(device.handle) -> replayCounter
	// nvml.DeviceGetPciInfo(device.handle) -> busId, deviceId, etc.

	m.PCIe = PCIeMetrics{
		LinkGeneration:        4,
		MaxLinkGeneration:     4,
		LinkWidth:             16,
		MaxLinkWidth:          16,
		TxThroughput:          0,
		RxThroughput:          0,
		ReplayCounter:         0,
		ReplayRolloverCounter: 0,
		BusID:                 device.Info.PCIBusID,
		DeviceID:              0,
		SubsystemID:           0,
	}

	return nil
}

// GetMaxBandwidthGB returns the theoretical max PCIe bandwidth in GB/s
func GetMaxBandwidthGB(gen, width uint32) float64 {
	if bw, ok := PCIeGenBandwidth[gen]; ok {
		return bw * float64(width)
	}
	return 0
}

// GetBandwidthUtilization calculates PCIe bandwidth utilization percentage
func GetBandwidthUtilization(txKBps, rxKBps uint32, gen, width uint32) float64 {
	maxBandwidth := GetMaxBandwidthGB(gen, width) * 1024 * 1024 // Convert to KB/s
	if maxBandwidth == 0 {
		return 0
	}
	totalThroughput := float64(txKBps + rxKBps)
	return (totalThroughput / maxBandwidth) * 100.0
}
