// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-003 - GPU Memory Metrics
package nvidia

// MemoryMetrics holds GPU memory metrics
type MemoryMetrics struct {
	// Total memory in bytes
	Total uint64

	// Used memory in bytes
	Used uint64

	// Free memory in bytes
	Free uint64

	// Reserved memory in bytes (for system use)
	Reserved uint64

	// BAR1 memory total in bytes
	BAR1Total uint64

	// BAR1 memory used in bytes
	BAR1Used uint64

	// BAR1 memory free in bytes
	BAR1Free uint64

	// Memory utilization percentage (0-100)
	Utilization float64
}

// collectMemory collects GPU memory metrics
func (c *Collector) collectMemory(device *Device, m *GPUMetrics) error {
	// In production, these would use NVML calls:
	// nvml.DeviceGetMemoryInfo(device.handle) -> total, used, free
	// nvml.DeviceGetBAR1MemoryInfo(device.handle) -> bar1 info

	total := device.Info.MemoryTotal
	used := uint64(0) // Would come from NVML
	free := total - used

	m.Memory = MemoryMetrics{
		Total:       total,
		Used:        used,
		Free:        free,
		Reserved:    0,
		BAR1Total:   256 * 1024 * 1024 * 1024, // 256GB typical for A100
		BAR1Used:    0,
		BAR1Free:    256 * 1024 * 1024 * 1024,
		Utilization: 0,
	}

	if total > 0 {
		m.Memory.Utilization = float64(used) / float64(total) * 100.0
	}

	return nil
}

// BytesToGB converts bytes to gigabytes
func BytesToGB(bytes uint64) float64 {
	return float64(bytes) / (1024 * 1024 * 1024)
}

// BytesToMB converts bytes to megabytes
func BytesToMB(bytes uint64) float64 {
	return float64(bytes) / (1024 * 1024)
}

// MemoryPressureLevel returns the memory pressure level
type MemoryPressureLevel int

const (
	MemoryPressureLow      MemoryPressureLevel = 0 // < 50%
	MemoryPressureMedium   MemoryPressureLevel = 1 // 50-75%
	MemoryPressureHigh     MemoryPressureLevel = 2 // 75-90%
	MemoryPressureCritical MemoryPressureLevel = 3 // > 90%
)

// GetMemoryPressure returns the memory pressure level
func GetMemoryPressure(mem *MemoryMetrics) MemoryPressureLevel {
	if mem.Utilization >= 90 {
		return MemoryPressureCritical
	}
	if mem.Utilization >= 75 {
		return MemoryPressureHigh
	}
	if mem.Utilization >= 50 {
		return MemoryPressureMedium
	}
	return MemoryPressureLow
}
