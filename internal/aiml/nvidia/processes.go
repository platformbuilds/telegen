// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-007 - GPU Process Metrics
package nvidia

// ProcessMetrics holds per-process GPU metrics
type ProcessMetrics struct {
	// Process ID
	PID uint32

	// Process name
	Name string

	// GPU memory used by process in bytes
	UsedMemory uint64

	// GPU SM utilization by process (0-100)
	SMUtilization uint32

	// GPU memory utilization by process (0-100)
	MemoryUtilization uint32

	// GPU encoder utilization by process (0-100)
	EncoderUtilization uint32

	// GPU decoder utilization by process (0-100)
	DecoderUtilization uint32

	// Process type
	Type ProcessType

	// MIG instance UUID (if applicable)
	MIGInstanceUUID string

	// Compute instance ID (for MIG)
	ComputeInstanceID uint32
}

// ProcessType represents the type of GPU process
type ProcessType int

const (
	ProcessTypeCompute  ProcessType = 0
	ProcessTypeGraphics ProcessType = 1
	ProcessTypeMPS      ProcessType = 2 // Multi-Process Service
)

// collectProcessInfo collects per-process GPU metrics
func (c *Collector) collectProcessInfo(device *Device, m *GPUMetrics) error {
	// In production, these would use NVML calls:
	// nvml.DeviceGetComputeRunningProcesses(device.handle) -> compute processes
	// nvml.DeviceGetGraphicsRunningProcesses(device.handle) -> graphics processes
	// nvml.DeviceGetMPSComputeRunningProcesses(device.handle) -> MPS processes
	// nvml.DeviceGetProcessUtilization(device.handle, ...) -> per-process utilization

	// Initialize with empty process list (no processes in simulation)
	m.Processes = []ProcessMetrics{}

	return nil
}

// GetProcessName attempts to get the process name from PID
// In production, this would read /proc/<pid>/comm or use process utilities
func GetProcessName(pid uint32) string {
	// Placeholder - in production would read from /proc
	return ""
}

// TotalProcessMemory calculates total GPU memory used by all processes
func TotalProcessMemory(processes []ProcessMetrics) uint64 {
	var total uint64
	for _, p := range processes {
		total += p.UsedMemory
	}
	return total
}

// FilterProcessesByType filters processes by their type
func FilterProcessesByType(processes []ProcessMetrics, ptype ProcessType) []ProcessMetrics {
	var result []ProcessMetrics
	for _, p := range processes {
		if p.Type == ptype {
			result = append(result, p)
		}
	}
	return result
}

// TopProcessesByMemory returns the top N processes by GPU memory usage
func TopProcessesByMemory(processes []ProcessMetrics, n int) []ProcessMetrics {
	if len(processes) <= n {
		return processes
	}

	// Simple selection sort for top N (efficient for small N)
	result := make([]ProcessMetrics, len(processes))
	copy(result, processes)

	for i := 0; i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(result); j++ {
			if result[j].UsedMemory > result[maxIdx].UsedMemory {
				maxIdx = j
			}
		}
		result[i], result[maxIdx] = result[maxIdx], result[i]
	}

	return result[:n]
}
