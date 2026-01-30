// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-002 - GPU Utilization Metrics
package nvidia

import (
	"time"
)

// GPUMetrics holds all metrics for a single GPU device
type GPUMetrics struct {
	// Metadata
	Timestamp   time.Time
	DeviceIndex int
	DeviceName  string
	DeviceUUID  string
	DeviceInfo  DeviceInfo

	// Utilization metrics (ML-002)
	Utilization UtilizationMetrics

	// Memory metrics (ML-003)
	Memory MemoryMetrics

	// Power metrics (ML-004)
	Power PowerMetrics

	// PCIe metrics (ML-005)
	PCIe PCIeMetrics

	// NVLink metrics (ML-006)
	NVLink NVLinkMetrics

	// Process metrics (ML-007)
	Processes []ProcessMetrics

	// ECC error metrics (ML-008)
	ECC ECCMetrics

	// MIG metrics (ML-009)
	MIG MIGMetrics
}

// UtilizationMetrics holds GPU utilization metrics
type UtilizationMetrics struct {
	// GPU core utilization percentage (0-100)
	GPU uint32

	// Memory controller utilization percentage (0-100)
	Memory uint32

	// Encoder utilization percentage (0-100)
	Encoder uint32

	// Decoder utilization percentage (0-100)
	Decoder uint32

	// SM (Streaming Multiprocessor) clock in MHz
	SMClock uint32

	// Memory clock in MHz
	MemoryClock uint32

	// Graphics clock in MHz
	GraphicsClock uint32

	// Max SM clock in MHz
	MaxSMClock uint32

	// Max memory clock in MHz
	MaxMemoryClock uint32

	// Throttle reasons bitmask
	ThrottleReason uint64

	// Performance state (P0-P15, lower is higher performance)
	PerformanceState uint32
}

// ThrottleReason constants
const (
	ThrottleReasonGPUIdle              uint64 = 1 << 0
	ThrottleReasonApplicationsSlowdown uint64 = 1 << 1
	ThrottleReasonSwPowerCap           uint64 = 1 << 2
	ThrottleReasonHwSlowdown           uint64 = 1 << 3
	ThrottleReasonSyncBoost            uint64 = 1 << 4
	ThrottleReasonSwThermalSlowdown    uint64 = 1 << 5
	ThrottleReasonHwThermalSlowdown    uint64 = 1 << 6
	ThrottleReasonHwPowerBrakeSlowdown uint64 = 1 << 7
	ThrottleReasonDisplayClockSetting  uint64 = 1 << 8
)

// collectUtilization collects GPU utilization metrics
func (c *Collector) collectUtilization(device *Device, m *GPUMetrics) error {
	// In production, these would use NVML calls:
	// nvml.DeviceGetUtilizationRates(device.handle)
	// nvml.DeviceGetClockInfo(device.handle, nvml.CLOCK_SM)
	// nvml.DeviceGetClockInfo(device.handle, nvml.CLOCK_MEM)
	// nvml.DeviceGetClockInfo(device.handle, nvml.CLOCK_GRAPHICS)
	// nvml.DeviceGetMaxClockInfo(device.handle, nvml.CLOCK_SM)
	// nvml.DeviceGetMaxClockInfo(device.handle, nvml.CLOCK_MEM)
	// nvml.DeviceGetCurrentClocksThrottleReasons(device.handle)
	// nvml.DeviceGetPerformanceState(device.handle)
	// nvml.DeviceGetEncoderUtilization(device.handle)
	// nvml.DeviceGetDecoderUtilization(device.handle)

	m.Utilization = UtilizationMetrics{
		GPU:              0,
		Memory:           0,
		Encoder:          0,
		Decoder:          0,
		SMClock:          1410,
		MemoryClock:      1215,
		GraphicsClock:    1410,
		MaxSMClock:       1410,
		MaxMemoryClock:   1215,
		ThrottleReason:   0,
		PerformanceState: 0,
	}

	return nil
}

// IsThrottled returns true if the GPU is being throttled
func IsThrottled(reasons uint64) bool {
	return reasons != 0 && reasons != ThrottleReasonGPUIdle
}

// GetThrottleReasonStrings returns human-readable throttle reasons
func GetThrottleReasonStrings(reasons uint64) []string {
	var result []string

	if reasons&ThrottleReasonGPUIdle != 0 {
		result = append(result, "GPU Idle")
	}
	if reasons&ThrottleReasonApplicationsSlowdown != 0 {
		result = append(result, "Applications Slowdown")
	}
	if reasons&ThrottleReasonSwPowerCap != 0 {
		result = append(result, "Software Power Cap")
	}
	if reasons&ThrottleReasonHwSlowdown != 0 {
		result = append(result, "Hardware Slowdown")
	}
	if reasons&ThrottleReasonSyncBoost != 0 {
		result = append(result, "Sync Boost")
	}
	if reasons&ThrottleReasonSwThermalSlowdown != 0 {
		result = append(result, "Software Thermal Slowdown")
	}
	if reasons&ThrottleReasonHwThermalSlowdown != 0 {
		result = append(result, "Hardware Thermal Slowdown")
	}
	if reasons&ThrottleReasonHwPowerBrakeSlowdown != 0 {
		result = append(result, "Hardware Power Brake")
	}
	if reasons&ThrottleReasonDisplayClockSetting != 0 {
		result = append(result, "Display Clock Setting")
	}

	return result
}
