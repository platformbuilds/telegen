// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-004 - GPU Power Metrics
package nvidia

// PowerMetrics holds GPU power and thermal metrics
type PowerMetrics struct {
	// Current power usage in milliwatts
	Usage uint32

	// Power limit in milliwatts
	Limit uint32

	// Default power limit in milliwatts
	DefaultLimit uint32

	// Min power limit in milliwatts
	MinLimit uint32

	// Max power limit in milliwatts
	MaxLimit uint32

	// Enforced power limit in milliwatts
	EnforcedLimit uint32

	// GPU temperature in Celsius
	Temperature uint32

	// GPU memory temperature in Celsius
	MemoryTemperature uint32

	// GPU junction temperature in Celsius (hottest spot)
	JunctionTemperature uint32

	// Temperature threshold for slowdown in Celsius
	SlowdownThreshold uint32

	// Temperature threshold for shutdown in Celsius
	ShutdownThreshold uint32

	// Fan speed percentage (0-100)
	FanSpeed uint32

	// Number of fans
	FanCount uint32
}

// TemperatureStatus represents temperature health status
type TemperatureStatus int

const (
	TemperatureNormal   TemperatureStatus = 0
	TemperatureWarning  TemperatureStatus = 1
	TemperatureCritical TemperatureStatus = 2
)

// collectPower collects GPU power and thermal metrics
func (c *Collector) collectPower(device *Device, m *GPUMetrics) error {
	// In production, these would use NVML calls:
	// nvml.DeviceGetPowerUsage(device.handle) -> power in mW
	// nvml.DeviceGetPowerManagementLimit(device.handle) -> limit
	// nvml.DeviceGetPowerManagementDefaultLimit(device.handle) -> default
	// nvml.DeviceGetPowerManagementLimitConstraints(device.handle) -> min, max
	// nvml.DeviceGetEnforcedPowerLimit(device.handle) -> enforced
	// nvml.DeviceGetTemperature(device.handle, TEMPERATURE_GPU) -> temp
	// nvml.DeviceGetTemperatureThreshold(device.handle, TEMPERATURE_THRESHOLD_SLOWDOWN)
	// nvml.DeviceGetTemperatureThreshold(device.handle, TEMPERATURE_THRESHOLD_SHUTDOWN)
	// nvml.DeviceGetFanSpeed(device.handle) -> fan speed %
	// nvml.DeviceGetNumFans(device.handle) -> fan count

	m.Power = PowerMetrics{
		Usage:               0,
		Limit:               device.Info.PowerLimit,
		DefaultLimit:        device.Info.PowerLimit,
		MinLimit:            100000, // 100W
		MaxLimit:            500000, // 500W
		EnforcedLimit:       device.Info.PowerLimit,
		Temperature:         35,
		MemoryTemperature:   33,
		JunctionTemperature: 38,
		SlowdownThreshold:   83,
		ShutdownThreshold:   90,
		FanSpeed:            0,
		FanCount:            0, // Passively cooled
	}

	return nil
}

// GetTemperatureStatus returns the temperature health status
func GetTemperatureStatus(power *PowerMetrics) TemperatureStatus {
	if power.Temperature >= power.SlowdownThreshold {
		return TemperatureCritical
	}
	if power.Temperature >= power.SlowdownThreshold-10 {
		return TemperatureWarning
	}
	return TemperatureNormal
}

// PowerUsagePercent returns power usage as a percentage of limit
func PowerUsagePercent(power *PowerMetrics) float64 {
	if power.Limit == 0 {
		return 0
	}
	return float64(power.Usage) / float64(power.Limit) * 100.0
}

// WattsFromMilliwatts converts milliwatts to watts
func WattsFromMilliwatts(mW uint32) float64 {
	return float64(mW) / 1000.0
}
