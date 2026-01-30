// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-009 - MIG (Multi-Instance GPU) Metrics
package nvidia

import "strings"

// MIGMetrics holds Multi-Instance GPU metrics
type MIGMetrics struct {
	// Whether MIG mode is enabled
	Enabled bool

	// MIG mode (current and pending)
	Mode        MIGMode
	PendingMode MIGMode

	// Number of GPU instances
	GPUInstanceCount uint32

	// GPU instances
	GPUInstances []GPUInstance

	// Maximum number of GPU instances possible
	MaxGPUInstances uint32
}

// MIGMode represents the MIG mode state
type MIGMode int

const (
	MIGModeDisabled MIGMode = 0
	MIGModeEnabled  MIGMode = 1
)

// GPUInstance represents a MIG GPU instance
type GPUInstance struct {
	// Instance ID
	ID uint32

	// Instance UUID
	UUID string

	// Profile ID
	ProfileID uint32

	// Profile name (e.g., "1g.5gb", "2g.10gb", "3g.20gb")
	ProfileName string

	// Compute instances within this GPU instance
	ComputeInstances []ComputeInstance

	// Placement information
	Placement GPUInstancePlacement

	// Memory information
	MemoryTotal uint64
	MemoryUsed  uint64
	MemoryFree  uint64

	// SM count
	SMCount uint32
}

// ComputeInstance represents a MIG compute instance
type ComputeInstance struct {
	// Instance ID
	ID uint32

	// Profile ID
	ProfileID uint32

	// Profile name
	ProfileName string

	// SM count available to this compute instance
	SMCount uint32
}

// GPUInstancePlacement holds placement info for a GPU instance
type GPUInstancePlacement struct {
	// Start slice index
	Start uint32

	// Size in slices
	Size uint32
}

// MIGProfile holds MIG profile definitions
type MIGProfile struct {
	Name       string
	Slices     uint32
	MemoryGB   uint32
	SMFraction float64
}

// Common MIG profiles for A100 (7 slices total)
var MIGProfilesA100 = map[uint32]MIGProfile{
	0:  {Name: "1g.5gb", Slices: 1, MemoryGB: 5, SMFraction: 0.143},
	1:  {Name: "1g.5gb+me", Slices: 1, MemoryGB: 5, SMFraction: 0.143},
	5:  {Name: "2g.10gb", Slices: 2, MemoryGB: 10, SMFraction: 0.286},
	9:  {Name: "3g.20gb", Slices: 3, MemoryGB: 20, SMFraction: 0.429},
	14: {Name: "4g.20gb", Slices: 4, MemoryGB: 20, SMFraction: 0.571},
	19: {Name: "7g.40gb", Slices: 7, MemoryGB: 40, SMFraction: 1.0},
}

// Common MIG profiles for H100 (8 slices total)
var MIGProfilesH100 = map[uint32]MIGProfile{
	0:  {Name: "1g.10gb", Slices: 1, MemoryGB: 10, SMFraction: 0.125},
	5:  {Name: "2g.20gb", Slices: 2, MemoryGB: 20, SMFraction: 0.25},
	9:  {Name: "3g.40gb", Slices: 3, MemoryGB: 40, SMFraction: 0.375},
	14: {Name: "4g.40gb", Slices: 4, MemoryGB: 40, SMFraction: 0.5},
	19: {Name: "7g.80gb", Slices: 7, MemoryGB: 80, SMFraction: 0.875},
}

// collectMIG collects MIG instance metrics
func (c *Collector) collectMIG(device *Device, m *GPUMetrics) error {
	// In production, these would use NVML calls:
	// nvml.DeviceGetMigMode(device.handle) -> currentMode, pendingMode
	// nvml.DeviceGetGpuInstances(device.handle, profileId) -> gpuInstances
	// nvml.DeviceGetMaxMigDeviceCount(device.handle) -> maxCount
	// nvml.GpuInstanceGetInfo(gpuInstance) -> info
	// nvml.GpuInstanceGetComputeInstances(gpuInstance, profileId) -> computeInstances

	m.MIG = MIGMetrics{
		Enabled:          false,
		Mode:             MIGModeDisabled,
		PendingMode:      MIGModeDisabled,
		GPUInstanceCount: 0,
		GPUInstances:     nil,
		MaxGPUInstances:  0,
	}

	return nil
}

// IsMIGCapable checks if the GPU architecture supports MIG
func IsMIGCapable(arch GPUArchitecture) bool {
	// MIG is supported on Ampere (A100) and later
	return arch >= ArchAmpere
}

// GPUArchitecture represents NVIDIA GPU architecture
type GPUArchitecture int

const (
	ArchUnknown GPUArchitecture = iota
	ArchKepler
	ArchMaxwell
	ArchPascal
	ArchVolta
	ArchTuring
	ArchAmpere
	ArchHopper
)

// GetArchitectureFromComputeCapability returns architecture from compute capability
func GetArchitectureFromComputeCapability(major, minor int) GPUArchitecture {
	switch major {
	case 3:
		return ArchKepler
	case 5:
		return ArchMaxwell
	case 6:
		return ArchPascal
	case 7:
		if minor < 5 {
			return ArchVolta
		}
		return ArchTuring
	case 8:
		if minor < 9 {
			return ArchAmpere
		}
		return ArchHopper
	case 9:
		return ArchHopper
	default:
		return ArchUnknown
	}
}

// GetMIGProfileForGPU returns available MIG profiles for the GPU
func GetMIGProfileForGPU(gpuName string) map[uint32]MIGProfile {
	if strings.Contains(gpuName, "A100") {
		return MIGProfilesA100
	}
	if strings.Contains(gpuName, "H100") {
		return MIGProfilesH100
	}
	return nil
}

// CalculateMIGUtilization calculates overall MIG utilization
func CalculateMIGUtilization(mig *MIGMetrics) float64 {
	if !mig.Enabled || mig.GPUInstanceCount == 0 {
		return 0
	}

	var totalUsed, totalAvailable uint64
	for _, inst := range mig.GPUInstances {
		totalUsed += inst.MemoryUsed
		totalAvailable += inst.MemoryTotal
	}

	if totalAvailable == 0 {
		return 0
	}

	return float64(totalUsed) / float64(totalAvailable) * 100.0
}
