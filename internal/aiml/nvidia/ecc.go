// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-008 - GPU ECC Error Metrics
package nvidia

// ECCMetrics holds GPU ECC (Error Correction Code) memory error metrics
type ECCMetrics struct {
	// Whether ECC is enabled on this GPU
	Enabled bool

	// Whether ECC is pending (requires reboot)
	Pending bool

	// ECC mode
	Mode ECCMode

	// Volatile (current boot) error counts
	VolatileSingleBit uint64
	VolatileDoubleBit uint64

	// Aggregate (lifetime) error counts
	AggregateSingleBit uint64
	AggregateDoubleBit uint64

	// Per-memory location error counts
	L1Cache       ECCErrorCounts
	L2Cache       ECCErrorCounts
	DeviceMemory  ECCErrorCounts
	RegisterFile  ECCErrorCounts
	TextureMemory ECCErrorCounts

	// Retired pages information
	RetiredPages RetiredPagesInfo
}

// ECCMode represents the ECC mode
type ECCMode int

const (
	ECCModeDisabled ECCMode = 0
	ECCModeEnabled  ECCMode = 1
)

// ECCErrorCounts holds error counts for a specific memory location
type ECCErrorCounts struct {
	// Single-bit correctable errors (volatile)
	VolatileSingleBit uint64

	// Double-bit uncorrectable errors (volatile)
	VolatileDoubleBit uint64

	// Single-bit correctable errors (aggregate/lifetime)
	AggregateSingleBit uint64

	// Double-bit uncorrectable errors (aggregate/lifetime)
	AggregateDoubleBit uint64
}

// RetiredPagesInfo holds information about retired memory pages
type RetiredPagesInfo struct {
	// Pages retired due to single-bit errors
	SingleBitPages uint32

	// Pages retired due to double-bit errors
	DoubleBitPages uint32

	// Whether a page retirement is pending
	PendingRetirement bool
}

// collectECC collects GPU ECC error metrics
func (c *Collector) collectECC(device *Device, m *GPUMetrics) error {
	// In production, these would use NVML calls:
	// nvml.DeviceGetEccMode(device.handle) -> current, pending
	// nvml.DeviceGetTotalEccErrors(device.handle, VOLATILE_ECC, SINGLE_BIT_ECC) -> singleBit
	// nvml.DeviceGetTotalEccErrors(device.handle, VOLATILE_ECC, DOUBLE_BIT_ECC) -> doubleBit
	// nvml.DeviceGetMemoryErrorCounter(device.handle, ..., MEMORY_LOCATION_*) -> per-location
	// nvml.DeviceGetRetiredPages(device.handle, ...) -> retired pages

	m.ECC = ECCMetrics{
		Enabled:            false,
		Pending:            false,
		Mode:               ECCModeDisabled,
		VolatileSingleBit:  0,
		VolatileDoubleBit:  0,
		AggregateSingleBit: 0,
		AggregateDoubleBit: 0,
		L1Cache:            ECCErrorCounts{},
		L2Cache:            ECCErrorCounts{},
		DeviceMemory:       ECCErrorCounts{},
		RegisterFile:       ECCErrorCounts{},
		TextureMemory:      ECCErrorCounts{},
		RetiredPages: RetiredPagesInfo{
			SingleBitPages:    0,
			DoubleBitPages:    0,
			PendingRetirement: false,
		},
	}

	return nil
}

// HasUncorrectableErrors returns true if there are any double-bit errors
func HasUncorrectableErrors(ecc *ECCMetrics) bool {
	return ecc.VolatileDoubleBit > 0 || ecc.AggregateDoubleBit > 0
}

// HasCorrectableErrors returns true if there are any single-bit errors
func HasCorrectableErrors(ecc *ECCMetrics) bool {
	return ecc.VolatileSingleBit > 0 || ecc.AggregateSingleBit > 0
}

// GetTotalErrors returns total error counts across all memory locations
func GetTotalErrors(ecc *ECCMetrics) (singleBit, doubleBit uint64) {
	locations := []ECCErrorCounts{
		ecc.L1Cache,
		ecc.L2Cache,
		ecc.DeviceMemory,
		ecc.RegisterFile,
		ecc.TextureMemory,
	}

	for _, loc := range locations {
		singleBit += loc.VolatileSingleBit + loc.AggregateSingleBit
		doubleBit += loc.VolatileDoubleBit + loc.AggregateDoubleBit
	}

	return singleBit, doubleBit
}

// ECCSeverity returns the severity level of ECC errors
type ECCSeverity int

const (
	ECCSeverityNone     ECCSeverity = 0
	ECCSeverityWarning  ECCSeverity = 1 // Single-bit errors (correctable)
	ECCSeverityCritical ECCSeverity = 2 // Double-bit errors (uncorrectable)
)

// GetECCSeverity determines the severity level based on error counts
func GetECCSeverity(ecc *ECCMetrics) ECCSeverity {
	if HasUncorrectableErrors(ecc) {
		return ECCSeverityCritical
	}
	if HasCorrectableErrors(ecc) {
		return ECCSeverityWarning
	}
	return ECCSeverityNone
}

// NeedsReboot checks if GPU needs reboot for ECC changes or page retirement
func NeedsReboot(ecc *ECCMetrics) bool {
	return ecc.Pending || ecc.RetiredPages.PendingRetirement
}
