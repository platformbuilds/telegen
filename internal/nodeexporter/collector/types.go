// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package collector

// CPUCollectorConfig holds CPU collector specific configuration.
// This is shared across platforms.
type CPUCollectorConfig struct {
	EnableGuest  bool
	EnableInfo   bool
	FlagsInclude string
	BugsInclude  string
}

// DefaultCPUCollectorConfig returns default CPU collector configuration.
func DefaultCPUCollectorConfig() CPUCollectorConfig {
	return CPUCollectorConfig{
		EnableGuest:  true,
		EnableInfo:   false,
		FlagsInclude: "",
		BugsInclude:  "",
	}
}

// StatCollectorConfig holds stat collector specific configuration.
type StatCollectorConfig struct {
	EnableSoftirq bool
}

// DefaultStatCollectorConfig returns default stat collector configuration.
func DefaultStatCollectorConfig() StatCollectorConfig {
	return StatCollectorConfig{
		EnableSoftirq: true,
	}
}

// TextfileCollectorConfig holds textfile collector specific configuration.
type TextfileCollectorConfig struct {
	Directory string
}

// DefaultTextfileCollectorConfig returns default textfile collector configuration.
func DefaultTextfileCollectorConfig() TextfileCollectorConfig {
	return TextfileCollectorConfig{
		Directory: "",
	}
}
