// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"strings"
)

// ParseMode parses a mode string into a Mode constant
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "agent", "":
		return ModeAgent, nil
	case "collector":
		return ModeCollector, nil
	case "unified", "both":
		return ModeUnified, nil
	default:
		return "", fmt.Errorf("unknown mode: %q (valid: agent, collector, unified)", s)
	}
}

// ModeCapabilities describes what capabilities are available in each mode
type ModeCapabilities struct {
	// eBPF indicates if eBPF-based tracing is available
	EBPF bool

	// Profiling indicates if continuous profiling is available
	Profiling bool

	// LogCollection indicates if local log collection is available
	LogCollection bool

	// SNMP indicates if SNMP polling/traps are available
	SNMP bool

	// RemotePolling indicates if remote API polling is available
	RemotePolling bool

	// KubernetesEnrichment indicates if K8s metadata enrichment is available
	KubernetesEnrichment bool

	// ContainerEnrichment indicates if container metadata enrichment is available
	ContainerEnrichment bool
}

// Capabilities returns the capabilities for the given mode
func (m Mode) Capabilities() ModeCapabilities {
	switch m {
	case ModeAgent:
		return ModeCapabilities{
			EBPF:                 true,
			Profiling:            true,
			LogCollection:        true,
			SNMP:                 false,
			RemotePolling:        false,
			KubernetesEnrichment: true,
			ContainerEnrichment:  true,
		}
	case ModeCollector:
		return ModeCapabilities{
			EBPF:                 false,
			Profiling:            false,
			LogCollection:        false,
			SNMP:                 true,
			RemotePolling:        true,
			KubernetesEnrichment: false,
			ContainerEnrichment:  false,
		}
	case ModeUnified:
		return ModeCapabilities{
			EBPF:                 true,
			Profiling:            true,
			LogCollection:        true,
			SNMP:                 true,
			RemotePolling:        true,
			KubernetesEnrichment: true,
			ContainerEnrichment:  true,
		}
	default:
		return ModeCapabilities{}
	}
}

// ValidateConfig validates the agent config for the specified mode
func (m Mode) ValidateConfig(cfg *Config) error {
	caps := m.Capabilities()

	// Validate mode-specific settings
	if !caps.EBPF && cfg.Pipeline.EBPF.Enabled {
		return fmt.Errorf("eBPF tracing not available in %s mode", m)
	}

	if !caps.Profiling && cfg.Pipeline.Profiling.Enabled {
		return fmt.Errorf("profiling not available in %s mode", m)
	}

	if !caps.SNMP && cfg.Pipeline.SNMP.Enabled {
		return fmt.Errorf("SNMP not available in %s mode", m)
	}

	return nil
}

// String returns the string representation of the mode
func (m Mode) String() string {
	return string(m)
}

// IsValid returns true if the mode is a valid known mode
func (m Mode) IsValid() bool {
	switch m {
	case ModeAgent, ModeCollector, ModeUnified:
		return true
	default:
		return false
	}
}
