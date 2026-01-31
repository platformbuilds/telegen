// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package sigdef provides signal metadata definitions for Telegen telemetry.
// All exported signals include these metadata attributes for indexing and discovery.
package sigdef

import (
	"sync"

	"go.opentelemetry.io/otel/attribute"
)

// Telegen-specific attribute keys for signal metadata
// These are exported with all signals for indexing and discovery
const (
	// AttrSignalCategory is the top-level category (e.g., "Host Metrics", "GPU Metrics", "Database Traces")
	AttrSignalCategory = "telegen.signal.category"

	// AttrSignalSubCategory is the sub-category (e.g., "CPU Utilization", "Token Usage", "PostgreSQL")
	AttrSignalSubCategory = "telegen.signal.subcategory"

	// AttrSourceModule is the Go source module that generated this signal
	AttrSourceModule = "telegen.source.module"

	// AttrBPFComponent is the eBPF component used (if any)
	AttrBPFComponent = "telegen.bpf.component"

	// AttrSignalDescription is a human-readable description of the signal
	AttrSignalDescription = "telegen.signal.description"

	// AttrCollectorType is the type of collector (ebpf, jfr, snmp, api, procfs, nvml)
	AttrCollectorType = "telegen.collector.type"
)

// MetadataFieldsConfig controls which metadata fields are exported with signals.
// Each field can be independently enabled/disabled to reduce storage costs.
type MetadataFieldsConfig struct {
	// EnableCategory exports telegen.signal.category / telegen_signal_category
	EnableCategory bool `yaml:"enable_category" env:"TELEGEN_METADATA_CATEGORY"`

	// EnableSubCategory exports telegen.signal.subcategory / telegen_signal_subcategory
	EnableSubCategory bool `yaml:"enable_subcategory" env:"TELEGEN_METADATA_SUBCATEGORY"`

	// EnableSourceModule exports telegen.source.module / telegen_source_module
	EnableSourceModule bool `yaml:"enable_source_module" env:"TELEGEN_METADATA_SOURCE_MODULE"`

	// EnableBPFComponent exports telegen.bpf.component / telegen_bpf_component
	EnableBPFComponent bool `yaml:"enable_bpf_component" env:"TELEGEN_METADATA_BPF_COMPONENT"`

	// EnableDescription exports telegen.signal.description / telegen_signal_description
	EnableDescription bool `yaml:"enable_description" env:"TELEGEN_METADATA_DESCRIPTION"`

	// EnableCollectorType exports telegen.collector.type / telegen_collector_type
	EnableCollectorType bool `yaml:"enable_collector_type" env:"TELEGEN_METADATA_COLLECTOR_TYPE"`
}

// DefaultMetadataFieldsConfig returns the default configuration with all fields enabled
func DefaultMetadataFieldsConfig() MetadataFieldsConfig {
	return MetadataFieldsConfig{
		EnableCategory:      true,
		EnableSubCategory:   true,
		EnableSourceModule:  true,
		EnableBPFComponent:  true,
		EnableDescription:   false, // Disabled by default - descriptions are verbose
		EnableCollectorType: true,
	}
}

// MinimalMetadataFieldsConfig returns a minimal configuration for cost-sensitive environments
func MinimalMetadataFieldsConfig() MetadataFieldsConfig {
	return MetadataFieldsConfig{
		EnableCategory:      true,
		EnableSubCategory:   false,
		EnableSourceModule:  false,
		EnableBPFComponent:  false,
		EnableDescription:   false,
		EnableCollectorType: false,
	}
}

// DisabledMetadataFieldsConfig returns a configuration with all fields disabled
func DisabledMetadataFieldsConfig() MetadataFieldsConfig {
	return MetadataFieldsConfig{}
}

// Global metadata config with thread-safe access
var (
	globalMetadataConfig   = DefaultMetadataFieldsConfig()
	globalMetadataConfigMu sync.RWMutex
)

// SetGlobalMetadataConfig sets the global metadata fields configuration
func SetGlobalMetadataConfig(cfg MetadataFieldsConfig) {
	globalMetadataConfigMu.Lock()
	defer globalMetadataConfigMu.Unlock()
	globalMetadataConfig = cfg
}

// GetGlobalMetadataConfig returns the current global metadata fields configuration
func GetGlobalMetadataConfig() MetadataFieldsConfig {
	globalMetadataConfigMu.RLock()
	defer globalMetadataConfigMu.RUnlock()
	return globalMetadataConfig
}

// CollectorType represents the type of data collector
type CollectorType string

const (
	CollectorTypeEBPF   CollectorType = "ebpf"
	CollectorTypeJFR    CollectorType = "jfr"
	CollectorTypeSNMP   CollectorType = "snmp"
	CollectorTypeAPI    CollectorType = "api"
	CollectorTypeProcFS CollectorType = "procfs"
	CollectorTypeNVML   CollectorType = "nvml"
	CollectorTypeFile   CollectorType = "file"
)

// SignalMetadata contains metadata for a telemetry signal
type SignalMetadata struct {
	// Category is the top-level category
	Category string

	// SubCategory is the sub-category
	SubCategory string

	// SourceModule is the Go source module path
	SourceModule string

	// BPFComponent is the eBPF source file (if applicable)
	BPFComponent string

	// Description is a human-readable description
	Description string

	// CollectorType is the type of collector
	CollectorType CollectorType

	// SignalType is the type of signal (metrics, traces, logs, profiles)
	SignalType SignalType
}

// ToAttributes converts SignalMetadata to OTel attributes for export.
// Respects the global MetadataFieldsConfig to control which fields are exported.
func (m *SignalMetadata) ToAttributes() []attribute.KeyValue {
	return m.ToAttributesWithConfig(GetGlobalMetadataConfig())
}

// ToAttributesWithConfig converts SignalMetadata to OTel attributes using the provided config.
// Use this for explicit control over which fields are exported.
func (m *SignalMetadata) ToAttributesWithConfig(cfg MetadataFieldsConfig) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 6)

	if cfg.EnableCategory && m.Category != "" {
		attrs = append(attrs, attribute.String(AttrSignalCategory, m.Category))
	}
	if cfg.EnableSubCategory && m.SubCategory != "" {
		attrs = append(attrs, attribute.String(AttrSignalSubCategory, m.SubCategory))
	}
	if cfg.EnableSourceModule && m.SourceModule != "" {
		attrs = append(attrs, attribute.String(AttrSourceModule, m.SourceModule))
	}
	if cfg.EnableBPFComponent && m.BPFComponent != "" {
		attrs = append(attrs, attribute.String(AttrBPFComponent, m.BPFComponent))
	}
	if cfg.EnableDescription && m.Description != "" {
		attrs = append(attrs, attribute.String(AttrSignalDescription, m.Description))
	}
	if cfg.EnableCollectorType && m.CollectorType != "" {
		attrs = append(attrs, attribute.String(AttrCollectorType, string(m.CollectorType)))
	}

	return attrs
}

// ToPrometheusLabels converts SignalMetadata to Prometheus-compatible labels.
// Respects the global MetadataFieldsConfig to control which fields are exported.
func (m *SignalMetadata) ToPrometheusLabels() map[string]string {
	return m.ToPrometheusLabelsWithConfig(GetGlobalMetadataConfig())
}

// ToPrometheusLabelsWithConfig converts SignalMetadata to Prometheus-compatible labels
// using the provided config. Use this for explicit control over which fields are exported.
func (m *SignalMetadata) ToPrometheusLabelsWithConfig(cfg MetadataFieldsConfig) map[string]string {
	labels := make(map[string]string, 6)

	if cfg.EnableCategory && m.Category != "" {
		labels["telegen_signal_category"] = m.Category
	}
	if cfg.EnableSubCategory && m.SubCategory != "" {
		labels["telegen_signal_subcategory"] = m.SubCategory
	}
	if cfg.EnableSourceModule && m.SourceModule != "" {
		labels["telegen_source_module"] = m.SourceModule
	}
	if cfg.EnableBPFComponent && m.BPFComponent != "" {
		labels["telegen_bpf_component"] = m.BPFComponent
	}
	if cfg.EnableDescription && m.Description != "" {
		labels["telegen_signal_description"] = m.Description
	}
	if cfg.EnableCollectorType && m.CollectorType != "" {
		labels["telegen_collector_type"] = string(m.CollectorType)
	}

	return labels
}

// Clone creates a copy of SignalMetadata
func (m *SignalMetadata) Clone() *SignalMetadata {
	return &SignalMetadata{
		Category:      m.Category,
		SubCategory:   m.SubCategory,
		SourceModule:  m.SourceModule,
		BPFComponent:  m.BPFComponent,
		Description:   m.Description,
		CollectorType: m.CollectorType,
		SignalType:    m.SignalType,
	}
}

// WithSubCategory returns a copy with a different sub-category
func (m *SignalMetadata) WithSubCategory(subCategory string) *SignalMetadata {
	c := m.Clone()
	c.SubCategory = subCategory
	return c
}

// WithDescription returns a copy with a different description
func (m *SignalMetadata) WithDescription(description string) *SignalMetadata {
	c := m.Clone()
	c.Description = description
	return c
}
