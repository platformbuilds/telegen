// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package sigdef provides signal metadata definitions for Telegen telemetry.
// All exported signals include these metadata attributes for indexing and discovery.
package sigdef

import (
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

// ToAttributes converts SignalMetadata to OTel attributes for export
func (m *SignalMetadata) ToAttributes() []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 6)

	if m.Category != "" {
		attrs = append(attrs, attribute.String(AttrSignalCategory, m.Category))
	}
	if m.SubCategory != "" {
		attrs = append(attrs, attribute.String(AttrSignalSubCategory, m.SubCategory))
	}
	if m.SourceModule != "" {
		attrs = append(attrs, attribute.String(AttrSourceModule, m.SourceModule))
	}
	if m.BPFComponent != "" {
		attrs = append(attrs, attribute.String(AttrBPFComponent, m.BPFComponent))
	}
	if m.Description != "" {
		attrs = append(attrs, attribute.String(AttrSignalDescription, m.Description))
	}
	if m.CollectorType != "" {
		attrs = append(attrs, attribute.String(AttrCollectorType, string(m.CollectorType)))
	}

	return attrs
}

// ToPrometheusLabels converts SignalMetadata to Prometheus-compatible labels
// for Remote Write to OTel Collector's prometheusreceiver
func (m *SignalMetadata) ToPrometheusLabels() map[string]string {
	labels := make(map[string]string, 6)

	if m.Category != "" {
		labels["telegen_signal_category"] = m.Category
	}
	if m.SubCategory != "" {
		labels["telegen_signal_subcategory"] = m.SubCategory
	}
	if m.SourceModule != "" {
		labels["telegen_source_module"] = m.SourceModule
	}
	if m.BPFComponent != "" {
		labels["telegen_bpf_component"] = m.BPFComponent
	}
	if m.Description != "" {
		labels["telegen_signal_description"] = m.Description
	}
	if m.CollectorType != "" {
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
