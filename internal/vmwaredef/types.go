// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package vmwaredef provides shared, dependency-free type definitions for the
// VMware vSphere collector. It intentionally imports only the standard library
// so that internal/config can reference it without pulling in govmomi.
package vmwaredef

import "time"

// MetricType represents the type of a VMware metric.
type MetricType string

const (
	MetricTypeGauge   MetricType = "gauge"
	MetricTypeCounter MetricType = "counter"
)

// Metric represents a single normalized VMware metric sample.
// Mirror of storagedef.Metric (internal/storagedef/types.go).
type Metric struct {
	Name               string
	Help               string
	Type               MetricType
	Value              float64
	Labels             map[string]string
	Timestamp          time.Time // Source timestamp (from vCenter PerfSampleInfo or inventory snapshot)
	ObservedTimestamp  time.Time // Collection instant (time.Now() at collection time)
}

// LogRecord represents a normalized VMware log/event record that is emitted as
// an OTLP log through the shared logger provider.
type LogRecord struct {
	Timestamp  time.Time
	Severity   string // one of: trace,debug,info,warn,error (mapped in logs_exporter.go)
	Body       string
	Attributes map[string]string
}
