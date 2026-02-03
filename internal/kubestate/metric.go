// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"math"
	"strconv"
	"strings"
)

// Type represents OpenMetrics metric types
type Type string

const (
	// Gauge is a metric that can go up and down
	Gauge Type = "gauge"
	// Counter is a metric that only goes up
	Counter Type = "counter"
	// Info is a metric with value 1 used for labels
	Info Type = "info"
	// StateSet is a metric representing a set of states
	StateSet Type = "stateset"
)

// Metric represents a single time series
type Metric struct {
	LabelKeys   []string
	LabelValues []string
	Value       float64
}

// Family represents a metric family (group of metrics with same name)
type Family struct {
	Name    string
	Type    Type
	Help    string
	Metrics []*Metric
}

// Write serializes the metric to Prometheus exposition format
func (m *Metric) Write(buf *bytes.Buffer, name string) {
	buf.WriteString(name)
	writeLabels(buf, m.LabelKeys, m.LabelValues)
	buf.WriteByte(' ')
	writeFloat(buf, m.Value)
	buf.WriteByte('\n')
}

// writeLabels writes label key-value pairs in Prometheus format
func writeLabels(buf *bytes.Buffer, keys, values []string) {
	if len(keys) == 0 {
		return
	}

	buf.WriteByte('{')
	for i := 0; i < len(keys); i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(keys[i])
		buf.WriteString("=\"")
		escapeLabelValue(buf, values[i])
		buf.WriteByte('"')
	}
	buf.WriteByte('}')
}

// escapeLabelValue escapes special characters in label values
func escapeLabelValue(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			buf.WriteString("\\\\")
		case '"':
			buf.WriteString("\\\"")
		case '\n':
			buf.WriteString("\\n")
		default:
			buf.WriteByte(s[i])
		}
	}
}

// writeFloat writes a float64 in a format suitable for Prometheus
func writeFloat(buf *bytes.Buffer, f float64) {
	switch {
	case math.IsNaN(f):
		buf.WriteString("NaN")
	case math.IsInf(f, 1):
		buf.WriteString("+Inf")
	case math.IsInf(f, -1):
		buf.WriteString("-Inf")
	default:
		buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	}
}

// Write serializes the family to Prometheus exposition format
func (f *Family) Write(buf *bytes.Buffer) {
	if len(f.Metrics) == 0 {
		return
	}

	// Write HELP line
	buf.WriteString("# HELP ")
	buf.WriteString(f.Name)
	buf.WriteByte(' ')
	buf.WriteString(f.Help)
	buf.WriteByte('\n')

	// Write TYPE line
	buf.WriteString("# TYPE ")
	buf.WriteString(f.Name)
	buf.WriteByte(' ')
	buf.WriteString(string(f.Type))
	buf.WriteByte('\n')

	// Write all metrics
	for _, m := range f.Metrics {
		m.Write(buf, f.Name)
	}
}

// ByteSlice returns the family as a byte slice
func (f *Family) ByteSlice() []byte {
	buf := &bytes.Buffer{}
	f.Write(buf)
	return buf.Bytes()
}

// Helper functions for creating metrics

// BoolFloat64 converts a boolean to float64 (1.0 for true, 0.0 for false)
func BoolFloat64(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// SanitizeLabelName sanitizes a string for use as a Prometheus label name
func SanitizeLabelName(name string) string {
	// Replace invalid characters with underscores
	result := strings.Builder{}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			result.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			result.WriteRune(r)
		case r >= '0' && r <= '9' && i > 0:
			result.WriteRune(r)
		case r == '_':
			result.WriteRune(r)
		default:
			result.WriteRune('_')
		}
	}
	return result.String()
}

// SanitizeLabelValue sanitizes a string for use as a Prometheus label value
func SanitizeLabelValue(value string) string {
	// Label values can contain any unicode character
	// but we should handle empty strings
	if value == "" {
		return ""
	}
	return value
}
