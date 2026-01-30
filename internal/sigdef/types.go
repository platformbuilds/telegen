// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package sigdef provides shared signal type definitions to avoid import cycles.
package sigdef

// SignalType represents the type of telemetry signal
type SignalType string

const (
SignalTraces   SignalType = "traces"
SignalMetrics  SignalType = "metrics"
SignalLogs     SignalType = "logs"
SignalProfiles SignalType = "profiles"
)

// Signal represents a generic telemetry signal that can be routed
type Signal interface {
	// Type returns the signal type
	Type() SignalType
	// Size returns the approximate size in bytes
	Size() int
}
