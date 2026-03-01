// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package netinfra provides network infrastructure observability integrations
// for Arista CloudVision and Cisco ACI platforms.
package netinfra

import (
	"github.com/mirastacklabs-ai/telegen/internal/netinfra/types"
)

// Re-export types from the types package for backward compatibility
type (
	NetworkMetric   = types.NetworkMetric
	MetricType      = types.MetricType
	Collector       = types.Collector
	CollectorConfig = types.CollectorConfig
)

// Re-export constants
const (
	MetricTypeGauge   = types.MetricTypeGauge
	MetricTypeCounter = types.MetricTypeCounter
)

// Re-export functions
var (
	NewMetric              = types.NewMetric
	NewCounterMetric       = types.NewCounterMetric
	DefaultCollectorConfig = types.DefaultCollectorConfig
)
