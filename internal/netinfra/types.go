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

// Re-export functions.
//
// Only the timestamp-taking constructors are mirrored; the clock-reading
// variants were removed because they sampled the clock once per metric and
// smeared a collection cycle across its full duration. See telegen/AGENTS.md
// "Timestamp Provenance".
var (
	NewMetricAt            = types.NewMetricAt
	NewCounterMetricAt     = types.NewCounterMetricAt
	DefaultCollectorConfig = types.DefaultCollectorConfig
)
