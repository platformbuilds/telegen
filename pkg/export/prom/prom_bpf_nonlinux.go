// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package prom // import "github.com/platformbuilds/telegen/pkg/export/prom"

func (bc *BPFCollector) enableBPFStatsRuntime() {}
