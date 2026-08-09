// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
)

func TestConnParseStats_RecordIgnoredNeverSuppresses(t *testing.T) {
	stats := &connParseStats{}
	for i := 0; i < 40; i++ {
		suppressed, changed := stats.record(ParseIgnored)
		assert.False(t, suppressed)
		assert.False(t, changed)
	}
}

func TestConnParseStats_RecordInvalidSuppressesOnce(t *testing.T) {
	stats := &connParseStats{}
	transitions := 0
	suppressed := false
	changed := false

	for i := 0; i < 20; i++ {
		suppressed, changed = stats.record(ParseInvalid)
		if changed {
			transitions++
			assert.True(t, suppressed)
		}
	}

	assert.True(t, suppressed)
	assert.Equal(t, 1, transitions)
}

func TestConnParseStats_RecordSuccessRecoversOnce(t *testing.T) {
	stats := &connParseStats{}
	for i := 0; i < 20; i++ {
		stats.record(ParseInvalid)
	}

	transitions := 0
	suppressed := true
	changed := false
	for i := 0; i < 20; i++ {
		suppressed, changed = stats.record(ParseSuccess)
		if changed {
			transitions++
			assert.False(t, suppressed)
		}
	}

	assert.False(t, suppressed)
	assert.Equal(t, 1, transitions)
}

func TestIsConnSuppressedDoesNotMutateWindow(t *testing.T) {
	parseCtx := &EBPFParseContext{
		parseStats: expirable.NewLRU[connStatsKey, *connParseStats](8, nil, time.Minute),
	}
	conn := BpfConnectionInfoT{
		S_port: 9092,
		D_port: 35718,
	}
	conn.S_addr[0] = 10
	conn.S_addr[1] = 42
	conn.D_addr[0] = 10
	conn.D_addr[1] = 99

	stats := &connParseStats{}
	for i := 0; i < 20; i++ {
		stats.record(ParseInvalid)
	}

	parseCtx.parseStats.Add(connKeyFromInfo(conn), stats)
	beforeTotal := stats.total

	assert.True(t, isConnSuppressed(parseCtx, conn))
	assert.Equal(t, beforeTotal, stats.total)
}
