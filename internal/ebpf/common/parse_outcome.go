// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"log/slog"
	"sync"
	"sync/atomic"
)

// ParseOutcome communicates the result of a single protocol frame parse attempt.
// All protocol handlers should return one of these values so the outer dispatch
// loop can take appropriate corrective action (wait, resync, suppress, etc.).
type ParseOutcome int

const (
	// ParseSuccess means a complete, valid frame was parsed and a span can be emitted.
	ParseSuccess ParseOutcome = iota

	// ParseNeedsMore means the buffer contains an incomplete frame.
	// The outer loop should stop processing this connection and wait for more data.
	ParseNeedsMore

	// ParseInvalid means the buffer contains a corrupt or misidentified frame.
	// The outer loop should increment the failure counter for this connection.
	ParseInvalid

	// ParseIgnored means the frame is valid but does not produce a span
	// (e.g., heartbeat, control packet, handshake).
	ParseIgnored
)

// parseFailureThreshold is the maximum allowed parse failure rate per connection
// before the connection is suppressed. Mirrors Pixie's kParseFailureRateThreshold.
const parseFailureThreshold = 0.4

// parseWindowSize is the number of recent parse attempts kept in the sliding window.
const parseWindowSize = 20

// connParseStats tracks a rolling window of parse outcomes for a single connection.
// Thread-safe via a mutex; connections are typically processed by a single goroutine
// but the map of stats is shared across the parse context.
type connParseStats struct {
	mu      sync.Mutex
	window  [parseWindowSize]bool // true = success, false = failure
	head    int
	total   int
	failures int32 // atomic counter for logging
}

// record records the outcome of a parse attempt and returns whether this
// connection should be suppressed (failure rate exceeded threshold).
func (s *connParseStats) record(outcome ParseOutcome) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch outcome {
	case ParseSuccess, ParseIgnored:
		s.window[s.head] = true
	default:
		s.window[s.head] = false
		atomic.AddInt32(&s.failures, 1)
	}

	s.head = (s.head + 1) % parseWindowSize
	if s.total < parseWindowSize {
		s.total++
	}

	if s.total < parseWindowSize/2 {
		// Not enough samples yet; don't suppress.
		return false
	}

	failCount := 0
	for i := 0; i < s.total; i++ {
		if !s.window[i] {
			failCount++
		}
	}
	rate := float64(failCount) / float64(s.total)
	return rate > parseFailureThreshold
}

// connStatsKey identifies a connection for per-connection parse statistics.
type connStatsKey struct {
	sAddr [16]uint8
	dAddr [16]uint8
	sPort uint16
	dPort uint16
}

func connKeyFromInfo(info BpfConnectionInfoT) connStatsKey {
	return connStatsKey{
		sAddr: [16]uint8(info.S_addr),
		dAddr: [16]uint8(info.D_addr),
		sPort: info.S_port,
		dPort: info.D_port,
	}
}

// recordParseOutcome records the outcome for the given connection in parseCtx.
// Returns true if the connection should be suppressed due to high failure rate.
func recordParseOutcome(parseCtx *EBPFParseContext, connInfo BpfConnectionInfoT, outcome ParseOutcome) bool {
	key := connKeyFromInfo(connInfo)
	parseCtx.parseStatsMu.Lock()
	stats, ok := parseCtx.parseStats[key]
	if !ok {
		stats = &connParseStats{}
		parseCtx.parseStats[key] = stats
	}
	parseCtx.parseStatsMu.Unlock()

	suppress := stats.record(outcome)
	if suppress {
		slog.Warn("suppressing connection due to high parse failure rate",
			"src_port", connInfo.S_port,
			"dst_port", connInfo.D_port,
			"total_failures", atomic.LoadInt32(&stats.failures),
		)
	}
	return suppress
}

// evictConnParseStats removes the stats entry for a connection (called on connection close).
func evictConnParseStats(parseCtx *EBPFParseContext, connInfo BpfConnectionInfoT) {
	key := connKeyFromInfo(connInfo)
	parseCtx.parseStatsMu.Lock()
	delete(parseCtx.parseStats, key)
	parseCtx.parseStatsMu.Unlock()
}
