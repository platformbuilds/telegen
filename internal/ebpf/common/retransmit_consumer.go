// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package ebpfcommon provides shared eBPF consumers.
// RetransmitConsumer reads tcp_retransmit_events from bpf/network/tcp_metrics.c and
// exposes per-connection retransmit count and smoothed RTT as OTel metrics.
// Ported from Pixie's tcp_stats connector (src/stirling/source_connectors/tcp_stats/).
package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/cilium/ebpf"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
)

// tcpRetransmitEventSize is the exact byte layout of struct tcp_retransmit_event from
// bpf/network/tcp_metrics.c. Fields in declaration order:
//
//	timestamp(8) pid(4) tid(4) saddr(4) daddr(4) sport(2) dport(2)
//	seq(4) len(4) retrans_count(4) state(1) _pad(3) srtt_us(4) comm(16)
//
// Total = 64 bytes.
const tcpRetransmitEventSize = 8 + 4 + 4 + 4 + 4 + 2 + 2 + 4 + 4 + 4 + 1 + 3 + 4 + 16

// RetransmitConsumer reads tcp_retransmit_events from the BPF ring buffer and emits
// per-connection retransmit counters and RTT histograms as OTel metrics.
//
// Ported from Pixie's per-connection TCP stats connector; Pixie uses kprobes on
// tcp_retransmit_skb to track loss at the 5-tuple level.
type RetransmitConsumer struct {
	reader *ringbuf.Reader
	log    *slog.Logger

	retransmitCounter metric.Int64Counter
	srttHistogram     metric.Int64Histogram
}

// NewRetransmitConsumer creates a RetransmitConsumer attached to the provided
// tcp_retransmit_events ring-buffer map.
func NewRetransmitConsumer(
	retransmitMap *ebpf.Map,
	meterProvider metric.MeterProvider,
	log *slog.Logger,
) (*RetransmitConsumer, error) {
	if retransmitMap == nil {
		return nil, errors.New("tcp_retransmit_events map is nil")
	}

	rd, err := ringbuf.NewReader(retransmitMap)
	if err != nil {
		return nil, fmt.Errorf("creating retransmit ring buffer reader: %w", err)
	}

	meter := meterProvider.Meter("telegen.tcp_retransmits")

	retrans, err := meter.Int64Counter(
		"telegen.tcp.retransmits",
		metric.WithDescription("Number of TCP segment retransmissions per connection"),
		metric.WithUnit("{retransmission}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating retransmits counter: %w", err)
	}

	srtt, err := meter.Int64Histogram(
		"telegen.tcp.srtt_microseconds",
		metric.WithDescription("Smoothed round-trip time per TCP retransmit event (µs)"),
		metric.WithUnit("us"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating srtt histogram: %w", err)
	}

	return &RetransmitConsumer{
		reader:            rd,
		log:               log.With("component", "tcp_retransmit_consumer"),
		retransmitCounter: retrans,
		srttHistogram:     srtt,
	}, nil
}

// Run reads tcp_retransmit_events until ctx is cancelled.
// Call this in a dedicated goroutine.
func (c *RetransmitConsumer) Run(ctx context.Context) {
	c.log.Debug("starting tcp_retransmit consumer")
	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.log.Debug("retransmit ring buffer closed — stopping")
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			c.log.Warn("retransmit ring buffer read error", "error", err)
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		c.handleEvent(ctx, record.RawSample)
	}
}

// Close shuts down the ring buffer reader.
func (c *RetransmitConsumer) Close() error {
	return c.reader.Close()
}

// handleEvent parses one tcp_retransmit_event and records OTel metrics.
//
// Layout (little-endian):
//
//	[0:8]   timestamp
//	[8:12]  pid
//	[12:16] tid
//	[16:20] saddr
//	[20:24] daddr
//	[24:26] sport
//	[26:28] dport
//	[28:32] seq
//	[32:36] len
//	[36:40] retrans_count
//	[40]    state
//	[41:44] _pad
//	[44:48] srtt_us
//	[48:64] comm
func (c *RetransmitConsumer) handleEvent(ctx context.Context, raw []byte) {
	if len(raw) < tcpRetransmitEventSize {
		c.log.Warn("tcp_retransmit_event too small", "size", len(raw), "expected", tcpRetransmitEventSize)
		return
	}

	saddr := binary.LittleEndian.Uint32(raw[16:20])
	daddr := binary.LittleEndian.Uint32(raw[20:24])
	sport := binary.LittleEndian.Uint16(raw[24:26])
	dport := binary.LittleEndian.Uint16(raw[26:28])
	retransCount := int64(binary.LittleEndian.Uint32(raw[36:40]))
	srttUs := int64(binary.LittleEndian.Uint32(raw[44:48]))

	srcIP := retransmitIntToIPv4(saddr)
	dstIP := retransmitIntToIPv4(daddr)

	attrs := []attribute.KeyValue{
		attribute.String("src.address", srcIP),
		attribute.String("dst.address", dstIP),
		attribute.Int("src.port", int(sport)),
		attribute.Int("dst.port", int(dport)),
	}
	attrSet := metric.WithAttributes(attrs...)

	// Record incremental retransmit (add 1 per event; the BPF fires once per retransmit).
	c.retransmitCounter.Add(ctx, 1, attrSet)

	// Record current smoothed RTT at the retransmit sample point.
	if srttUs > 0 {
		c.srttHistogram.Record(ctx, srttUs, attrSet)
	}

	c.log.Debug("tcp_retransmit",
		"src", fmt.Sprintf("%s:%d", srcIP, sport),
		"dst", fmt.Sprintf("%s:%d", dstIP, dport),
		"retrans_count", retransCount,
		"srtt_us", srttUs,
	)
}

func retransmitIntToIPv4(n uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return net.IP(b).String()
}
