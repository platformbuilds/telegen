// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

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

// connCloseEvent mirrors the BPF struct conn_close_event from bpf/network/tcp_metrics.c.
// Fields must match the C layout exactly (little-endian, packed).
//
//nolint:unused
type connCloseEvent struct {
	Timestamp    uint64
	Saddr        uint32
	Daddr        uint32
	Sport        uint16
	Dport        uint16
	IPVersion    uint8
	Pad          [3]uint8
	BytesSent    uint64
	BytesRecv    uint64
	Pid          uint32
	Pad2         uint32
}

const connCloseEventSize = 8 + 4 + 4 + 2 + 2 + 1 + 3 + 8 + 8 + 4 + 4 // 48 bytes

// ConnStatsConsumer reads conn_close_events from the BPF ring buffer and emits
// per-connection byte-transfer counters as OTel Int64Counters.
//
// Ported from Pixie's ConnStats consumer in conn_tracker.cc.
// Pixie emits per-connection stats; we aggregate at the consumer level.
type ConnStatsConsumer struct {
	reader *ringbuf.Reader
	log    *slog.Logger

	bytesSentCounter metric.Int64Counter
	bytesRecvCounter metric.Int64Counter
}

// NewConnStatsConsumer creates and starts a ConnStatsConsumer attached to the
// provided conn_close_events ring buffer map.
func NewConnStatsConsumer(
	connCloseMap *ebpf.Map,
	meterProvider metric.MeterProvider,
	log *slog.Logger,
) (*ConnStatsConsumer, error) {
	if connCloseMap == nil {
		return nil, errors.New("conn_close_events map is nil")
	}

	rd, err := ringbuf.NewReader(connCloseMap)
	if err != nil {
		return nil, fmt.Errorf("creating conn_close ring buffer reader: %w", err)
	}

	meter := meterProvider.Meter("telegen.conn_stats")

	sent, err := meter.Int64Counter(
		"telegen.connection.bytes_sent",
		metric.WithDescription("Total bytes sent per TCP connection"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating bytes_sent counter: %w", err)
	}

	recv, err := meter.Int64Counter(
		"telegen.connection.bytes_received",
		metric.WithDescription("Total bytes received per TCP connection"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating bytes_received counter: %w", err)
	}

	return &ConnStatsConsumer{
		reader:           rd,
		log:              log.With("component", "conn_stats"),
		bytesSentCounter: sent,
		bytesRecvCounter: recv,
	}, nil
}

// Run reads conn_close_events until ctx is cancelled.
// Call this in a dedicated goroutine.
func (c *ConnStatsConsumer) Run(ctx context.Context) {
	c.log.Debug("starting conn_stats consumer")
	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.log.Debug("conn_stats ring buffer closed — stopping")
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			c.log.Warn("conn_stats ring buffer read error", "error", err)
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
func (c *ConnStatsConsumer) Close() error {
	return c.reader.Close()
}

func (c *ConnStatsConsumer) handleEvent(ctx context.Context, raw []byte) {
	if len(raw) < connCloseEventSize {
		c.log.Warn("conn_close_event too small", "size", len(raw), "expected", connCloseEventSize)
		return
	}

	// Parse fields in the exact layout order.
	// timestamp (8) + saddr (4) + daddr (4) + sport (2) + dport (2) +
	// ip_version (1) + pad (3) + bytes_sent (8) + bytes_recv (8) + pid (4) + pad2 (4)
	saddr := binary.LittleEndian.Uint32(raw[8:12])
	daddr := binary.LittleEndian.Uint32(raw[12:16])
	sport := binary.LittleEndian.Uint16(raw[16:18])
	dport := binary.LittleEndian.Uint16(raw[18:20])
	bytesSent := int64(binary.LittleEndian.Uint64(raw[24:32]))
	bytesRecv := int64(binary.LittleEndian.Uint64(raw[32:40]))

	srcIP := intToIPv4(saddr)
	dstIP := intToIPv4(daddr)

	attrs := []attribute.KeyValue{
		attribute.String("src.address", srcIP),
		attribute.String("dst.address", dstIP),
		attribute.Int("src.port", int(sport)),
		attribute.Int("dst.port", int(dport)),
	}

	c.bytesSentCounter.Add(ctx, bytesSent, metric.WithAttributes(attrs...))
	c.bytesRecvCounter.Add(ctx, bytesRecv, metric.WithAttributes(attrs...))

	c.log.Debug("conn_close: recorded byte counts",
		"src", fmt.Sprintf("%s:%d", srcIP, sport),
		"dst", fmt.Sprintf("%s:%d", dstIP, dport),
		"bytes_sent", bytesSent,
		"bytes_recv", bytesRecv,
	)
}

func intToIPv4(n uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return net.IP(b).String()
}
