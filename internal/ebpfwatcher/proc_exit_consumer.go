// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// ProcExitConsumer reads proc_exit_events from bpf/watcher/watcher.c and emits
// an OTel counter for process exit events, differentiating clean exits from
// crash exits (non-zero signal).
//
// Ported from Pixie's proc_exit connector
// (src/stirling/source_connectors/proc_exit/).
package watcher // import "github.com/mirastacklabs-ai/telegen/internal/ebpfwatcher"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/cilium/ebpf"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
)

// procExitEventSize mirrors the exact byte layout of proc_exit_event_t from
// bpf/watcher/watcher.c:
//
//	timestamp(8) pid(4) tid(4) exit_code(4) signal_num(4) comm(16)
//
// Total = 40 bytes.
const procExitEventSize = 8 + 4 + 4 + 4 + 4 + 16

// ProcExitEvent is the Go-side representation of a process exit event.
type ProcExitEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	ExitCode  uint32
	SignalNum uint32
	Comm      string
}

// ProcExitConsumer reads proc_exit_events from the BPF ring buffer and
// emits OTel counters for process exits and crashes.
//
// It distinguishes:
//   - Clean exits  (signal == 0): telegen.process.exit{exit_type="clean"}
//   - Crash exits  (signal != 0): telegen.process.exit{exit_type="crash", signal=<num>}
type ProcExitConsumer struct {
	reader *ringbuf.Reader
	log    *slog.Logger

	exitCounter  metric.Int64Counter
	crashCounter metric.Int64Counter

	// Optional callback for callers that want to act on each event (e.g. drain
	// detection, connection cleanup).
	OnExit func(ev ProcExitEvent)
}

// NewProcExitConsumer creates a ProcExitConsumer attached to the provided
// proc_exit_events ring-buffer map.
func NewProcExitConsumer(
	procExitMap *ebpf.Map,
	meterProvider metric.MeterProvider,
	log *slog.Logger,
) (*ProcExitConsumer, error) {
	if procExitMap == nil {
		return nil, errors.New("proc_exit_events map is nil")
	}

	rd, err := ringbuf.NewReader(procExitMap)
	if err != nil {
		return nil, fmt.Errorf("creating proc_exit ring buffer reader: %w", err)
	}

	meter := meterProvider.Meter("telegen.proc_lifecycle")

	exits, err := meter.Int64Counter(
		"telegen.process.exits",
		metric.WithDescription("Total process exit events observed by Telegen"),
		metric.WithUnit("{exit}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating process exits counter: %w", err)
	}

	crashes, err := meter.Int64Counter(
		"telegen.process.crashes",
		metric.WithDescription("Process exits caused by a signal (crashes, OOM kills, SIGKILL)"),
		metric.WithUnit("{crash}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating process crashes counter: %w", err)
	}

	return &ProcExitConsumer{
		reader:       rd,
		log:          log.With("component", "proc_exit_consumer"),
		exitCounter:  exits,
		crashCounter: crashes,
	}, nil
}

// Run reads proc_exit_events until ctx is cancelled.
// Call this in a dedicated goroutine.
func (c *ProcExitConsumer) Run(ctx context.Context) {
	c.log.Debug("starting proc_exit consumer")
	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.log.Debug("proc_exit ring buffer closed — stopping")
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			c.log.Warn("proc_exit ring buffer read error", "error", err)
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
func (c *ProcExitConsumer) Close() error {
	return c.reader.Close()
}

// handleEvent parses one proc_exit_event_t and records OTel metrics.
//
// Layout (little-endian):
//
//	[0:8]   timestamp
//	[8:12]  pid
//	[12:16] tid
//	[16:20] exit_code
//	[20:24] signal_num
//	[24:40] comm (16 bytes, NUL-terminated)
func (c *ProcExitConsumer) handleEvent(ctx context.Context, raw []byte) {
	if len(raw) < procExitEventSize {
		c.log.Warn("proc_exit_event too small", "size", len(raw), "expected", procExitEventSize)
		return
	}

	timestamp := binary.LittleEndian.Uint64(raw[0:8])
	pid := binary.LittleEndian.Uint32(raw[8:12])
	exitCode := binary.LittleEndian.Uint32(raw[16:20])
	signalNum := binary.LittleEndian.Uint32(raw[20:24])
	comm := cStringToGo(raw[24:40])

	ev := ProcExitEvent{
		Timestamp: timestamp,
		PID:       pid,
		TID:       binary.LittleEndian.Uint32(raw[12:16]),
		ExitCode:  exitCode,
		SignalNum: signalNum,
		Comm:      comm,
	}

	commAttr := attribute.String("process.executable.name", comm)
	exitCodeAttr := attribute.Int("process.exit_code", int(exitCode))

	c.exitCounter.Add(ctx, 1, metric.WithAttributes(commAttr, exitCodeAttr))

	if signalNum != 0 {
		// Non-zero signal means the process was killed — could be a crash (SIGSEGV/SIGABRT),
		// an OOM kill (SIGKILL from the kernel), or an operator-initiated termination.
		signalAttr := attribute.Int("process.signal", int(signalNum))
		c.crashCounter.Add(ctx, 1, metric.WithAttributes(commAttr, signalAttr))

		c.log.Info("process crash detected",
			"pid", pid,
			"comm", comm,
			"signal", signalNum,
		)
	} else {
		c.log.Debug("process clean exit",
			"pid", pid,
			"comm", comm,
			"exit_code", exitCode,
		)
	}

	if c.OnExit != nil {
		c.OnExit(ev)
	}
}

// cStringToGo converts a fixed-size NUL-terminated C string byte slice to a Go string.
func cStringToGo(b []byte) string {
	for i, ch := range b {
		if ch == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
