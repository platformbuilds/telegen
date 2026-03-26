// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package watcher // import "github.com/mirastacklabs-ai/telegen/internal/ebpfwatcher"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/metric"

	"github.com/cilium/ebpf"
)

// ProcExitEvent is the Go-side representation of a process exit event.
type ProcExitEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	ExitCode  uint32
	SignalNum uint32
	Comm      string
}

// ProcExitConsumer is a no-op stub on non-Linux platforms.
type ProcExitConsumer struct {
	OnExit func(ev ProcExitEvent)
}

func NewProcExitConsumer(
	_ *ebpf.Map,
	_ metric.MeterProvider,
	_ *slog.Logger,
) (*ProcExitConsumer, error) {
	return &ProcExitConsumer{}, nil
}

func (c *ProcExitConsumer) Run(_ context.Context) {}
func (c *ProcExitConsumer) Close() error          { return nil }
