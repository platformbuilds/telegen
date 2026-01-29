// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "github.com/platformbuilds/telegen/internal/netollyebpf"

import (
	"github.com/platformbuilds/telegen/internal/obiconfig"
	"github.com/platformbuilds/telegen/internal/ringbuf"
	"github.com/platformbuilds/telegen/internal/ebpf/tcmanager"
)

type FlowFetcher struct{}

func NewFlowFetcher(
	_, _ int,
	_, _ bool,
	_ *tcmanager.InterfaceManager,
	_ config.TCBackend,
) (*FlowFetcher, error) {
	return nil, nil
}

func (m *FlowFetcher) Close() error {
	return nil
}

func (m *FlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return ringbuf.Record{}, nil
}

func (m *FlowFetcher) LookupAndDeleteMap() map[NetFlowId][]NetFlowMetrics {
	return nil
}
