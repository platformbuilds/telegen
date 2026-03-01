// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "github.com/mirastacklabs-ai/telegen/internal/netollyebpf"

import (
	"github.com/mirastacklabs-ai/telegen/internal/ebpf/tcmanager"
	"github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
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
