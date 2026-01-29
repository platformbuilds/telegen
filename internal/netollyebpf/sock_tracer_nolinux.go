// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "github.com/platformbuilds/telegen/internal/netollyebpf"

import (
	"github.com/platformbuilds/telegen/internal/ringbuf"
)

type SockFlowFetcher struct{}

func (s *SockFlowFetcher) Close() error {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) LookupAndDeleteMap() map[NetFlowId][]NetFlowMetrics {
	panic("this is never going to be executed")
}

func (s *SockFlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	panic("this is never going to be executed")
}

func NewSockFlowFetcher(
	_, _ int,
) (*SockFlowFetcher, error) {
	// avoids linter complaining
	return nil, nil
}
