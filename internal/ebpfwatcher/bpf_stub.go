// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package watcher

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type BpfWatchInfoT struct {
	Flags   uint64
	Payload uint64
}

type BpfObjects struct {
	BpfMaps
	BpfPrograms
}

type BpfMaps struct {
	DebugEvents  *ebpf.Map
	MsgBufferMem *ebpf.Map
	WatchEvents  *ebpf.Map
}

type BpfPrograms struct {
	ObiKprobeSysBind *ebpf.Program
}

func (o *BpfObjects) Close() error { return nil }

func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF not supported on this platform")
}
