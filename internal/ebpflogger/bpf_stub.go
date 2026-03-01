// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package logger // import "github.com/platformbuilds/telegen/internal/ebpflogger"

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type BpfLogInfoT struct {
	Pid  uint64
	Log  [80]uint8
	Comm [20]uint8
	Pad  [4]uint8
}

type BpfObjects struct {
	BpfMaps
	BpfPrograms
}

type BpfMaps struct {
	DebugEvents *ebpf.Map
}
type BpfPrograms struct{}

func (o *BpfObjects) Close() error { return nil }

func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF not supported on this platform")
}
