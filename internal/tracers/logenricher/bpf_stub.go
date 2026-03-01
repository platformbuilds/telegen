// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package logenricher

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type BpfConnectionInfoPartT struct{}
type BpfConnectionInfoT struct{}
type BpfCpSupportDataT struct{}
type BpfEgressKeyT struct{}
type BpfFdInfoT struct{}
type BpfFdKey struct{}
type BpfLogEventT struct{}
type BpfPidConnectionInfoT struct{}
type BpfPidKeyT struct{}
type BpfPumaTaskIdT struct{}
type BpfTpInfoPidT struct{}
type BpfTraceKeyT struct{}
type BpfTraceMapKeyT struct{}

type BpfObjects struct {
	BpfMaps
	BpfPrograms
}

type BpfMaps struct{}
type BpfPrograms struct{}

func (o *BpfObjects) Close() error { return nil }

func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF not supported on this platform")
}
