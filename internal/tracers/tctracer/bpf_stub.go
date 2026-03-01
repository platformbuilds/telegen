// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package tctracer

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type BpfConnectionInfoT struct{}
type BpfEgressKeyT struct{}
type BpfGoAddrKeyT struct{}
type BpfHttpFuncInvocationT struct{}
type BpfHttpInfoT struct{}
type BpfPidConnectionInfoT struct{}
type BpfTpInfoPidT struct{}
type BpfTraceMapKeyT struct{}

type BpfObjects struct {
	BpfMaps
	BpfPrograms
}

type BpfMaps struct {
	IngressSkb *ebpf.Map
	EgressSkb  *ebpf.Map
}
type BpfPrograms struct {
	TcIngress *ebpf.Program
	TcEgress  *ebpf.Program
}

func (o *BpfObjects) Close() error { return nil }

func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF not supported on this platform")
}
