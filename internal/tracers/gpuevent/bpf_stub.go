// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package gpuevent

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type BpfPidInfo struct {
	HostPid uint32
	UserPid uint32
	Ns      uint32
}

type BpfGpuKernelLaunchT struct {
	Flags       uint8
	Pad         [3]uint8
	PidInfo     BpfPidInfo
	KernFuncOff uint64
	GridX       int32
	GridY       int32
	GridZ       int32
	BlockX      int32
	BlockY      int32
	BlockZ      int32
	Stream      uint64
	Args        [16]uint64
	UstackSz    uint64
	Ustack      [128]uint64
}

type BpfGpuMallocT struct {
	Flags   uint8
	Pad     [3]uint8
	PidInfo BpfPidInfo
	Size    int64
}

type BpfGpuMemcpyT struct {
	Flags   uint8
	Kind    uint8
	Pad     [2]uint8
	PidInfo BpfPidInfo
	Size    int64
}

type BpfObjects struct {
	BpfMaps
	BpfPrograms
}

type BpfMaps struct {
	DebugEvents *ebpf.Map
	PidCache    *ebpf.Map
	Rb          *ebpf.Map
	ValidPids   *ebpf.Map
}

type BpfPrograms struct {
	HandleCudaLaunch *ebpf.Program
	HandleCudaMalloc *ebpf.Program
	HandleCudaMemcpy *ebpf.Program
}

func (o *BpfObjects) Close() error { return nil }

func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF not supported on this platform")
}
