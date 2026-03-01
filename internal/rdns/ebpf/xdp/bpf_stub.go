// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file provides stub types for the XDP BPF generated code.
// These stubs allow the code to compile on non-linux platforms (darwin, windows).

package xdp // import "github.com/platformbuilds/telegen/internal/rdns/ebpf/xdp"

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// BpfSpecs - specs stub
type BpfSpecs struct {
	Programs BpfProgramSpecs
	Maps     BpfMapSpecs
}

// BpfProgramSpecs - program specs stub
type BpfProgramSpecs struct {
	DnsResponseTracker *ebpf.ProgramSpec `ebpf:"dns_response_tracker"`
}

// BpfMapSpecs - map specs stub
type BpfMapSpecs struct {
	RingBuffer *ebpf.MapSpec `ebpf:"ring_buffer"`
}

// BpfVariableSpecs - variable specs stub
type BpfVariableSpecs struct{}

// BpfObjects - objects stub
type BpfObjects struct {
	BpfPrograms
	BpfMaps
}

// BpfPrograms - programs stub
type BpfPrograms struct {
	DnsResponseTracker *ebpf.Program `ebpf:"dns_response_tracker"`
}

// BpfMaps - maps stub
type BpfMaps struct {
	RingBuffer *ebpf.Map `ebpf:"ring_buffer"`
}

// BpfVariables - variables stub
type BpfVariables struct{}

// Close - stub close method
func (o *BpfObjects) Close() error { return nil }

// Close - stub close for maps
func (m *BpfMaps) Close() error { return nil }

// Close - stub close for programs
func (p *BpfPrograms) Close() error { return nil }

// LoadBpf - stub loader
func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("BPF not available on this platform")
}

// LoadBpfObjects - stub object loader
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("BPF not available on this platform")
}
