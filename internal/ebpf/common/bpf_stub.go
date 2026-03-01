// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file provides stub types for the BPF generated code.
// These stubs allow the code to compile on non-linux platforms (darwin, windows).
// The actual generated files are:
//   - bpf_x86_bpfel.go (linux/amd64)
//   - bpf_arm64_bpfel.go (linux/arm64)

package ebpfcommon

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// BPF type stubs for non-linux builds

// TpInfo - tracepoint info embedded struct
type TpInfo struct {
	TraceId  [16]uint8
	SpanId   [8]uint8
	ParentId [8]uint8
	Ts       uint64
	Flags    uint8
	Pad      [7]uint8
}

// PidInfo - process ID info embedded struct
type PidInfo struct {
	HostPid uint32
	UserPid uint32
	Ns      uint32
}

// SpanNameInfo - span name info embedded struct
type SpanNameInfo struct {
	Buf [64]uint8
}

// SpanAttrInfo - span attribute info
type SpanAttrInfo struct {
	ValLength uint16
	Vtype     uint8
	Reserved  uint8
	Key       [32]uint8
	Value     [128]uint8
}

// SpanAttrsInfo - span attributes collection
type SpanAttrsInfo struct {
	Attrs      [16]SpanAttrInfo
	ValidAttrs uint8
	Apad       uint8
}

// BpfConnectionInfoT - connection info stub
type BpfConnectionInfoT struct {
	S_addr [16]uint8
	D_addr [16]uint8
	S_port uint16
	D_port uint16
}

// BpfDnsReqT - DNS request stub
type BpfDnsReqT struct {
	Flags uint8
	DnsQ  uint8
	Pad1  [2]uint8
	Len   uint32
	Conn  BpfConnectionInfoT
	Id    uint16
	Pad2  [2]uint8
	Tp    TpInfo
	Pid   PidInfo
	Buf   [512]uint8
	Pad3  [4]uint8
}

// BpfHttp2GrpcRequestT - HTTP2/gRPC request stub
type BpfHttp2GrpcRequestT struct {
	Flags           uint8
	Ssl             uint8
	Type            uint8
	Pad0            [1]uint8
	ConnInfo        BpfConnectionInfoT
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Data            [256]uint8
	RetData         [64]uint8
	Len             int32
	Pid             PidInfo
	NewConnId       uint64
	Tp              TpInfo
}

// BpfHttpInfoT - HTTP info stub
type BpfHttpInfoT struct {
	Flags           uint8
	Type            uint8
	Ssl             uint8
	Delayed         uint8
	ConnInfo        BpfConnectionInfoT
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	ReqMonotimeNs   uint64
	ExtraId         uint64
	Tp              TpInfo
	Pid             PidInfo
	Len             uint32
	RespLen         uint32
	TaskTid         uint32
	Status          uint16
	Buf             [256]uint8
	HasLargeBuffers uint8
	Direction       uint8
	Submitted       uint8
	Pad             [3]uint8
}

// BpfHttpRequestTraceT - HTTP request trace stub
type BpfHttpRequestTraceT struct {
	Type              uint8
	Pad0              [1]uint8
	Status            uint16
	Method            [7]uint8
	Scheme            [10]uint8
	Pad1              [11]uint8
	GoStartMonotimeNs uint64
	StartMonotimeNs   uint64
	EndMonotimeNs     uint64
	ContentLength     int64
	ResponseLength    int64
	Path              [100]uint8
	Pattern           [96]uint8
	Host              [100]uint8
	Tp                TpInfo
	Conn              BpfConnectionInfoT
	Pid               PidInfo
}

// BpfKafkaClientReqT - Kafka client request stub
type BpfKafkaClientReqT struct {
	Type            uint8
	Pad             [7]uint8
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Buf             [256]uint8
	Conn            BpfConnectionInfoT
	Pid             PidInfo
}

// BpfKafkaGoReqT - Kafka-Go request stub
type BpfKafkaGoReqT struct {
	Type            uint8
	Op              uint8
	Pad0            [2]uint8
	Pid             PidInfo
	Conn            BpfConnectionInfoT
	Pad1            [4]uint8
	Tp              TpInfo
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Topic           [64]uint8
}

// BpfMongoGoClientReqT - MongoDB client request stub
type BpfMongoGoClientReqT struct {
	Type            uint8
	Err             uint8
	Pad             [6]uint8
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Pid             PidInfo
	Op              [32]uint8
	Db              [32]uint8
	Coll            [32]uint8
	Conn            BpfConnectionInfoT
	Tp              TpInfo
}

// BpfOtelSpanT - OTel span stub
type BpfOtelSpanT struct {
	Type            uint8
	Pad             [7]uint8
	StartTime       uint64
	EndTime         uint64
	ParentGo        uint64
	Tp              TpInfo
	PrevTp          TpInfo
	Status          uint32
	SpanName        SpanNameInfo
	SpanDescription SpanNameInfo
	Pid             PidInfo
	SpanAttrs       SpanAttrsInfo
	Epad            [6]uint8
}

// BpfRedisClientReqT - Redis client request stub
type BpfRedisClientReqT struct {
	Type            uint8
	Err             uint8
	Pad             [6]uint8
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Pid             PidInfo
	Buf             [256]uint8
	Conn            BpfConnectionInfoT
	Tp              TpInfo
}

// BpfSqlRequestTraceT - SQL request trace stub
type BpfSqlRequestTraceT struct {
	Type            uint8
	Pad             [1]uint8
	Status          uint16
	Pid             PidInfo
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Tp              TpInfo
	Conn            BpfConnectionInfoT
	Sql             [500]uint8
	Hostname        [96]uint8
}

// BpfTcpLargeBufferT - TCP large buffer stub
type BpfTcpLargeBufferT struct {
	Type       uint8
	PacketType uint8
	Action     uint8
	Direction  uint8
	Len        uint32
	ConnInfo   BpfConnectionInfoT
	Pad2       uint32
	Tp         TpInfo
	Buf        [0]uint8
}

// BpfTcpReqT - TCP request stub
type BpfTcpReqT struct {
	Flags           uint8
	Ssl             uint8
	Direction       uint8
	HasLargeBuffers uint8
	ProtocolType    uint8
	IsServer        bool
	Pad1            [2]uint8
	ConnInfo        BpfConnectionInfoT
	Len             uint32
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	ExtraId         uint64
	ReqLen          uint32
	RespLen         uint32
	Pad2            [4]uint8
	Buf             [256]uint8
	Rbuf            [128]uint8
	Pid             PidInfo
	Tp              TpInfo
}

// BpfSpecs - specs stub
type BpfSpecs struct {
	Programs BpfProgramSpecs
	Maps     BpfMapSpecs
}

// BpfProgramSpecs - program specs stub
type BpfProgramSpecs struct{}

// BpfMapSpecs - map specs stub
type BpfMapSpecs struct{}

// BpfVariableSpecs - variable specs stub
type BpfVariableSpecs struct{}

// BpfObjects - objects stub
type BpfObjects struct {
	BpfPrograms
	BpfMaps
}

// BpfPrograms - programs stub
type BpfPrograms struct{}

// BpfMaps - maps stub
type BpfMaps struct{}

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

// Ensure bytes is used
var _ = bytes.Buffer{}
