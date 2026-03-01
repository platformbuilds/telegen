// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package tpinjector

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type BpfCallProtocolArgsT struct{}
type BpfConnectionInfoPartT struct{}
type BpfConnectionInfoT struct{}
type BpfCpSupportDataT struct{}
type BpfEgressKeyT struct{}
type BpfFdInfoT struct{}
type BpfFdKey struct{}
type BpfGrpcFramesCtxT struct{}
type BpfHttp2ConnInfoDataT struct{}
type BpfHttp2ConnStreamT struct{}
type BpfHttp2GrpcRequestT struct{}
type BpfHttpConnectionMetadataT struct{}
type BpfHttpInfoT struct{}
type BpfKafkaCorrelationDataT struct{}
type BpfKafkaStateDataT struct{}
type BpfKafkaStateKeyT struct{}
type BpfMsgBufferT struct{}
type BpfMysqlStateData struct{}
type BpfPidConnectionInfoT struct{}
type BpfPidKeyT struct{}
type BpfPumaTaskIdT struct{}
type BpfRecvArgsT struct{}
type BpfSendArgsT struct{}
type BpfSockArgsT struct{}
type BpfSslArgsT struct{}
type BpfTpInfoPidT struct{}
type BpfTraceKeyT struct{}
type BpfTraceMapKeyT struct{}

type BpfObjects struct {
	BpfMaps
	BpfPrograms
}

type BpfMaps struct {
	ActiveSslReadArgs   *ebpf.Map
	ActiveSslWriteArgs  *ebpf.Map
	ActiveSslHandshakes *ebpf.Map
	SslToConn           *ebpf.Map
	SslToPidTid         *ebpf.Map
	OngoingHttp         *ebpf.Map
	OngoingHttp2Grpc    *ebpf.Map
	Http2InfoMem        *ebpf.Map
	OngoingHttpFallback *ebpf.Map
	TraceMap            *ebpf.Map
	JumpTable           *ebpf.Map
	Events              *ebpf.Map
	OngoingKafkaReq     *ebpf.Map
}
type BpfPrograms struct{}

func (o *BpfObjects) Close() error { return nil }

func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF not supported on this platform")
}
