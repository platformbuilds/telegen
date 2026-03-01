// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package gotracer

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type BpfOffTableT struct {
	Table [74]uint64
}

type BpfConnectionInfoT struct{}
type BpfEgressKeyT struct{}
type BpfFramerFuncInvocationT struct{}
type BpfGoAddrKeyT struct{}
type BpfGoroutineMetadata struct{}
type BpfGrpcClientFuncInvocationT struct{}
type BpfGrpcFramerFuncInvocationT struct{}
type BpfGrpcSrvFuncInvocationT struct{}
type BpfGrpcTransportsT struct{}
type BpfHttpClientDataT struct{}
type BpfHttpFuncInvocationT struct{}
type BpfKafkaClientReqT struct{}
type BpfKafkaGoReqT struct{}
type BpfMongoGoClientReqT struct{}
type BpfNewFuncInvocationT struct{}
type BpfOtelSpanT struct{}
type BpfProduceReqT struct{}
type BpfRedisClientReqT struct{}
type BpfServerHttpFuncInvocationT struct{}

type BpfObjects struct {
	BpfMaps
	BpfPrograms
}

type BpfMaps struct {
	GoTraceMap      *ebpf.Map
	OngoingHttpReq  *ebpf.Map
	GolangMapbucket *ebpf.Map
	Newproc1        *ebpf.Map
	GoOffsetsMap    *ebpf.Map
	Events          *ebpf.Map
}

type BpfPrograms struct {
	ObiUprobeClientConnClose                      *ebpf.Program
	ObiUprobeClientConnInvoke                     *ebpf.Program
	ObiUprobeClientConnInvokeReturn               *ebpf.Program
	ObiUprobeClientConnNewStream                  *ebpf.Program
	ObiUprobeClientConnNewStreamReturn            *ebpf.Program
	ObiUprobeClientRoundTrip                      *ebpf.Program
	ObiUprobeClientStreamRecvMsgReturn            *ebpf.Program
	ObiUprobeConnServe                            *ebpf.Program
	ObiUprobeConnServeRet                         *ebpf.Program
	ObiUprobeExecDC                               *ebpf.Program
	ObiUprobeFindHandlerRet                       *ebpf.Program
	ObiUprobeGinGetValueRet                       *ebpf.Program
	ObiUprobeGolangHttp2FramerWriteHeaders        *ebpf.Program
	ObiUprobeGrpcFramerWriteHeaders               *ebpf.Program
	ObiUprobeGrpcFramerWriteHeadersReturns        *ebpf.Program
	ObiUprobeHttp2FramerWriteHeadersReturns       *ebpf.Program
	ObiUprobeHttp2ResponseWriterStateWriteHeader  *ebpf.Program
	ObiUprobeHttp2RoundTrip                       *ebpf.Program
	ObiUprobeHttp2ServerOperateHeaders            *ebpf.Program
	ObiUprobeHttp2ServerProcessHeaders            *ebpf.Program
	ObiUprobeHttp2WriteHeaders                    *ebpf.Program
	ObiUprobeHttp2WriteHeadersVendored            *ebpf.Program
	ObiUprobeHttp2serverConnRunHandler            *ebpf.Program
	ObiUprobeJsonrpcReadRequestHeader             *ebpf.Program
	ObiUprobeJsonrpcReadRequestHeaderReturns      *ebpf.Program
	ObiUprobeMongoOpAggregate                     *ebpf.Program
	ObiUprobeMongoOpCountDocuments                *ebpf.Program
	ObiUprobeMongoOpDelete                        *ebpf.Program
	ObiUprobeMongoOpDistinct                      *ebpf.Program
	ObiUprobeMongoOpDrop                          *ebpf.Program
	ObiUprobeMongoOpEstimatedDocumentCount        *ebpf.Program
	ObiUprobeMongoOpExecute                       *ebpf.Program
	ObiUprobeMongoOpExecuteRet                    *ebpf.Program
	ObiUprobeMongoOpFind                          *ebpf.Program
	ObiUprobeMongoOpFindAndModify                 *ebpf.Program
	ObiUprobeMongoOpInsert                        *ebpf.Program
	ObiUprobeMongoOpUpdateOrReplace               *ebpf.Program
	ObiUprobeMuxSetMatch                          *ebpf.Program
	ObiUprobeNetFdRead                            *ebpf.Program
	ObiUprobeNetHttp2FramerWriteHeaders           *ebpf.Program
	ObiUprobeNonRecordingSpanEnd                  *ebpf.Program
	ObiUprobePersistConnRoundTrip                 *ebpf.Program
	ObiUprobePgxExec                              *ebpf.Program
	ObiUprobePgxQuery                             *ebpf.Program
	ObiUprobePgxQueryReturn                       *ebpf.Program
	ObiUprobePqNetworkReturn                      *ebpf.Program
	ObiUprobeProcGoexit1                          *ebpf.Program
	ObiUprobeProcNewproc1                         *ebpf.Program
	ObiUprobeProcNewproc1Ret                      *ebpf.Program
	ObiUprobeProtocolRoundtrip                    *ebpf.Program
	ObiUprobeProtocolRoundtripRet                 *ebpf.Program
	ObiUprobeQueryDC                              *ebpf.Program
	ObiUprobeQueryReturn                          *ebpf.Program
	ObiUprobeReadContinuedLineSliceReturns        *ebpf.Program
	ObiUprobeReadRequestReturns                   *ebpf.Program
	ObiUprobeReadRequestStart                     *ebpf.Program
	ObiUprobeReaderRead                           *ebpf.Program
	ObiUprobeReaderReadRet                        *ebpf.Program
	ObiUprobeReaderSendMessage                    *ebpf.Program
	ObiUprobeRecordError                          *ebpf.Program
	ObiUprobeRedisProcess                         *ebpf.Program
	ObiUprobeRedisProcessRet                      *ebpf.Program
	ObiUprobeRedisWithWriter                      *ebpf.Program
	ObiUprobeRedisWithWriterRet                   *ebpf.Program
	ObiUprobeRoundTrip                            *ebpf.Program
	ObiUprobeRoundTripReturn                      *ebpf.Program
	ObiUprobeSaramaBrokerWrite                    *ebpf.Program
	ObiUprobeSaramaResponsePromiseHandle          *ebpf.Program
	ObiUprobeSaramaSendInternal                   *ebpf.Program
	ObiUprobeServeHTTP                            *ebpf.Program
	ObiUprobeServeHTTPReturns                     *ebpf.Program
	ObiUprobeServerHandleStream                   *ebpf.Program
	ObiUprobeServerHandleStreamReturn             *ebpf.Program
	ObiUprobeServerHandlerTransportHandleStreams  *ebpf.Program
	ObiUprobeSetAttributes                        *ebpf.Program
	ObiUprobeSetName                              *ebpf.Program
	ObiUprobeSetStatus                            *ebpf.Program
	ObiUprobeTracerStart                          *ebpf.Program
	ObiUprobeTracerStartGlobal                    *ebpf.Program
	ObiUprobeTracerStartReturns                   *ebpf.Program
	ObiUprobeTransportHttp2ClientNewStream        *ebpf.Program
	ObiUprobeTransportHttp2ClientNewStreamReturns *ebpf.Program
	ObiUprobeTransportWriteStatus                 *ebpf.Program
	ObiUprobeWriteSubset                          *ebpf.Program
	ObiUprobeWriterProduce                        *ebpf.Program
	ObiUprobeWriterWriteMessages                  *ebpf.Program
}

func (o *BpfObjects) Close() error { return nil }

func LoadBpf() (*ebpf.CollectionSpec, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF not supported on this platform")
}
