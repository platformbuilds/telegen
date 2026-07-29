// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
)

const (
	goAMQP091OpPublish uint8 = iota
	goAMQP091OpProcess
	goAMQP091OpSettle
	goAMQP091OpCreate
)

const goAMQPClientStatement = "go-amqp-client"

func amqp091OperationName(op uint8) string {
	switch op {
	case goAMQP091OpPublish:
		return request.MessagingPublish
	case goAMQP091OpProcess:
		return request.MessagingProcess
	case goAMQP091OpSettle:
		return request.MessagingSettle
	case goAMQP091OpCreate:
		return request.MessagingCreate
	default:
		return "unknown"
	}
}

func ReadGoAMQP091RequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoAMQP091ClientInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	return GoAMQP091ToSpan(event), false, nil
}

func GoAMQP091ToSpan(event *GoAMQP091ClientInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	return request.Span{
		Type:          request.EventTypeAMQPClient,
		Method:        amqp091OperationName(event.Op),
		Statement:     goAMQPClientStatement,
		Path:          cstr(event.Topic[:]),
		Peer:          peer,
		PeerPort:      int(event.Conn.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(event.StartMonotimeNs),
		Start:         int64(event.StartMonotimeNs),
		End:           int64(event.EndMonotimeNs),
		TraceID:       trace2.TraceID(event.Tp.TraceId),
		SpanID:        trace2.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(event.Tp.ParentId),
		TraceFlags:    event.Tp.Flags,
		Status:        0,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}
}
