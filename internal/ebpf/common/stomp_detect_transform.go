// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"errors"
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/stompparser"
)

// isSTOMP returns true if the buffer looks like STOMP protocol data.
func isSTOMP(buf []byte) bool {
	return stompparser.IsSTOMP(buf)
}

func ProcessPossibleSTOMPEvent(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	reqFrames, _, reqErr := stompparser.ParseFrames(reqBuf)
	respFrames, _, respErr := stompparser.ParseFrames(respBuf)

	if reqErr != nil && respErr != nil {
		if errors.Is(reqErr, stompparser.ErrNeedsMoreData) || errors.Is(respErr, stompparser.ErrNeedsMoreData) {
			return request.Span{}, ParseNeedsMore, errors.New("stomp: needs more data")
		}
		return request.Span{}, ParseInvalid, errors.New("stomp: could not parse either direction")
	}

	if len(reqFrames) == 0 && len(respFrames) == 0 {
		if errors.Is(reqErr, stompparser.ErrNeedsMoreData) || errors.Is(respErr, stompparser.ErrNeedsMoreData) {
			return request.Span{}, ParseNeedsMore, nil
		}
		return request.Span{}, ParseIgnored, nil
	}

	for _, frame := range reqFrames {
		if span, ok := spanFromSTOMPFrame(event, frame, amqpSourceRequest); ok {
			return span, ParseSuccess, nil
		}
	}
	for _, frame := range respFrames {
		if span, ok := spanFromSTOMPFrame(event, frame, amqpSourceResponse); ok {
			return span, ParseSuccess, nil
		}
	}

	return request.Span{}, ParseIgnored, nil
}

func spanFromSTOMPFrame(trace *TCPRequestInfo, frame stompparser.Frame, source amqpFrameSource) (request.Span, bool) {
	opType, opName, ok := stompOperation(frame.Command, source)
	if !ok {
		return request.Span{}, false
	}

	traceForSpan := *trace
	if source == amqpSourceResponse {
		reverseTCPEvent(&traceForSpan)
	}

	spanType := request.EventTypeSTOMPClient
	if traceForSpan.Direction == directionRecv {
		spanType = request.EventTypeSTOMPServer
	}

	destination := frame.Headers["destination"]
	if destination == "" {
		destination = frame.Headers["subscription"]
	}

	return TCPToSTOMPToSpan(&traceForSpan, spanType, opType, opName, destination), true
}

func stompOperation(command string, source amqpFrameSource) (string, string, bool) {
	switch command {
	case "SEND":
		if source == amqpSourceResponse {
			return request.MessagingReceive, "stomp.send", true
		}
		return request.MessagingPublish, "stomp.send", true
	case "MESSAGE":
		return request.MessagingReceive, "stomp.message", true
	case "ACK":
		return request.MessagingSettle, "stomp.ack", true
	case "NACK":
		return request.MessagingSettle, "stomp.nack", true
	case "SUBSCRIBE":
		return request.MessagingCreate, "stomp.subscribe", true
	case "UNSUBSCRIBE":
		return request.MessagingCreate, "stomp.unsubscribe", true
	case "CONNECT":
		return request.MessagingCreate, "stomp.connect", true
	case "STOMP":
		return request.MessagingCreate, "stomp.stomp", true
	case "CONNECTED":
		return request.MessagingCreate, "stomp.connected", true
	case "DISCONNECT":
		return request.MessagingCreate, "stomp.disconnect", true
	case "BEGIN":
		return request.MessagingCreate, "stomp.begin", true
	case "COMMIT":
		return request.MessagingCreate, "stomp.commit", true
	case "ABORT":
		return request.MessagingCreate, "stomp.abort", true
	case "RECEIPT":
		return request.MessagingProcess, "stomp.receipt", true
	case "ERROR":
		return request.MessagingProcess, "stomp.error", true
	default:
		return "", "", false
	}
}

func TCPToSTOMPToSpan(
	trace *TCPRequestInfo,
	spanType request.EventType,
	opType string,
	opName string,
	destination string,
) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:          spanType,
		Method:        opType,
		Path:          destination,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		MessagingInfo: &request.MessagingInfo{OperationName: opName},
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}
