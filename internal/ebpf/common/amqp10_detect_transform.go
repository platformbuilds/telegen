// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"errors"
	"unsafe"

	lru "github.com/hashicorp/golang-lru/v2/simplelru"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/amqp10parser"
)

type amqp10LinkKey struct {
	Conn    BpfConnectionInfoT
	Channel uint16
	Handle  uint32
	Role    bool
}

// isAMQP1 returns true if the buffer looks like AMQP 1.0 traffic.
func isAMQP1(buf []byte) bool {
	return amqp10parser.IsAMQP1(buf)
}

func ProcessPossibleAMQP10Event(
	event *TCPRequestInfo,
	reqBuf, respBuf []byte,
	linkCache *lru.LRU[amqp10LinkKey, string],
) (request.Span, ParseOutcome, error) {
	reqFrames, _, reqErr := amqp10parser.ParseFrames(reqBuf)
	respFrames, _, respErr := amqp10parser.ParseFrames(respBuf)

	if reqErr != nil && respErr != nil {
		if errors.Is(reqErr, amqp10parser.ErrNeedsMoreData) || errors.Is(respErr, amqp10parser.ErrNeedsMoreData) {
			return request.Span{}, ParseNeedsMore, errors.New("amqp1: needs more data")
		}
		return request.Span{}, ParseInvalid, errors.New("amqp1: could not parse either direction")
	}

	if len(reqFrames) == 0 && len(respFrames) == 0 {
		if errors.Is(reqErr, amqp10parser.ErrNeedsMoreData) || errors.Is(respErr, amqp10parser.ErrNeedsMoreData) {
			return request.Span{}, ParseNeedsMore, nil
		}
		return request.Span{}, ParseIgnored, nil
	}

	for _, frame := range reqFrames {
		if span, ok := spanFromAMQP10Frame(event, frame, amqpSourceRequest, linkCache); ok {
			return span, ParseSuccess, nil
		}
	}
	for _, frame := range respFrames {
		if span, ok := spanFromAMQP10Frame(event, frame, amqpSourceResponse, linkCache); ok {
			return span, ParseSuccess, nil
		}
	}

	return request.Span{}, ParseIgnored, nil
}

func spanFromAMQP10Frame(
	trace *TCPRequestInfo,
	frame amqp10parser.Frame,
	source amqpFrameSource,
	linkCache *lru.LRU[amqp10LinkKey, string],
) (request.Span, bool) {
	opType, rawName, ok := amqp10Operation(frame.Performative, source)
	if !ok {
		return request.Span{}, false
	}

	traceForSpan := *trace
	if source == amqpSourceResponse {
		reverseTCPEvent(&traceForSpan)
	}

	spanType := request.EventTypeAMQPClient
	if traceForSpan.Direction == directionRecv {
		spanType = request.EventTypeAMQPServer
	}

	role := spanType == request.EventTypeAMQPServer
	if frame.HasRole {
		role = frame.Role
	}

	destination := frame.Address
	if frame.Performative == amqp10parser.PerformativeAttach && frame.HasHandle && destination != "" {
		rememberAMQP10Address(linkCache, &traceForSpan, frame.Channel, frame.Handle, role, destination)
	} else if frame.HasHandle && destination == "" {
		destination = lookupAMQP10Address(linkCache, &traceForSpan, frame.Channel, frame.Handle, role)
		if destination == "" {
			destination = lookupAMQP10Address(linkCache, &traceForSpan, frame.Channel, frame.Handle, !role)
		}
	}

	return TCPToAMQP10ToSpan(&traceForSpan, opType, rawName, destination, spanType), true
}

func amqp10Operation(performative amqp10parser.PerformativeType, source amqpFrameSource) (string, string, bool) {
	switch performative {
	case amqp10parser.PerformativeAttach:
		return request.MessagingCreate, "amqp1.attach", true
	case amqp10parser.PerformativeTransfer:
		if source == amqpSourceRequest {
			return request.MessagingPublish, "amqp1.transfer", true
		}
		return request.MessagingReceive, "amqp1.transfer", true
	case amqp10parser.PerformativeDisposition:
		return request.MessagingSettle, "amqp1.disposition", true
	case amqp10parser.PerformativeFlow:
		return request.MessagingReceive, "amqp1.flow", true
	case amqp10parser.PerformativeDetach:
		return request.MessagingSettle, "amqp1.detach", true
	default:
		return "", "", false
	}
}

func TCPToAMQP10ToSpan(
	trace *TCPRequestInfo,
	opType string,
	rawName string,
	destination string,
	spanType request.EventType,
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
		MessagingInfo: &request.MessagingInfo{OperationName: rawName},
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

func rememberAMQP10Address(
	cache *lru.LRU[amqp10LinkKey, string],
	trace *TCPRequestInfo,
	channel uint16,
	handle uint32,
	role bool,
	destination string,
) {
	if cache == nil || channel == 0 || handle == 0 || destination == "" {
		return
	}
	cache.Add(amqp10AddressKey(trace, channel, handle, role), destination)
}

func lookupAMQP10Address(
	cache *lru.LRU[amqp10LinkKey, string],
	trace *TCPRequestInfo,
	channel uint16,
	handle uint32,
	role bool,
) string {
	if cache == nil || channel == 0 || handle == 0 {
		return ""
	}
	if destination, ok := cache.Get(amqp10AddressKey(trace, channel, handle, role)); ok {
		return destination
	}
	return ""
}

func amqp10AddressKey(trace *TCPRequestInfo, channel uint16, handle uint32, role bool) amqp10LinkKey {
	return amqp10LinkKey{
		Conn:    normalizeAMQPConn(trace.ConnInfo),
		Channel: channel,
		Handle:  handle,
		Role:    role,
	}
}
