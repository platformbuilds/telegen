// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"errors"
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/amqpparser"
)

// isAMQP returns true if the buffer looks like AMQP 0-9-1 data.
func isAMQP(buf []byte) bool {
	return amqpparser.IsAMQP(buf)
}

// ProcessPossibleAMQPEvent attempts to parse and stitch AMQP frames from a TCP event.
// Returns a span, the ParseOutcome, and any error.
func ProcessPossibleAMQPEvent(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	reqFrames, _, reqErr := amqpparser.ParseFrames(reqBuf)
	respFrames, _, respErr := amqpparser.ParseFrames(respBuf)

	// Both directions failed → not AMQP or too short
	if reqErr != nil && respErr != nil {
		if errors.Is(reqErr, amqpparser.ErrNeedsMoreData) || errors.Is(respErr, amqpparser.ErrNeedsMoreData) {
			return request.Span{}, ParseNeedsMore, errors.New("amqp: needs more data")
		}
		return request.Span{}, ParseInvalid, errors.New("amqp: could not parse either direction")
	}

	records := amqpparser.StitchFrames(reqFrames, respFrames)
	if len(records) == 0 {
		// Valid AMQP data but nothing span-worthy (e.g., heartbeat only)
		return request.Span{}, ParseIgnored, nil
	}

	// Use the first span-worthy record. Heartbeat-only connections are ignored.
	for _, rec := range records {
		// Pick the frame that has a method name (skip pure body/header frames as span name)
		var opFrame amqpparser.Frame
		if rec.Request.Type == amqpparser.FrameMethod {
			opFrame = rec.Request
		} else if rec.Response.Type == amqpparser.FrameMethod {
			opFrame = rec.Response
		} else {
			continue
		}
		if opFrame.Method.Class == 0 {
			continue // no class/method decoded
		}

		return TCPToAMQPToSpan(event, opFrame), ParseSuccess, nil
	}

	return request.Span{}, ParseIgnored, nil
}

// TCPToAMQPToSpan builds a request.Span from a TCP event and an AMQP method frame.
func TCPToAMQPToSpan(trace *TCPRequestInfo, frame amqpparser.Frame) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:         request.EventTypeAMQPClient,
		Method:       frame.Method.String(),
		Path:         amqpExchangeOrQueue(frame),
		Peer:         peer,
		PeerPort:     int(trace.ConnInfo.S_port),
		Host:         hostname,
		HostPort:     hostPort,
		RequestStart: int64(trace.StartMonotimeNs),
		Start:        int64(trace.StartMonotimeNs),
		End:          int64(trace.EndMonotimeNs),
		TraceID:      trace.Tp.TraceId,
		SpanID:       trace.Tp.SpanId,
		ParentSpanID: trace.Tp.ParentId,
		TraceFlags:   trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

// amqpExchangeOrQueue attempts to extract a routing key or queue name from the
// AMQP frame payload for use as the span path. The encoding is class-specific;
// for basic.publish the exchange is a short-string at payload[4].
func amqpExchangeOrQueue(frame amqpparser.Frame) string {
	if len(frame.Payload) < 6 {
		return ""
	}
	// Skip class(2) + method(2), then read a short-string (length byte + bytes)
	off := 4
	if off >= len(frame.Payload) {
		return ""
	}
	slen := int(frame.Payload[off])
	off++
	if off+slen > len(frame.Payload) {
		return ""
	}
	name := string(frame.Payload[off : off+slen])
	return name
}
