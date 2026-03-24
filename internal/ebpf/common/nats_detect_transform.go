// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"errors"
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/natsparser"
)

// isNATS returns true if the buffer looks like NATS protocol data.
func isNATS(buf []byte) bool {
	return natsparser.IsNATS(buf)
}

// ProcessPossibleNATSEvent attempts to parse NATS messages and produce a span.
func ProcessPossibleNATSEvent(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	var allMessages []natsparser.Message

	reqMsgs, _, reqErr := natsparser.ParseMessages(reqBuf)
	if reqErr != nil && !errors.Is(reqErr, natsparser.ErrNeedsMoreData) {
		return request.Span{}, ParseInvalid, reqErr
	}
	allMessages = append(allMessages, reqMsgs...)

	respMsgs, _, respErr := natsparser.ParseMessages(respBuf)
	if respErr != nil && !errors.Is(respErr, natsparser.ErrNeedsMoreData) {
		return request.Span{}, ParseInvalid, respErr
	}
	allMessages = append(allMessages, respMsgs...)

	if len(allMessages) == 0 {
		return request.Span{}, ParseNeedsMore, nil
	}

	records := natsparser.StitchMessages(allMessages)
	if len(records) == 0 {
		return request.Span{}, ParseIgnored, nil
	}

	return TCPToNATSToSpan(event, records[0]), ParseSuccess, nil
}

// TCPToNATSToSpan converts a TCPRequestInfo and NATS Record into a request.Span.
func TCPToNATSToSpan(trace *TCPRequestInfo, rec natsparser.Record) request.Span {
	peer, hostname := (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()

	// Prefer request subject; fall back to response.
	subject := rec.Request.Subject
	if subject == "" {
		subject = rec.Response.Subject
	}

	method := "PUB"
	if rec.Request.Type == natsparser.TypePING {
		method = "PING"
	} else if rec.Request.Type == natsparser.TypeCONNECT {
		method = "CONNECT"
	}

	return request.Span{
		Type:           request.EventTypeNATSClient,
		Method:         method,
		Path:           subject,
		Peer:           peer,
		PeerPort:       int(trace.ConnInfo.S_port),
		Host:           hostname,
		HostPort:       int(trace.ConnInfo.D_port),
		RequestStart:   int64(trace.StartMonotimeNs),
		Start:          int64(trace.StartMonotimeNs),
		End:            int64(trace.EndMonotimeNs),
		TraceID:        trace.Tp.TraceId,
		SpanID:         trace.Tp.SpanId,
		ParentSpanID:   trace.Tp.ParentId,
		TraceFlags:     trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}
