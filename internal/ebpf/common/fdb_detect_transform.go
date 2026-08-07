// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/fdbparser"
)

// isFDB returns true if buf starts with FoundationDB connect magic.
func isFDB(buf []byte) bool {
	return fdbparser.IsFDB(buf)
}

// ProcessPossibleFDBEvent attempts to parse FoundationDB protocol packets from a TCP event.
// Returns a span, the ParseOutcome, and any error.
func ProcessPossibleFDBEvent(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	reqPkts, _, reqErr := fdbparser.ParsePackets(reqBuf)
	if reqErr != nil && len(reqPkts) == 0 {
		return request.Span{}, ParseInvalid, reqErr
	}
	if len(reqPkts) == 0 {
		return request.Span{}, ParseIgnored, nil
	}

	respPkts, _, respErr := fdbparser.ParsePackets(respBuf)
	if respErr != nil {
		respPkts = nil
	}

	// The primary span is the connect handshake or first data exchange.
	req := reqPkts[0]

	op := "data"
	path := ""
	statusCode := 0
	if req.Type == fdbparser.FrameConnect {
		op = "connect"
		path = fdbparser.ProtocolVersionString(req.ProtocolVersion)
	}

	// Check if any response frame indicates an error (heuristic: token == 0 on data is unusual)
	for _, resp := range respPkts {
		if resp.Type == fdbparser.FrameData && resp.PayloadLen == 0 && resp.Token == fdbparser.TokenUnset {
			statusCode = 1
			break
		}
	}

	return TCPToFDBToSpan(event, op, path, statusCode), ParseSuccess, nil
}

// TCPToFDBToSpan builds a request.Span from a FoundationDB event.
func TCPToFDBToSpan(trace *TCPRequestInfo, op, path string, statusCode int) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:         request.EventTypeFDBClient,
		Method:       op,
		Path:         path,
		Peer:         peer,
		PeerPort:     int(trace.ConnInfo.S_port),
		Host:         hostname,
		HostPort:     hostPort,
		RequestStart: int64(trace.StartMonotimeNs),
		Start:        int64(trace.StartMonotimeNs),
		End:          int64(trace.EndMonotimeNs),
		Status:       statusCode,
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
