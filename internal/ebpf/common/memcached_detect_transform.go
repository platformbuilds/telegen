// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/memcachedparser"
)

// isMemcached returns true if buf looks like Memcached ASCII protocol data.
func isMemcached(buf []byte) bool {
	return memcachedparser.IsMemcached(buf)
}

// ProcessPossibleMemcachedEvent attempts to parse a Memcached ASCII command from a TCP event.
// Returns a span, the ParseOutcome, and any error.
func ProcessPossibleMemcachedEvent(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	// Try to parse the request direction first.
	requests, _, reqErr := memcachedparser.ParseRequest(reqBuf)
	if reqErr != nil && len(requests) == 0 {
		// Could be a response-only capture or wrong direction — try the other side.
		if isMemcached(respBuf) {
			responses, _, respErr := memcachedparser.ParseResponse(respBuf)
			if respErr != nil {
				responses = nil
			}
			if len(responses) > 0 {
				// We only have a response; build a minimal span.
				resp := responses[0]
				return TCPToMemcachedToSpan(event, memcachedparser.Message{
					Direction:  memcachedparser.DirectionRequest,
					CommandStr: "unknown",
					Command:    memcachedparser.CmdUnknown,
				}, resp), ParseSuccess, nil
			}
		}
		return request.Span{}, ParseInvalid, reqErr
	}

	if len(requests) == 0 {
		return request.Span{}, ParseIgnored, nil
	}

	req := requests[0]
	// Match the best response for the first request.
	var resp memcachedparser.Message
	responses, _, respErr := memcachedparser.ParseResponse(respBuf)
	if respErr != nil {
		responses = nil
	}
	if len(responses) > 0 {
		resp = responses[0]
	}

	return TCPToMemcachedToSpan(event, req, resp), ParseSuccess, nil
}

// TCPToMemcachedToSpan builds a request.Span from a Memcached request+response pair.
func TCPToMemcachedToSpan(trace *TCPRequestInfo, req, resp memcachedparser.Message) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	key := req.Key
	if key == "" && len(req.Keys) > 0 {
		key = req.Keys[0]
	}

	statusCode := resp.StatusCode

	return request.Span{
		Type:         request.EventTypeMemcachedClient,
		Method:       req.CommandStr,
		Path:         key,
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
