// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/dubbov2parser"
)

// isDubbo2 returns true if buf starts with Dubbo2 magic bytes.
func isDubbo2(buf []byte) bool {
	return dubbov2parser.IsDubbo2(buf)
}

// ProcessPossibleDubbo2Event attempts to parse Dubbo2 RPC frames from a TCP event.
// Returns a span, the ParseOutcome, and any error.
func ProcessPossibleDubbo2Event(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	reqFrames, _, reqErr := dubbov2parser.ParseFrames(reqBuf)
	if reqErr != nil && len(reqFrames) == 0 {
		return request.Span{}, ParseInvalid, reqErr
	}

	respFrames, _, respErr := dubbov2parser.ParseFrames(respBuf)
	if respErr != nil {
		respFrames = nil
	}

	allFrames := append(reqFrames, respFrames...)
	if len(allFrames) == 0 {
		return request.Span{}, ParseIgnored, nil
	}

	records := dubbov2parser.StitchFrames(allFrames)

	// Pick the first matched record.
	if len(records) > 0 {
		rec := records[0]
		req := rec.Request
		resp := rec.Response

		method := req.ParsedMethod
		service := req.ParsedService
		version := req.ParsedVersion
		if method == "" {
			method = "unknown"
		}

		// Build span path as "service/version/method"
		path := service
		if version != "" && version != "0.0.0" {
			path += "@" + version
		}
		if method != "" {
			if path != "" {
				path += "/" + method
			} else {
				path = method
			}
		}

		statusCode := resp.StatusCode

		return TCPToDubbo2ToSpan(event, method, path, req.Serialization, statusCode, resp.Status), ParseSuccess, nil
	}

	// Request-only frames (e.g., heartbeat events)
	if len(reqFrames) > 0 {
		f := reqFrames[0]
		if f.IsEvent {
			return request.Span{}, ParseIgnored, nil // heartbeat — skip
		}
		method := f.ParsedMethod
		if method == "" {
			method = "invoke"
		}
		return TCPToDubbo2ToSpan(event, method, f.ParsedService+"/"+method, f.Serialization, 0, 0), ParseSuccess, nil
	}

	return request.Span{}, ParseIgnored, nil
}

// TCPToDubbo2ToSpan builds a request.Span from a Dubbo2 RPC event.
func TCPToDubbo2ToSpan(trace *TCPRequestInfo, method, path string, serial dubbov2parser.SerializationID, statusCode int, status uint8) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:         request.EventTypeDubbo2Client,
		Method:       method,
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

// ClientPacketTypeName returns a human-readable name for a Dubbo2 "client packet type" (not used directly).
func ClientPacketTypeName(_ int) string { return "invoke" }
