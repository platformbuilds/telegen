// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"errors"
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/cqlparser"
)

// isCQL returns true if the buffer looks like a CQL v3–v5 frame.
func isCQL(buf []byte) bool {
	return cqlparser.IsCQL(buf)
}

// ProcessPossibleCQLEvent attempts to parse Cassandra/ScyllaDB CQL frames.
func ProcessPossibleCQLEvent(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	// Combine both directions and stitch by stream ID.
	var allFrames []cqlparser.Frame

	reqFrames, _, reqErr := cqlparser.ParseFrames(reqBuf)
	if reqErr != nil && !errors.Is(reqErr, cqlparser.ErrNeedsMoreData) {
		return request.Span{}, ParseInvalid, reqErr
	}
	allFrames = append(allFrames, reqFrames...)

	respFrames, _, respErr := cqlparser.ParseFrames(respBuf)
	if respErr != nil && !errors.Is(respErr, cqlparser.ErrNeedsMoreData) {
		return request.Span{}, ParseInvalid, respErr
	}
	allFrames = append(allFrames, respFrames...)

	if len(allFrames) == 0 {
		if errors.Is(reqErr, cqlparser.ErrNeedsMoreData) || errors.Is(respErr, cqlparser.ErrNeedsMoreData) {
			return request.Span{}, ParseNeedsMore, errors.New("cql: needs more data")
		}
		return request.Span{}, ParseIgnored, nil
	}

	records := cqlparser.StitchFrames(allFrames)
	for _, rec := range records {
		// Look for a QUERY or EXECUTE request to turn into a span.
		req := rec.Request
		if req.Opcode != cqlparser.OpcodeQuery &&
			req.Opcode != cqlparser.OpcodeExecute &&
			req.Opcode != cqlparser.OpcodeBatch &&
			req.Opcode != cqlparser.OpcodePrepare {
			continue
		}
		return TCPToCQLToSpan(event, rec), ParseSuccess, nil
	}

	// No span-worthy frames, but parsing succeeded.
	return request.Span{}, ParseIgnored, nil
}

// TCPToCQLToSpan builds a request.Span from a CQL record.
func TCPToCQLToSpan(trace *TCPRequestInfo, rec cqlparser.Record) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	op := cqlparser.OpcodeName(rec.Request.Opcode)
	query := rec.Request.QueryString

	statusCode := 0
	if rec.Response.Opcode == cqlparser.OpcodeError {
		statusCode = 1
	}

	return request.Span{
		Type:          request.EventTypeCQLClient,
		Method:        op,
		Path:          query,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        statusCode,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}
