// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/clickhouseparser"
)

// isClickHouse returns true if buf looks like ClickHouse native TCP data.
func isClickHouse(buf []byte) bool {
	return clickhouseparser.IsClickHouse(buf)
}

// ProcessPossibleClickHouseEvent attempts to decode a ClickHouse native TCP event.
// Returns a span, the ParseOutcome, and any error.
func ProcessPossibleClickHouseEvent(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	// Decode client (request) packet
	reqPkt, _, reqErr := clickhouseparser.DecodeClientPacket(reqBuf)
	if reqErr != nil {
		// Try server hello direction (swapped capture)
		if clickhouseparser.IsClickHouseServer(reqBuf) {
			return request.Span{}, ParseIgnored, nil
		}
		return request.Span{}, ParseInvalid, reqErr
	}

	// Decode response
	var respPkt clickhouseparser.Packet
	var statusCode int
	if len(respBuf) > 0 {
		p, _, err := clickhouseparser.DecodeServerPacket(respBuf)
		if err == nil {
			respPkt = p
			if respPkt.ServerType == clickhouseparser.ServerException {
				statusCode = 1
			}
		}
	}

	// Extract SQL from ClientQuery packets
	querySQL := reqPkt.QuerySQL
	if querySQL == "" && reqPkt.ClientType == clickhouseparser.ClientQuery {
		querySQL = clickhouseparser.ExtractQuerySQL(reqBuf)
	}

	op := clickhouseparser.ClientPacketTypeName(reqPkt.ClientType)
	path := querySQL

	return TCPToClickHouseToSpan(event, op, path, reqPkt.QueryID, statusCode, int32(respPkt.ErrorCode), respPkt.ErrorMessage), ParseSuccess, nil
}

// TCPToClickHouseToSpan builds a request.Span from a ClickHouse event.
func TCPToClickHouseToSpan(trace *TCPRequestInfo, op, query, queryID string, statusCode int, errCode int32, errMsg string) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	sp := request.Span{
		Type:         request.EventTypeClickHouseClient,
		Method:       op,
		Path:         query,
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
	return sp
}
