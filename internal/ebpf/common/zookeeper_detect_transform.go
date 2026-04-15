// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/zkparser"
)

// isZooKeeper returns true if buf looks like ZooKeeper Jute binary protocol data.
func isZooKeeper(buf []byte) bool {
	return zkparser.IsZooKeeper(buf)
}

// ProcessPossibleZooKeeperEvent attempts to parse ZooKeeper packets from a TCP event.
// Returns a span, the ParseOutcome, and any error.
func ProcessPossibleZooKeeperEvent(event *TCPRequestInfo, reqBuf, respBuf []byte) (request.Span, ParseOutcome, error) {
	var allPkts []zkparser.Packet

	reqPkts, _, reqErr := zkparser.ParsePackets(reqBuf)
	if reqErr != nil && len(reqPkts) == 0 {
		return request.Span{}, ParseInvalid, reqErr
	}
	allPkts = append(allPkts, reqPkts...)

	respPkts, _, _ := zkparser.ParsePackets(respBuf)
	allPkts = append(allPkts, respPkts...)

	if len(allPkts) == 0 {
		return request.Span{}, ParseIgnored, nil
	}

	records := zkparser.StitchPackets(allPkts)

	// Pick the first span-worthy record (has a request with a known opCode).
	for _, rec := range records {
		if rec.Request == nil {
			continue
		}
		req := rec.Request

		var opName string
		var path string
		if req.Connect != nil {
			opName = "Connect"
			path = ""
		} else if req.Request != nil {
			opName = zkparser.OpCodeName(req.Request.OpCode)
			path = req.Path
		} else {
			continue
		}

		statusCode := 0
		if rec.Response != nil && rec.Response.Reply != nil && rec.Response.Reply.ErrCode != 0 {
			statusCode = 1
		}

		return TCPToZooKeeperToSpan(event, opName, path, statusCode), ParseSuccess, nil
	}

	// Connect packet alone — still useful as a span
	for i := range allPkts {
		pkt := &allPkts[i]
		if pkt.Connect != nil {
			return TCPToZooKeeperToSpan(event, "Connect", "", 0), ParseSuccess, nil
		}
	}

	return request.Span{}, ParseIgnored, nil
}

// TCPToZooKeeperToSpan builds a request.Span from a ZooKeeper event.
func TCPToZooKeeperToSpan(trace *TCPRequestInfo, op, path string, statusCode int) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:         request.EventTypeZooKeeperClient,
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
