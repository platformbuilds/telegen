// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"errors"
	"log/slog"
	"strconv"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/largebuf"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/sunrpcparser"
)

// SunRPCInfo carries parsed ONC RPC metadata for span creation.
type SunRPCInfo struct {
	Program     uint32
	Version     uint32
	Procedure   uint32
	ProgramName string
	Method      string
	AuthFlavor  string
	Status      int
}

var errSunRPCParseFailed = errors.New("sunrpc parse failed")

// ProcessPossibleSunRPCEvent parses both TCP capture buffers and picks the best SunRPC metadata
// for span creation.
func ProcessPossibleSunRPCEvent(event *TCPRequestInfo, reqBytes, respBytes []byte) (*SunRPCInfo, bool, error) {
	reqInfo, reqIgnore, reqErr := processSunRPCBuffer(reqBytes)
	respInfo, respIgnore, respErr := processSunRPCBuffer(respBytes)

	reqCall := reqErr == nil && !reqIgnore && isSunRPCCallInfo(reqInfo)
	respCall := respErr == nil && !respIgnore && isSunRPCCallInfo(respInfo)

	// eBPF labels buffers by capture direction (send vs recv), not by RPC role.
	switch {
	case reqCall:
		mergeSunRPCReplyStatus(reqInfo, respInfo, respErr, respIgnore)
		return reqInfo, false, nil
	case respCall:
		reverseTCPEvent(event)
		mergeSunRPCReplyStatus(respInfo, reqInfo, reqErr, reqIgnore)
		return respInfo, false, nil
	case reqErr == nil && !reqIgnore && reqInfo != nil:
		return reqInfo, false, nil
	case respErr == nil && !respIgnore && respInfo != nil:
		reverseTCPEvent(event)
		return respInfo, false, nil
	case reqErr == nil || respErr == nil:
		return nil, true, nil
	}

	if errors.Is(reqErr, sunrpcparser.ErrNotSunRPC) && errors.Is(respErr, sunrpcparser.ErrNotSunRPC) {
		return nil, true, sunrpcparser.ErrNotSunRPC
	}
	return nil, true, errSunRPCParseFailed
}

func isSunRPCCallInfo(info *SunRPCInfo) bool {
	return info != nil && info.Method != request.SunRPCSyntheticReplyMethod
}

func mergeSunRPCReplyStatus(callInfo *SunRPCInfo, replyInfo *SunRPCInfo, replyErr error, replyIgnore bool) {
	if callInfo == nil || replyErr != nil || replyIgnore || replyInfo == nil {
		return
	}
	if replyInfo.Status != 0 {
		callInfo.Status = replyInfo.Status
	}
}

func processSunRPCBuffer(pkt []byte) (*SunRPCInfo, bool, error) {
	if len(pkt) == 0 {
		return nil, true, sunrpcparser.ErrNotSunRPC
	}

	reader := largebuf.NewLargeBufferFrom(pkt).NewReader()
	if !sunrpcparser.IsLikelySunRPC(&reader) {
		return nil, true, sunrpcparser.ErrNotSunRPC
	}

	reader.Reset()
	result, err := sunrpcparser.Parse(&reader)
	if err != nil {
		return nil, true, err
	}

	if result.Call != nil {
		return sunRPCInfoFromCall(result.Call, result.Reply), false, nil
	}
	if result.Reply != nil {
		return sunRPCInfoFromReply(result.Reply), false, nil
	}
	return nil, true, nil
}

func sunRPCInfoFromCall(call *sunrpcparser.CallInfo, reply *sunrpcparser.ReplyInfo) *SunRPCInfo {
	progName := sunrpcparser.ProgramName(call.Program)
	if progName == "" {
		progName = strconv.FormatUint(uint64(call.Program), 10)
	}

	info := &SunRPCInfo{
		Program:     call.Program,
		Version:     call.Version,
		Procedure:   call.Procedure,
		ProgramName: progName,
		Method:      sunrpcparser.ProcedureLabel(call.Program, call.Procedure),
		AuthFlavor:  sunrpcparser.AuthFlavorName(call.AuthFlavor),
	}
	if reply != nil && reply.MatchCallXid {
		info.Status = sunRPCStatusFromReply(reply)
	}
	return info
}

func sunRPCInfoFromReply(reply *sunrpcparser.ReplyInfo) *SunRPCInfo {
	info := &SunRPCInfo{
		ProgramName: "sunrpc",
		Method:      request.SunRPCSyntheticReplyMethod,
	}
	info.Status = sunRPCStatusFromReply(reply)
	return info
}

// sunRPCStatusFromReply maps REPLY outcomes to span.Status (non-zero => error).
func sunRPCStatusFromReply(reply *sunrpcparser.ReplyInfo) int {
	switch {
	case reply.Denied:
		return 1
	case reply.AcceptStat != sunrpcAcceptSuccess:
		return int(reply.AcceptStat) + 1
	}
	return 0
}

const sunrpcAcceptSuccess = 0

func TCPToSunRPCToSpan(trace *TCPRequestInfo, data *SunRPCInfo) request.Span {
	peer := ""
	hostname := ""
	peerPort := 0
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(&trace.ConnInfo).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}

	spanType := sunRPCSpanType(trace, data)
	subType := 0
	if data.Version > 0 && data.Version <= 255 {
		subType = int(data.Version)
	}

	route := ""
	if isSunRPCCallInfo(data) {
		route = strconv.FormatUint(uint64(data.Procedure), 10)
	}

	return request.Span{
		Type:         spanType,
		Method:       data.Method,
		Path:         data.ProgramName,
		Route:        route,
		Statement:    data.AuthFlavor,
		SubType:      subType,
		Peer:         peer,
		PeerPort:     peerPort,
		Host:         hostname,
		HostPort:     hostPort,
		RequestStart: int64(trace.StartMonotimeNs),
		Start:        int64(trace.StartMonotimeNs),
		End:          int64(trace.EndMonotimeNs),
		Status:       data.Status,
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

func sunRPCSpanType(trace *TCPRequestInfo, data *SunRPCInfo) request.EventType {
	serverOnRecv := trace.Direction == directionRecv
	if !isSunRPCCallInfo(data) {
		serverOnRecv = !serverOnRecv
	}
	if serverOnRecv {
		return request.EventTypeSunRPCServer
	}
	return request.EventTypeSunRPCClient
}

func matchSunRPC(_ *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer []byte) (request.Span, bool, bool, error) {
	info, ignore, err := ProcessPossibleSunRPCEvent(event, requestBuffer, responseBuffer)
	if ignore && err == nil {
		return request.Span{}, true, true, nil
	}
	if err != nil {
		if errors.Is(err, sunrpcparser.ErrNotSunRPC) {
			return request.Span{}, false, false, nil
		}
		slog.Debug("SunRPC parsing failed after heuristic match, dropping event", "error", err)
		return request.Span{}, true, true, nil
	}
	if info == nil {
		return request.Span{}, true, true, nil
	}
	return TCPToSunRPCToSpan(event, info), false, true, nil
}
