// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"errors"
	"strings"
	"unsafe"

	lru "github.com/hashicorp/golang-lru/v2/simplelru"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/openwireparser"
)

type openWireDestinationKey struct {
	Conn BpfConnectionInfoT
	ID   uint32
	Kind uint8
}

const (
	openWireDestinationProducer uint8 = 1
	openWireDestinationConsumer uint8 = 2
)

// isOpenWire returns true if the buffer looks like OpenWire protocol data.
func isOpenWire(buf []byte) bool {
	return openwireparser.IsOpenWire(buf)
}

func ProcessPossibleOpenWireEvent(
	event *TCPRequestInfo,
	reqBuf, respBuf []byte,
	destinationCache *lru.LRU[openWireDestinationKey, string],
) (request.Span, ParseOutcome, error) {
	reqCommands, _, reqErr := openwireparser.ParseCommands(reqBuf)
	respCommands, _, respErr := openwireparser.ParseCommands(respBuf)

	if reqErr != nil && respErr != nil {
		if errors.Is(reqErr, openwireparser.ErrNeedsMoreData) || errors.Is(respErr, openwireparser.ErrNeedsMoreData) {
			return request.Span{}, ParseNeedsMore, errors.New("openwire: needs more data")
		}
		return request.Span{}, ParseInvalid, errors.New("openwire: could not parse either direction")
	}

	if len(reqCommands) == 0 && len(respCommands) == 0 {
		if errors.Is(reqErr, openwireparser.ErrNeedsMoreData) || errors.Is(respErr, openwireparser.ErrNeedsMoreData) {
			return request.Span{}, ParseNeedsMore, nil
		}
		return request.Span{}, ParseIgnored, nil
	}

	for _, command := range reqCommands {
		if span, ok := spanFromOpenWireCommand(event, command, amqpSourceRequest, destinationCache); ok {
			return span, ParseSuccess, nil
		}
	}
	for _, command := range respCommands {
		if span, ok := spanFromOpenWireCommand(event, command, amqpSourceResponse, destinationCache); ok {
			return span, ParseSuccess, nil
		}
	}

	return request.Span{}, ParseIgnored, nil
}

func spanFromOpenWireCommand(
	trace *TCPRequestInfo,
	command openwireparser.Command,
	source amqpFrameSource,
	destinationCache *lru.LRU[openWireDestinationKey, string],
) (request.Span, bool) {
	traceForSpan := *trace
	if source == amqpSourceResponse {
		reverseTCPEvent(&traceForSpan)
	}

	spanType := request.EventTypeOpenWireClient
	if traceForSpan.Direction == directionRecv {
		spanType = request.EventTypeOpenWireServer
	}

	var opType string
	var opName string
	destination := openWireDestination(command.DestinationType, command.Destination)

	switch command.Type {
	case openwireparser.CommandWireFormatInfo:
		return request.Span{}, false
	case openwireparser.CommandProducerInfo:
		opType = request.MessagingCreate
		opName = "openwire.producer_info"
		if command.ProducerID != 0 && destination != "" {
			rememberOpenWireDestination(destinationCache, &traceForSpan, command.ProducerID, openWireDestinationProducer, destination)
		}
	case openwireparser.CommandConsumerInfo:
		opType = request.MessagingCreate
		opName = "openwire.consumer_info"
		if command.ConsumerID != 0 && destination != "" {
			rememberOpenWireDestination(destinationCache, &traceForSpan, command.ConsumerID, openWireDestinationConsumer, destination)
		}
	case openwireparser.CommandMessage:
		opType = request.MessagingPublish
		if source == amqpSourceResponse {
			opType = request.MessagingReceive
		}
		opName = "openwire.message"
		if destination == "" && command.ProducerID != 0 {
			destination = lookupOpenWireDestination(destinationCache, &traceForSpan, command.ProducerID, openWireDestinationProducer)
		}
	case openwireparser.CommandMessageAck:
		opType = request.MessagingSettle
		opName = "openwire.message_ack"
		if command.ConsumerID != 0 {
			destination = lookupOpenWireDestination(destinationCache, &traceForSpan, command.ConsumerID, openWireDestinationConsumer)
		}
	default:
		return request.Span{}, false
	}

	return TCPToOpenWireToSpan(&traceForSpan, spanType, opType, opName, destination), true
}

func TCPToOpenWireToSpan(
	trace *TCPRequestInfo,
	spanType request.EventType,
	opType string,
	opName string,
	destination string,
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
		MessagingInfo: &request.MessagingInfo{OperationName: opName},
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

func rememberOpenWireDestination(
	cache *lru.LRU[openWireDestinationKey, string],
	trace *TCPRequestInfo,
	id uint32,
	kind uint8,
	destination string,
) {
	if cache == nil || id == 0 || destination == "" {
		return
	}
	cache.Add(openWireCacheKey(trace, id, kind), destination)
}

func lookupOpenWireDestination(
	cache *lru.LRU[openWireDestinationKey, string],
	trace *TCPRequestInfo,
	id uint32,
	kind uint8,
) string {
	if cache == nil || id == 0 {
		return ""
	}
	if destination, ok := cache.Get(openWireCacheKey(trace, id, kind)); ok {
		return destination
	}
	return ""
}

func openWireCacheKey(trace *TCPRequestInfo, id uint32, kind uint8) openWireDestinationKey {
	return openWireDestinationKey{
		Conn: normalizeAMQPConn(trace.ConnInfo),
		ID:   id,
		Kind: kind,
	}
}

func openWireDestination(destType openwireparser.DestinationType, destination string) string {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return ""
	}

	switch destType {
	case openwireparser.DestinationQueue:
		if strings.HasPrefix(destination, "queue://") {
			return destination
		}
		return "queue://" + destination
	case openwireparser.DestinationTopic:
		if strings.HasPrefix(destination, "topic://") {
			return destination
		}
		return "topic://" + destination
	default:
		return destination
	}
}
