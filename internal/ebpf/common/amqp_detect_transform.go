// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"unsafe"

	lru "github.com/hashicorp/golang-lru/v2/simplelru"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/amqpparser"
)

type amqpChannelKey struct {
	Conn    BpfConnectionInfoT
	Channel uint16
}

type amqpFrameSource uint8

const (
	amqpSourceRequest amqpFrameSource = iota
	amqpSourceResponse
)

type amqpMethodDetails struct {
	rawMethod   string
	opType      string
	destination string
	channel     uint16
}

// isAMQP returns true if the buffer looks like AMQP 0-9-1 data.
func isAMQP(buf []byte) bool {
	return amqpparser.IsAMQP(buf)
}

// ProcessPossibleAMQPEvent attempts to parse and stitch AMQP frames from a TCP event.
// Returns a span, the ParseOutcome, and any error.
func ProcessPossibleAMQPEvent(
	event *TCPRequestInfo,
	reqBuf, respBuf []byte,
	destinationCache *lru.LRU[amqpChannelKey, string],
) (request.Span, ParseOutcome, error) {
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
		if span, ok := spanFromAMQPFrame(event, rec.Request, amqpSourceRequest, destinationCache); ok {
			return span, ParseSuccess, nil
		}
		if span, ok := spanFromAMQPFrame(event, rec.Response, amqpSourceResponse, destinationCache); ok {
			return span, ParseSuccess, nil
		}
	}

	return request.Span{}, ParseIgnored, nil
}

func spanFromAMQPFrame(
	trace *TCPRequestInfo,
	frame amqpparser.Frame,
	source amqpFrameSource,
	destinationCache *lru.LRU[amqpChannelKey, string],
) (request.Span, bool) {
	details, ok := decodeAMQPMethodDetails(frame)
	if !ok {
		return request.Span{}, false
	}

	if details.destination != "" {
		rememberAMQPDestination(destinationCache, trace, details.channel, details.destination)
	} else if details.opType == request.MessagingSettle {
		details.destination = lookupAMQPDestination(destinationCache, trace, details.channel)
	}

	traceForSpan := *trace
	if source == amqpSourceResponse {
		reverseTCPEvent(&traceForSpan)
	}

	return TCPToAMQPToSpan(&traceForSpan, details), true
}

// TCPToAMQPToSpan builds a request.Span from a TCP event and decoded AMQP method details.
func TCPToAMQPToSpan(trace *TCPRequestInfo, details amqpMethodDetails) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	spanType := request.EventTypeAMQPClient
	if trace.Direction == directionRecv {
		spanType = request.EventTypeAMQPServer
	}

	return request.Span{
		Type:          spanType,
		Method:        details.opType,
		Path:          details.destination,
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
		MessagingInfo: &request.MessagingInfo{OperationName: details.rawMethod},
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

func decodeAMQPMethodDetails(frame amqpparser.Frame) (amqpMethodDetails, bool) {
	if frame.Type != amqpparser.FrameMethod || frame.Method.Class == 0 {
		return amqpMethodDetails{}, false
	}

	details := amqpMethodDetails{
		rawMethod: frame.Method.String(),
		opType:    request.MessagingProcess,
		channel:   frame.Channel,
	}

	switch frame.Method {
	case amqpparser.ClassMethod{Class: 60, Method: 40}: // basic.publish
		exchange, routingKey, ok := parseBasicPublishDestination(frame.Payload)
		if !ok {
			return amqpMethodDetails{}, false
		}
		details.opType = request.MessagingPublish
		details.destination = resolveAMQPDestination(exchange, routingKey)
	case amqpparser.ClassMethod{Class: 60, Method: 20}: // basic.consume
		queue, ok := parseBasicConsumeQueue(frame.Payload)
		if !ok {
			return amqpMethodDetails{}, false
		}
		details.opType = request.MessagingCreate
		details.destination = queue
	case amqpparser.ClassMethod{Class: 60, Method: 60}: // basic.deliver
		exchange, routingKey, ok := parseBasicDeliverDestination(frame.Payload)
		if !ok {
			return amqpMethodDetails{}, false
		}
		details.opType = request.MessagingReceive
		details.destination = resolveAMQPDestination(exchange, routingKey)
	case amqpparser.ClassMethod{Class: 60, Method: 70}: // basic.get
		queue, ok := parseBasicGetQueue(frame.Payload)
		if !ok {
			return amqpMethodDetails{}, false
		}
		details.opType = request.MessagingReceive
		details.destination = queue
	case amqpparser.ClassMethod{Class: 60, Method: 71}: // basic.get-ok
		exchange, routingKey, ok := parseBasicGetOKDestination(frame.Payload)
		if !ok {
			return amqpMethodDetails{}, false
		}
		details.opType = request.MessagingReceive
		details.destination = resolveAMQPDestination(exchange, routingKey)
	case amqpparser.ClassMethod{Class: 60, Method: 80}, // basic.ack
		amqpparser.ClassMethod{Class: 60, Method: 90},  // basic.reject
		amqpparser.ClassMethod{Class: 60, Method: 120}: // basic.nack
		details.opType = request.MessagingSettle
	case amqpparser.ClassMethod{Class: 10, Method: 40}, // connection.open
		amqpparser.ClassMethod{Class: 20, Method: 10}, // channel.open
		amqpparser.ClassMethod{Class: 40, Method: 10}, // exchange.declare
		amqpparser.ClassMethod{Class: 40, Method: 20}, // exchange.delete
		amqpparser.ClassMethod{Class: 40, Method: 30}, // exchange.bind
		amqpparser.ClassMethod{Class: 40, Method: 40}, // exchange.unbind
		amqpparser.ClassMethod{Class: 50, Method: 10}, // queue.declare
		amqpparser.ClassMethod{Class: 50, Method: 20}, // queue.bind
		amqpparser.ClassMethod{Class: 50, Method: 50}: // queue.unbind
		details.opType = request.MessagingCreate
		details.destination = parseCreateDestination(frame)
	default:
		details.opType = request.MessagingProcess
	}

	return details, true
}

func parseCreateDestination(frame amqpparser.Frame) string {
	switch frame.Method {
	case amqpparser.ClassMethod{Class: 10, Method: 40}: // connection.open
		if vhost, _, ok := readShortstr(frame.Payload, 4); ok {
			return vhost
		}
	case amqpparser.ClassMethod{Class: 40, Method: 10}, // exchange.declare
		amqpparser.ClassMethod{Class: 40, Method: 20}: // exchange.delete
		if exchange, _, ok := parseExchangeFromReservedShort(frame.Payload); ok {
			return exchange
		}
	case amqpparser.ClassMethod{Class: 50, Method: 10}: // queue.declare
		if queue, _, ok := parseQueueFromReservedShort(frame.Payload); ok {
			return queue
		}
	case amqpparser.ClassMethod{Class: 50, Method: 20}, // queue.bind
		amqpparser.ClassMethod{Class: 50, Method: 50}: // queue.unbind
		queue, exchange, routingKey, ok := parseQueueBindLike(frame.Payload)
		if ok {
			if queue != "" {
				return queue
			}
			return resolveAMQPDestination(exchange, routingKey)
		}
	case amqpparser.ClassMethod{Class: 40, Method: 30}, // exchange.bind
		amqpparser.ClassMethod{Class: 40, Method: 40}: // exchange.unbind
		destExchange, sourceExchange, routingKey, ok := parseExchangeBindLike(frame.Payload)
		if !ok {
			return ""
		}
		if destExchange != "" {
			return destExchange
		}
		return resolveAMQPDestination(sourceExchange, routingKey)
	}

	return ""
}

func parseBasicPublishDestination(payload []byte) (string, string, bool) {
	exchange, off, ok := parseExchangeFromReservedShort(payload)
	if !ok {
		return "", "", false
	}
	routingKey, _, ok := readShortstr(payload, off)
	if !ok {
		return "", "", false
	}
	return exchange, routingKey, true
}

func parseBasicConsumeQueue(payload []byte) (string, bool) {
	queue, _, ok := parseQueueFromReservedShort(payload)
	return queue, ok
}

func parseBasicGetQueue(payload []byte) (string, bool) {
	queue, _, ok := parseQueueFromReservedShort(payload)
	return queue, ok
}

func parseBasicDeliverDestination(payload []byte) (string, string, bool) {
	off := 4
	_, off, ok := readShortstr(payload, off) // consumer-tag
	if !ok || off+8+1 > len(payload) {
		return "", "", false
	}
	off += 8 // delivery-tag
	off++    // redelivered bitfield
	exchange, off, ok := readShortstr(payload, off)
	if !ok {
		return "", "", false
	}
	routingKey, _, ok := readShortstr(payload, off)
	if !ok {
		return "", "", false
	}
	return exchange, routingKey, true
}

func parseBasicGetOKDestination(payload []byte) (string, string, bool) {
	off := 4
	if off+8+1 > len(payload) {
		return "", "", false
	}
	off += 8 // delivery-tag
	off++    // redelivered bitfield
	exchange, off, ok := readShortstr(payload, off)
	if !ok {
		return "", "", false
	}
	routingKey, _, ok := readShortstr(payload, off)
	if !ok {
		return "", "", false
	}
	return exchange, routingKey, true
}

func parseExchangeFromReservedShort(payload []byte) (string, int, bool) {
	off := 4
	if off+2 > len(payload) {
		return "", 0, false
	}
	off += 2 // reserved-1 short
	exchange, off, ok := readShortstr(payload, off)
	if !ok {
		return "", 0, false
	}
	return exchange, off, true
}

func parseQueueFromReservedShort(payload []byte) (string, int, bool) {
	off := 4
	if off+2 > len(payload) {
		return "", 0, false
	}
	off += 2 // reserved-1 short
	queue, off, ok := readShortstr(payload, off)
	if !ok {
		return "", 0, false
	}
	return queue, off, true
}

func parseQueueBindLike(payload []byte) (queue, exchange, routingKey string, ok bool) {
	queue, off, ok := parseQueueFromReservedShort(payload)
	if !ok {
		return "", "", "", false
	}
	exchange, off, ok = readShortstr(payload, off)
	if !ok {
		return "", "", "", false
	}
	routingKey, _, ok = readShortstr(payload, off)
	if !ok {
		return "", "", "", false
	}
	return queue, exchange, routingKey, true
}

func parseExchangeBindLike(payload []byte) (destinationExchange, sourceExchange, routingKey string, ok bool) {
	destinationExchange, off, ok := parseExchangeFromReservedShort(payload)
	if !ok {
		return "", "", "", false
	}
	sourceExchange, off, ok = readShortstr(payload, off)
	if !ok {
		return "", "", "", false
	}
	routingKey, _, ok = readShortstr(payload, off)
	if !ok {
		return "", "", "", false
	}
	return destinationExchange, sourceExchange, routingKey, true
}

func readShortstr(payload []byte, off int) (string, int, bool) {
	if off < 0 || off >= len(payload) {
		return "", off, false
	}
	slen := int(payload[off])
	off++
	if off+slen > len(payload) {
		return "", off, false
	}
	return string(payload[off : off+slen]), off + slen, true
}

func resolveAMQPDestination(exchange, routingKey string) string {
	exchange = strings.TrimSpace(exchange)
	routingKey = strings.TrimSpace(routingKey)

	if exchange == "" {
		return routingKey
	}
	if routingKey == "" {
		return exchange
	}
	return exchange + ":" + routingKey
}

func rememberAMQPDestination(cache *lru.LRU[amqpChannelKey, string], trace *TCPRequestInfo, channel uint16, destination string) {
	if cache == nil || channel == 0 || destination == "" {
		return
	}
	cache.Add(amqpDestinationKey(trace, channel), destination)
}

func lookupAMQPDestination(cache *lru.LRU[amqpChannelKey, string], trace *TCPRequestInfo, channel uint16) string {
	if cache == nil || channel == 0 {
		return ""
	}
	if destination, ok := cache.Get(amqpDestinationKey(trace, channel)); ok {
		return destination
	}
	return ""
}

func amqpDestinationKey(trace *TCPRequestInfo, channel uint16) amqpChannelKey {
	return amqpChannelKey{
		Conn:    normalizeAMQPConn(trace.ConnInfo),
		Channel: channel,
	}
}

func normalizeAMQPConn(conn BpfConnectionInfoT) BpfConnectionInfoT {
	left := conn.S_addr
	right := conn.D_addr
	if compareAMQPEndpoints(left[:], conn.S_port, right[:], conn.D_port) > 0 {
		conn.S_addr, conn.D_addr = conn.D_addr, conn.S_addr
		conn.S_port, conn.D_port = conn.D_port, conn.S_port
	}
	return conn
}

func compareAMQPEndpoints(addrA []byte, portA uint16, addrB []byte, portB uint16) int {
	if cmp := bytes.Compare(addrA, addrB); cmp != 0 {
		return cmp
	}
	a := make([]byte, 2)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(a, portA)
	binary.BigEndian.PutUint16(b, portB)
	return bytes.Compare(a, b)
}
