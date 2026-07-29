// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/amqpparser"
)

func TestProcessPossibleAMQPEventBasicPublishUsesReservedShortAndRoutingKey(t *testing.T) {
	event := &TCPRequestInfo{
		ConnInfo:  newTestConnInfo(),
		Direction: directionSend,
	}

	reqBuf := amqpMethodFrame(1, 60, 40, basicPublishArgs("", "orders.created"))
	span, outcome, err := ProcessPossibleAMQPEvent(event, reqBuf, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.EventTypeAMQPClient, span.Type)
	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "orders.created", span.Path)
	require.NotNil(t, span.MessagingInfo)
	assert.Equal(t, "basic.publish", span.MessagingInfo.OperationName)
}

func TestProcessPossibleAMQPEventBasicDeliverParsesConsumerTagLayout(t *testing.T) {
	event := &TCPRequestInfo{
		ConnInfo:  newTestConnInfo(),
		Direction: directionSend,
	}

	respBuf := amqpMethodFrame(3, 60, 60, basicDeliverArgs("consumer-1", 42, "amq.topic", "billing.completed"))
	span, outcome, err := ProcessPossibleAMQPEvent(event, nil, respBuf, nil)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.EventTypeAMQPServer, span.Type)
	assert.Equal(t, request.MessagingReceive, span.Method)
	assert.Equal(t, "amq.topic:billing.completed", span.Path)
	require.NotNil(t, span.MessagingInfo)
	assert.Equal(t, "basic.deliver", span.MessagingInfo.OperationName)
}

func TestProcessPossibleAMQPEventSettleUsesPerChannelDestinationCache(t *testing.T) {
	cache, err := lru.NewLRU[amqpChannelKey, string](32, nil)
	require.NoError(t, err)

	conn := newTestConnInfo()
	publishEvent := &TCPRequestInfo{
		ConnInfo:  conn,
		Direction: directionSend,
	}
	ackEvent := &TCPRequestInfo{
		ConnInfo: BpfConnectionInfoT{
			S_addr: conn.D_addr,
			D_addr: conn.S_addr,
			S_port: conn.D_port,
			D_port: conn.S_port,
		},
		Direction: directionSend,
	}

	publishBuf := amqpMethodFrame(9, 60, 40, basicPublishArgs("events", "shipments.created"))
	_, outcome, err := ProcessPossibleAMQPEvent(publishEvent, publishBuf, nil, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)

	ackBuf := amqpMethodFrame(9, 60, 80, basicAckArgs(99))
	ackSpan, outcome, err := ProcessPossibleAMQPEvent(ackEvent, ackBuf, nil, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.MessagingSettle, ackSpan.Method)
	assert.Equal(t, "events:shipments.created", ackSpan.Path)
	require.NotNil(t, ackSpan.MessagingInfo)
	assert.Equal(t, "basic.ack", ackSpan.MessagingInfo.OperationName)
}

func TestProcessPossibleAMQPEventInvalidFrameIsRejected(t *testing.T) {
	event := &TCPRequestInfo{ConnInfo: newTestConnInfo(), Direction: directionSend}

	invalid := amqpMethodFrame(1, 60, 40, basicPublishArgs("amq.topic", "orders"))
	invalid[len(invalid)-1] = 0x00

	_, outcome, err := ProcessPossibleAMQPEvent(event, invalid, invalid, nil)
	require.Error(t, err)
	assert.Equal(t, ParseInvalid, outcome)
}

func amqpMethodFrame(channel uint16, class uint16, method uint16, args []byte) []byte {
	payload := make([]byte, 4+len(args))
	binary.BigEndian.PutUint16(payload[0:2], class)
	binary.BigEndian.PutUint16(payload[2:4], method)
	copy(payload[4:], args)

	frame := make([]byte, 7+len(payload)+1)
	frame[0] = amqpparser.FrameMethod
	binary.BigEndian.PutUint16(frame[1:3], channel)
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload)))
	copy(frame[7:7+len(payload)], payload)
	frame[len(frame)-1] = amqpparser.FrameEnd
	return frame
}

func basicPublishArgs(exchange, routingKey string) []byte {
	args := make([]byte, 0, 2+len(exchange)+len(routingKey)+4)
	args = append(args, 0, 0) // reserved-1 short
	args = append(args, shortstr(exchange)...)
	args = append(args, shortstr(routingKey)...)
	args = append(args, 0) // flags
	return args
}

func basicDeliverArgs(consumerTag string, deliveryTag uint64, exchange, routingKey string) []byte {
	args := make([]byte, 0, len(consumerTag)+len(exchange)+len(routingKey)+16)
	args = append(args, shortstr(consumerTag)...)
	deliveryTagBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(deliveryTagBuf, deliveryTag)
	args = append(args, deliveryTagBuf...)
	args = append(args, 0) // redelivered bitfield
	args = append(args, shortstr(exchange)...)
	args = append(args, shortstr(routingKey)...)
	return args
}

func basicAckArgs(deliveryTag uint64) []byte {
	args := make([]byte, 9)
	binary.BigEndian.PutUint64(args[0:8], deliveryTag)
	args[8] = 0 // multiple bit
	return args
}

func shortstr(v string) []byte {
	out := make([]byte, 1+len(v))
	out[0] = byte(len(v))
	copy(out[1:], []byte(v))
	return out
}
