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
	"github.com/mirastacklabs-ai/telegen/internal/parsers/openwireparser"
)

func TestProcessPossibleOpenWireEventCachesProducerDestination(t *testing.T) {
	cache, err := lru.NewLRU[openWireDestinationKey, string](32, nil)
	require.NoError(t, err)

	event := &TCPRequestInfo{ConnInfo: newTestConnInfo(), Direction: directionSend}

	producer := openWireProducerInfo(11, openwireparser.DestinationQueue, "orders.queue")
	span, outcome, err := ProcessPossibleOpenWireEvent(event, producer, nil, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.MessagingCreate, span.Method)
	assert.Equal(t, "queue://orders.queue", span.Path)

	message := openWireMessage(11, openwireparser.DestinationUnknown, "")
	span, outcome, err = ProcessPossibleOpenWireEvent(event, message, nil, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "queue://orders.queue", span.Path)
	require.NotNil(t, span.MessagingInfo)
	assert.Equal(t, "openwire.message", span.MessagingInfo.OperationName)
}

func TestProcessPossibleOpenWireEventAckUsesConsumerCacheAcrossDirections(t *testing.T) {
	cache, err := lru.NewLRU[openWireDestinationKey, string](32, nil)
	require.NoError(t, err)

	conn := newTestConnInfo()
	consumerEvent := &TCPRequestInfo{ConnInfo: conn, Direction: directionSend}
	ackEvent := &TCPRequestInfo{
		ConnInfo: BpfConnectionInfoT{
			S_addr: conn.D_addr,
			D_addr: conn.S_addr,
			S_port: conn.D_port,
			D_port: conn.S_port,
		},
		Direction: directionSend,
	}

	consumer := openWireConsumerInfo(33, openwireparser.DestinationTopic, "billing.topic")
	_, outcome, err := ProcessPossibleOpenWireEvent(consumerEvent, consumer, nil, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)

	ack := openWireMessageAck(33)
	span, outcome, err := ProcessPossibleOpenWireEvent(ackEvent, ack, nil, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.MessagingSettle, span.Method)
	assert.Equal(t, "topic://billing.topic", span.Path)
}

func TestProcessPossibleOpenWireEventResponseMessageIsReceiveServer(t *testing.T) {
	cache, err := lru.NewLRU[openWireDestinationKey, string](32, nil)
	require.NoError(t, err)
	event := &TCPRequestInfo{ConnInfo: newTestConnInfo(), Direction: directionSend}

	respMessage := openWireMessage(44, openwireparser.DestinationTopic, "alerts.topic")
	span, outcome, err := ProcessPossibleOpenWireEvent(event, nil, respMessage, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.EventTypeOpenWireServer, span.Type)
	assert.Equal(t, request.MessagingReceive, span.Method)
	assert.Equal(t, "topic://alerts.topic", span.Path)
}

func openWireProducerInfo(producerID uint32, destinationType openwireparser.DestinationType, destination string) []byte {
	out := []byte{byte(openwireparser.CommandProducerInfo)}
	id := make([]byte, 4)
	binary.BigEndian.PutUint32(id, producerID)
	out = append(out, id...)
	out = append(out, byte(destinationType))
	out = append(out, openWireString(destination)...)
	return out
}

func openWireConsumerInfo(consumerID uint32, destinationType openwireparser.DestinationType, destination string) []byte {
	out := []byte{byte(openwireparser.CommandConsumerInfo)}
	id := make([]byte, 4)
	binary.BigEndian.PutUint32(id, consumerID)
	out = append(out, id...)
	out = append(out, byte(destinationType))
	out = append(out, openWireString(destination)...)
	return out
}

func openWireMessage(producerID uint32, destinationType openwireparser.DestinationType, destination string) []byte {
	out := []byte{byte(openwireparser.CommandMessage)}
	id := make([]byte, 4)
	binary.BigEndian.PutUint32(id, producerID)
	out = append(out, id...)
	out = append(out, byte(destinationType))
	out = append(out, openWireString(destination)...)
	return out
}

func openWireMessageAck(consumerID uint32) []byte {
	out := []byte{byte(openwireparser.CommandMessageAck)}
	id := make([]byte, 4)
	binary.BigEndian.PutUint32(id, consumerID)
	out = append(out, id...)
	return out
}

func openWireString(v string) []byte {
	out := make([]byte, 2+len(v))
	binary.BigEndian.PutUint16(out[:2], uint16(len(v)))
	copy(out[2:], []byte(v))
	return out
}
