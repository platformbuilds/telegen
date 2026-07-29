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
	"github.com/mirastacklabs-ai/telegen/internal/parsers/amqp10parser"
)

func TestProcessPossibleAMQP10EventAttachAndTransferLookup(t *testing.T) {
	cache, err := lru.NewLRU[amqp10LinkKey, string](32, nil)
	require.NoError(t, err)

	conn := newTestConnInfo()
	attachEvent := &TCPRequestInfo{ConnInfo: conn, Direction: directionSend}
	transferEvent := &TCPRequestInfo{
		ConnInfo: BpfConnectionInfoT{
			S_addr: conn.D_addr,
			D_addr: conn.S_addr,
			S_port: conn.D_port,
			D_port: conn.S_port,
		},
		Direction: directionSend,
	}

	attachFrame := buildAMQP10Frame(5, encodePerformative(0x12, amqp10List(
		amqp10Str8("link-orders"),
		amqp10SmallUint(5), // handle
		amqp10BoolFalse(),  // role=false (sender)
		amqp10Null(),
		amqp10Null(),
		amqp10Null(),
		amqp10TerminusTarget("orders.created"),
	)))
	span, outcome, err := ProcessPossibleAMQP10Event(attachEvent, attachFrame, nil, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.MessagingCreate, span.Method)
	assert.Equal(t, "orders.created", span.Path)
	require.NotNil(t, span.MessagingInfo)
	assert.Equal(t, "amqp1.attach", span.MessagingInfo.OperationName)

	transferFrame := buildAMQP10Frame(5, encodePerformative(0x14, amqp10List(
		amqp10SmallUint(5), // handle
		amqp10Null(),
		amqp10Null(),
		amqp10Null(),
		amqp10Null(),
	)))
	span, outcome, err = ProcessPossibleAMQP10Event(transferEvent, transferFrame, nil, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "orders.created", span.Path)
}

func TestProcessPossibleAMQP10EventResponseTransferIsReceiveServerSpan(t *testing.T) {
	event := &TCPRequestInfo{ConnInfo: newTestConnInfo(), Direction: directionSend}
	cache, err := lru.NewLRU[amqp10LinkKey, string](32, nil)
	require.NoError(t, err)

	respFrame := buildAMQP10Frame(7, encodePerformative(0x14, amqp10List(
		amqp10SmallUint(7),
		amqp10Null(),
		amqp10Null(),
		amqp10Null(),
		amqp10Null(),
	)))
	span, outcome, err := ProcessPossibleAMQP10Event(event, nil, respFrame, cache)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.EventTypeAMQPServer, span.Type)
	assert.Equal(t, request.MessagingReceive, span.Method)
	require.NotNil(t, span.MessagingInfo)
	assert.Equal(t, "amqp1.transfer", span.MessagingInfo.OperationName)
}

func TestIsAMQP1Wrapper(t *testing.T) {
	assert.True(t, isAMQP1(amqp10parser.ProtocolHeader))
}

func buildAMQP10Frame(channel uint16, body []byte) []byte {
	frameSize := 8 + len(body)
	frame := make([]byte, frameSize)
	binary.BigEndian.PutUint32(frame[0:4], uint32(frameSize))
	frame[4] = 2 // data offset in 4-byte words
	frame[5] = 0 // AMQP frame type
	binary.BigEndian.PutUint16(frame[6:8], channel)
	copy(frame[8:], body)
	return frame
}

func encodePerformative(code byte, listValue []byte) []byte {
	out := []byte{0x00, 0x53, code}
	out = append(out, listValue...)
	return out
}

func amqp10List(values ...[]byte) []byte {
	content := make([]byte, 0, 64)
	for _, v := range values {
		content = append(content, v...)
	}
	size := 1 + len(content)
	out := []byte{0xc0, byte(size), byte(len(values))}
	out = append(out, content...)
	return out
}

func amqp10Null() []byte      { return []byte{0x40} }
func amqp10BoolFalse() []byte { return []byte{0x42} }
func amqp10SmallUint(v byte) []byte {
	return []byte{0x52, v}
}

func amqp10Str8(v string) []byte {
	out := []byte{0xa1, byte(len(v))}
	out = append(out, []byte(v)...)
	return out
}

func amqp10TerminusTarget(address string) []byte {
	return amqp10Described(0x29, amqp10List(amqp10Str8(address)))
}

func amqp10Described(code byte, value []byte) []byte {
	out := []byte{0x00, 0x53, code}
	out = append(out, value...)
	return out
}
