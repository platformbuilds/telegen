// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqp10parser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsAMQP1(t *testing.T) {
	assert.True(t, IsAMQP1(ProtocolHeader))

	attach := buildAMQP10Frame(7, encodePerformative(0x12, list(
		str8("link-orders"),
		smallUint(7),
		boolFalse(),
		null(),
		null(),
		null(),
		terminusTarget("orders.created"),
	)))
	assert.True(t, IsAMQP1(attach))

	truncated := attach[:len(attach)-2]
	assert.False(t, IsAMQP1(truncated))
}

func TestParseFramesPerformatives(t *testing.T) {
	attach := buildAMQP10Frame(7, encodePerformative(0x12, list(
		str8("link-orders"),
		smallUint(7), // handle
		boolFalse(),  // role=sender
		null(),
		null(),
		null(),
		terminusTarget("orders.created"),
	)))
	transfer := buildAMQP10Frame(7, encodePerformative(0x14, list(
		smallUint(7), // handle
		null(),
		null(),
		null(),
		null(),
	)))
	disposition := buildAMQP10Frame(7, encodePerformative(0x15, list(
		boolTrue(), // role=receiver
		smallUint(1),
		smallUint(1),
		boolTrue(),
	)))
	flow := buildAMQP10Frame(7, encodePerformative(0x13, list(
		null(),
		null(),
		null(),
		null(),
		smallUint(7), // handle
	)))
	detach := buildAMQP10Frame(7, encodePerformative(0x16, list(
		smallUint(7),
		boolFalse(),
	)))

	combined := append(append(append(append(append([]byte{}, ProtocolHeader...), attach...), transfer...), disposition...), flow...)
	combined = append(combined, detach...)

	frames, consumed, err := ParseFrames(combined)
	require.NoError(t, err)
	assert.Equal(t, len(combined), consumed)
	require.Len(t, frames, 5)

	assert.Equal(t, PerformativeAttach, frames[0].Performative)
	assert.True(t, frames[0].HasHandle)
	assert.Equal(t, uint32(7), frames[0].Handle)
	assert.True(t, frames[0].HasRole)
	assert.False(t, frames[0].Role)
	assert.Equal(t, "orders.created", frames[0].Address)

	assert.Equal(t, PerformativeTransfer, frames[1].Performative)
	assert.True(t, frames[1].HasHandle)
	assert.Equal(t, uint32(7), frames[1].Handle)

	assert.Equal(t, PerformativeDisposition, frames[2].Performative)
	assert.True(t, frames[2].HasRole)
	assert.True(t, frames[2].Role)

	assert.Equal(t, PerformativeFlow, frames[3].Performative)
	assert.True(t, frames[3].HasHandle)
	assert.Equal(t, uint32(7), frames[3].Handle)

	assert.Equal(t, PerformativeDetach, frames[4].Performative)
	assert.True(t, frames[4].HasHandle)
	assert.Equal(t, uint32(7), frames[4].Handle)
}

func buildAMQP10Frame(channel uint16, body []byte) []byte {
	frameSize := 8 + len(body)
	frame := make([]byte, frameSize)
	binary.BigEndian.PutUint32(frame[0:4], uint32(frameSize))
	frame[4] = 2 // data offset in 4-byte words (8-byte header)
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

func list(values ...[]byte) []byte {
	content := make([]byte, 0, 64)
	for _, v := range values {
		content = append(content, v...)
	}
	size := 1 + len(content) // count-byte + values
	out := []byte{0xc0, byte(size), byte(len(values))}
	out = append(out, content...)
	return out
}

func null() []byte            { return []byte{0x40} }
func boolTrue() []byte        { return []byte{0x41} }
func boolFalse() []byte       { return []byte{0x42} }
func smallUint(v byte) []byte { return []byte{0x52, v} }

func str8(v string) []byte {
	out := []byte{0xa1, byte(len(v))}
	out = append(out, []byte(v)...)
	return out
}

func terminusTarget(address string) []byte {
	return described(0x29, list(str8(address)))
}

func described(code byte, value []byte) []byte {
	out := []byte{0x00, 0x53, code}
	out = append(out, value...)
	return out
}
