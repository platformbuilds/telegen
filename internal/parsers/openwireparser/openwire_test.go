// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package openwireparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsOpenWire(t *testing.T) {
	wireFormat := buildWireFormatInfo("ActiveMQ-OpenWire")
	assert.True(t, IsOpenWire(wireFormat))

	producer := buildProducerInfo(7, DestinationQueue, "orders.queue")
	assert.True(t, IsOpenWire(producer))

	assert.False(t, IsOpenWire([]byte{0xff, 0x01, 0x02}))
}

func TestParseCommands(t *testing.T) {
	wireFormat := buildWireFormatInfo("ActiveMQ-OpenWire")
	producer := buildProducerInfo(7, DestinationQueue, "orders.queue")
	consumer := buildConsumerInfo(9, DestinationTopic, "orders.topic")
	msg := buildMessage(7, DestinationQueue, "orders.queue")
	ack := buildMessageAck(9)

	stream := append(append(append(append(wireFormat, producer...), consumer...), msg...), ack...)
	commands, consumed, err := ParseCommands(stream)
	require.NoError(t, err)
	assert.Equal(t, len(stream), consumed)
	require.Len(t, commands, 5)

	assert.Equal(t, CommandWireFormatInfo, commands[0].Type)
	assert.Equal(t, CommandProducerInfo, commands[1].Type)
	assert.Equal(t, uint32(7), commands[1].ProducerID)
	assert.Equal(t, DestinationQueue, commands[1].DestinationType)
	assert.Equal(t, "orders.queue", commands[1].Destination)

	assert.Equal(t, CommandConsumerInfo, commands[2].Type)
	assert.Equal(t, uint32(9), commands[2].ConsumerID)
	assert.Equal(t, DestinationTopic, commands[2].DestinationType)
	assert.Equal(t, "orders.topic", commands[2].Destination)

	assert.Equal(t, CommandMessage, commands[3].Type)
	assert.Equal(t, uint32(7), commands[3].ProducerID)
	assert.Equal(t, "orders.queue", commands[3].Destination)

	assert.Equal(t, CommandMessageAck, commands[4].Type)
	assert.Equal(t, uint32(9), commands[4].ConsumerID)
}

func buildWireFormatInfo(name string) []byte {
	out := []byte{byte(CommandWireFormatInfo)}
	out = append(out, encodeString(name)...)
	return out
}

func buildProducerInfo(producerID uint32, destType DestinationType, destination string) []byte {
	out := []byte{byte(CommandProducerInfo)}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, producerID)
	out = append(out, buf...)
	out = append(out, byte(destType))
	out = append(out, encodeString(destination)...)
	return out
}

func buildConsumerInfo(consumerID uint32, destType DestinationType, destination string) []byte {
	out := []byte{byte(CommandConsumerInfo)}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, consumerID)
	out = append(out, buf...)
	out = append(out, byte(destType))
	out = append(out, encodeString(destination)...)
	return out
}

func buildMessage(producerID uint32, destType DestinationType, destination string) []byte {
	out := []byte{byte(CommandMessage)}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, producerID)
	out = append(out, buf...)
	out = append(out, byte(destType))
	out = append(out, encodeString(destination)...)
	return out
}

func buildMessageAck(consumerID uint32) []byte {
	out := []byte{byte(CommandMessageAck)}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, consumerID)
	out = append(out, buf...)
	return out
}

func encodeString(v string) []byte {
	out := make([]byte, 2+len(v))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(v)))
	copy(out[2:], []byte(v))
	return out
}
