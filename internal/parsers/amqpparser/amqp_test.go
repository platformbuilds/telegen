// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAMQPValidatesLengthAndFrameEnd(t *testing.T) {
	valid := methodFrame(1, 60, 40, []byte{0, 0, 0, 0, 0})
	assert.True(t, IsAMQP(valid))

	invalidFrameEnd := append([]byte(nil), valid...)
	invalidFrameEnd[len(invalidFrameEnd)-1] = 0
	assert.False(t, IsAMQP(invalidFrameEnd))

	truncated := valid[:len(valid)-2]
	assert.False(t, IsAMQP(truncated))

	assert.True(t, IsAMQP(AMQPHeader))
}

func TestClassMethodStringIncludesBasicNack(t *testing.T) {
	assert.Equal(t, "basic.nack", (ClassMethod{Class: 60, Method: 120}).String())
}

func methodFrame(channel uint16, class uint16, method uint16, args []byte) []byte {
	payload := make([]byte, 4+len(args))
	binary.BigEndian.PutUint16(payload[0:2], class)
	binary.BigEndian.PutUint16(payload[2:4], method)
	copy(payload[4:], args)

	frame := make([]byte, 7+len(payload)+1)
	frame[0] = FrameMethod
	binary.BigEndian.PutUint16(frame[1:3], channel)
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload)))
	copy(frame[7:], payload)
	frame[len(frame)-1] = FrameEnd
	return frame
}
