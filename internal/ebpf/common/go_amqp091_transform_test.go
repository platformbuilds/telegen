// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
)

func TestAMQP091OperationName(t *testing.T) {
	assert.Equal(t, request.MessagingPublish, amqp091OperationName(goAMQP091OpPublish))
	assert.Equal(t, request.MessagingProcess, amqp091OperationName(goAMQP091OpProcess))
	assert.Equal(t, request.MessagingSettle, amqp091OperationName(goAMQP091OpSettle))
	assert.Equal(t, request.MessagingCreate, amqp091OperationName(goAMQP091OpCreate))
	assert.Equal(t, "unknown", amqp091OperationName(99))
}

func TestReadGoAMQP091RequestIntoSpan(t *testing.T) {
	event := GoAMQP091ClientInfo{
		Type:            EventTypeGoAMQP091,
		Op:              goAMQP091OpPublish,
		StartMonotimeNs: 100,
		EndMonotimeNs:   250,
	}
	event.Tp.TraceId = [16]uint8{1, 2, 3}
	event.Tp.SpanId = [8]uint8{4, 5, 6}
	event.Tp.ParentId = [8]uint8{7, 8, 9}
	event.Tp.Flags = 1
	event.Pid.HostPid = 42
	event.Pid.UserPid = 43
	event.Pid.Ns = 44
	copy(event.Topic[:], []byte("orders.created"))

	record := &ringbuf.Record{RawSample: eventToRawSample(event)}
	span, ignore, err := ReadGoAMQP091RequestIntoSpan(record)
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, request.EventTypeAMQPClient, span.Type)
	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "orders.created", span.Path)
	assert.Equal(t, goAMQPClientStatement, span.Statement)
	assert.Equal(t, int64(100), span.Start)
	assert.Equal(t, int64(250), span.End)
	assert.Equal(t, uint32(42), span.Pid.HostPID)
	assert.Equal(t, uint32(43), span.Pid.UserPID)
	assert.Equal(t, uint32(44), span.Pid.Namespace)
	assert.Equal(t, uint8(1), span.TraceFlags)
}

func TestGoAMQP091ToSpanMapsSettle(t *testing.T) {
	event := &GoAMQP091ClientInfo{Op: goAMQP091OpSettle}
	span := GoAMQP091ToSpan(event)
	assert.Equal(t, request.MessagingSettle, span.Method)
}

func eventToRawSample(event GoAMQP091ClientInfo) []byte {
	size := int(unsafe.Sizeof(event))
	raw := make([]byte, size)
	src := unsafe.Slice((*byte)(unsafe.Pointer(&event)), size)
	copy(raw, src)
	return raw
}
