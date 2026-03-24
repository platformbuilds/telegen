// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package amqpparser implements AMQP 0-9-1 frame parsing and request/response
// stitching. The protocol is used by RabbitMQ and any broker implementing
// the AMQP 0-9-1 specification.
//
// Ported from Pixie's C++ implementation:
// src/stirling/source_connectors/socket_tracer/protocols/amqp/
package amqpparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/amqpparser"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// AMQP 0-9-1 frame types.
const (
	FrameMethod    uint8 = 1
	FrameHeader    uint8 = 2
	FrameBody      uint8 = 3
	FrameHeartbeat uint8 = 8
	FrameEnd       uint8 = 0xCE // 206
)

// Minimum frame size: type(1) + channel(2) + size(4) + frame-end(1) = 8 bytes.
const MinFrameLen = 8

// AMQP connection header that clients send on connect: "AMQP\x00\x00\x09\x01".
var AMQPHeader = []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}

// ClassMethod encodes an AMQP class-id + method-id pair for human-readable naming.
type ClassMethod struct {
	Class  uint16
	Method uint16
}

// String returns a human-readable "class.method" label.
func (cm ClassMethod) String() string {
	names := map[ClassMethod]string{
		{10, 10}: "connection.start",
		{10, 11}: "connection.start-ok",
		{10, 20}: "connection.secure",
		{10, 21}: "connection.secure-ok",
		{10, 30}: "connection.tune",
		{10, 31}: "connection.tune-ok",
		{10, 40}: "connection.open",
		{10, 41}: "connection.open-ok",
		{10, 50}: "connection.close",
		{10, 51}: "connection.close-ok",
		{20, 10}: "channel.open",
		{20, 11}: "channel.open-ok",
		{20, 20}: "channel.flow",
		{20, 21}: "channel.flow-ok",
		{20, 40}: "channel.close",
		{20, 41}: "channel.close-ok",
		{40, 10}: "exchange.declare",
		{40, 11}: "exchange.declare-ok",
		{40, 20}: "exchange.delete",
		{40, 21}: "exchange.delete-ok",
		{40, 30}: "exchange.bind",
		{40, 31}: "exchange.bind-ok",
		{40, 40}: "exchange.unbind",
		{40, 51}: "exchange.unbind-ok",
		{50, 10}: "queue.declare",
		{50, 11}: "queue.declare-ok",
		{50, 20}: "queue.bind",
		{50, 21}: "queue.bind-ok",
		{50, 30}: "queue.purge",
		{50, 31}: "queue.purge-ok",
		{50, 40}: "queue.delete",
		{50, 41}: "queue.delete-ok",
		{50, 50}: "queue.unbind",
		{50, 51}: "queue.unbind-ok",
		{60, 10}: "basic.qos",
		{60, 11}: "basic.qos-ok",
		{60, 20}: "basic.consume",
		{60, 21}: "basic.consume-ok",
		{60, 30}: "basic.cancel",
		{60, 31}: "basic.cancel-ok",
		{60, 40}: "basic.publish",
		{60, 50}: "basic.return",
		{60, 60}: "basic.deliver",
		{60, 70}: "basic.get",
		{60, 71}: "basic.get-ok",
		{60, 72}: "basic.get-empty",
		{60, 80}: "basic.ack",
		{60, 90}: "basic.reject",
		{60, 100}: "basic.recover-async",
		{60, 110}: "basic.recover",
		{60, 111}: "basic.recover-ok",
		{90, 10}: "tx.select",
		{90, 11}: "tx.select-ok",
		{90, 20}: "tx.commit",
		{90, 21}: "tx.commit-ok",
		{90, 30}: "tx.rollback",
		{90, 31}: "tx.rollback-ok",
	}
	if name, ok := names[cm]; ok {
		return name
	}
	return fmt.Sprintf("class%d.method%d", cm.Class, cm.Method)
}

// isSynchronous returns true if the method requires a corresponding response on
// the same channel. Async methods (basic.publish, basic.deliver, etc.) are emitted
// immediately as one-sided records.
func (cm ClassMethod) isSynchronous() bool {
	asyncMethods := map[ClassMethod]bool{
		{60, 40}: true, // basic.publish
		{60, 50}: true, // basic.return
		{60, 60}: true, // basic.deliver
		{60, 80}: true, // basic.ack
		{60, 90}: true, // basic.reject
		{60, 100}: true, // basic.recover-async
	}
	return !asyncMethods[cm]
}

// Frame represents a parsed AMQP 0-9-1 frame.
type Frame struct {
	Type       uint8
	Channel    uint16
	Method     ClassMethod // valid only when Type == FrameMethod
	Payload    []byte
	Synchronous bool
}

// Record is a matched request/response pair (or a one-sided async frame).
type Record struct {
	Request  Frame
	Response Frame
}

// DecodeFrame attempts to decode one AMQP frame from buf.
// Returns the decoded Frame, the number of bytes consumed, and any error.
// Returns (Frame{}, 0, ErrNeedsMoreData) if the buffer is too short.
func DecodeFrame(buf []byte) (Frame, int, error) {
	if len(buf) < MinFrameLen {
		return Frame{}, 0, ErrNeedsMoreData
	}

	frameType := buf[0]
	channel := binary.BigEndian.Uint16(buf[1:3])
	payloadSize := binary.BigEndian.Uint32(buf[3:7])
	totalSize := int(7 + payloadSize + 1) // header + payload + frame-end

	if len(buf) < totalSize {
		return Frame{}, 0, ErrNeedsMoreData
	}
	if buf[totalSize-1] != FrameEnd {
		return Frame{}, 0, fmt.Errorf("amqp: invalid frame-end byte 0x%x", buf[totalSize-1])
	}

	payload := buf[7 : 7+payloadSize]
	frame := Frame{
		Type:    frameType,
		Channel: channel,
		Payload: payload,
	}

	if frameType == FrameMethod && len(payload) >= 4 {
		cm := ClassMethod{
			Class:  binary.BigEndian.Uint16(payload[0:2]),
			Method: binary.BigEndian.Uint16(payload[2:4]),
		}
		frame.Method = cm
		frame.Synchronous = cm.isSynchronous()
	}

	return frame, totalSize, nil
}

// ParseFrames decodes all complete AMQP frames from buf.
// Partial frames at the end are silently ignored (caller should retain the remainder).
func ParseFrames(buf []byte) ([]Frame, int, error) {
	var frames []Frame
	consumed := 0
	for len(buf) > 0 {
		f, n, err := DecodeFrame(buf)
		if errors.Is(err, ErrNeedsMoreData) {
			break
		}
		if err != nil {
			return frames, consumed, err
		}
		frames = append(frames, f)
		buf = buf[n:]
		consumed += n
	}
	return frames, consumed, nil
}

// ErrNeedsMoreData is returned when the buffer does not contain a complete frame.
var ErrNeedsMoreData = errors.New("amqp: needs more data")

// StitchFrames matches request frames to response frames by channel, following
// AMQP's channel-ordered synchronous semantics. Async frames are returned as
// one-sided records immediately.
//
// This mirrors Pixie's amqp::StitchFrames in protocols/amqp/stitcher.cc.
func StitchFrames(reqFrames, respFrames []Frame) []Record {
	var records []Record

	// Map channel → pending synchronous request queue.
	pending := make(map[uint16][]Frame)

	for _, req := range reqFrames {
		if !req.Synchronous {
			// Async: emit immediately as a one-sided record.
			records = append(records, Record{Request: req})
			continue
		}
		pending[req.Channel] = append(pending[req.Channel], req)
	}

	for _, resp := range respFrames {
		if !resp.Synchronous {
			records = append(records, Record{Response: resp})
			continue
		}
		// In AMQP the server can send first (ConnectionStart, ConnectionTune).
		// If no pending request exists, emit as server-initiated one-sided record.
		queue := pending[resp.Channel]
		if len(queue) == 0 {
			records = append(records, Record{Response: resp})
			continue
		}
		req := queue[0]
		pending[resp.Channel] = queue[1:]
		records = append(records, Record{Request: req, Response: resp})
	}

	return records
}

// IsAMQP returns true if buf starts with the AMQP 0-9-1 protocol header or
// a valid AMQP frame type byte, which is a reliable fingerprint.
func IsAMQP(buf []byte) bool {
	if len(buf) >= len(AMQPHeader) {
		if string(buf[:len(AMQPHeader)]) == string(AMQPHeader) {
			return true
		}
	}
	if len(buf) >= MinFrameLen {
		ft := buf[0]
		return ft == FrameMethod || ft == FrameHeader || ft == FrameBody || ft == FrameHeartbeat
	}
	return false
}
