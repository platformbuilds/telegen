// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package amqp10parser implements minimal AMQP 1.0 frame parsing for telemetry.
package amqp10parser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/amqp10parser"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// ErrNeedsMoreData indicates a truncated AMQP 1.0 frame.
	ErrNeedsMoreData = errors.New("amqp1: needs more data")
	// ProtocolHeader is the AMQP 1.0 protocol preface.
	ProtocolHeader = []byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0}
)

type PerformativeType uint8

const (
	PerformativeUnknown PerformativeType = iota
	PerformativeAttach
	PerformativeFlow
	PerformativeTransfer
	PerformativeDisposition
	PerformativeDetach
)

type Frame struct {
	Channel      uint16
	Performative PerformativeType
	Handle       uint32
	HasHandle    bool
	Role         bool
	HasRole      bool
	Address      string
}

type valueKind uint8

const (
	valueNull valueKind = iota
	valueBool
	valueUint
	valueString
	valueList
	valueDescribed
)

type amqpValue struct {
	kind  valueKind
	u64   uint64
	b     bool
	s     string
	desc  uint64
	child *amqpValue
	list  []amqpValue
}

func IsAMQP1(buf []byte) bool {
	if len(buf) >= len(ProtocolHeader) && bytes.Equal(buf[:len(ProtocolHeader)], ProtocolHeader) {
		return true
	}

	if len(buf) < 8 {
		return false
	}

	size := binary.BigEndian.Uint32(buf[0:4])
	doff := int(buf[4]) * 4
	if size < 8 || doff < 8 || int(size) > len(buf) {
		return false
	}

	frameType := buf[5]
	if frameType != 0 && frameType != 1 {
		return false
	}

	body := buf[doff:int(size)]
	descriptor, ok := readPerformativeDescriptor(body)
	if !ok {
		return false
	}
	return descriptor >= 0x12 && descriptor <= 0x16
}

func ParseFrames(buf []byte) ([]Frame, int, error) {
	frames := make([]Frame, 0, 4)
	consumed := 0

	for len(buf) > 0 {
		if len(buf) >= len(ProtocolHeader) && bytes.Equal(buf[:len(ProtocolHeader)], ProtocolHeader) {
			buf = buf[len(ProtocolHeader):]
			consumed += len(ProtocolHeader)
			continue
		}

		frame, n, err := DecodeFrame(buf)
		if errors.Is(err, ErrNeedsMoreData) {
			break
		}
		if err != nil {
			return frames, consumed, err
		}
		frames = append(frames, frame)
		buf = buf[n:]
		consumed += n
	}

	return frames, consumed, nil
}

func DecodeFrame(buf []byte) (Frame, int, error) {
	if len(buf) < 8 {
		return Frame{}, 0, ErrNeedsMoreData
	}

	size := binary.BigEndian.Uint32(buf[0:4])
	doff := int(buf[4]) * 4
	if size < 8 {
		return Frame{}, 0, fmt.Errorf("amqp1: invalid frame size %d", size)
	}
	if doff < 8 {
		return Frame{}, 0, fmt.Errorf("amqp1: invalid data offset %d", doff)
	}
	if int(size) < doff {
		return Frame{}, 0, fmt.Errorf("amqp1: data offset %d exceeds frame size %d", doff, size)
	}
	if len(buf) < int(size) {
		return Frame{}, 0, ErrNeedsMoreData
	}

	frameType := buf[5]
	if frameType != 0 && frameType != 1 {
		return Frame{}, 0, fmt.Errorf("amqp1: unsupported frame type %d", frameType)
	}

	channel := binary.BigEndian.Uint16(buf[6:8])
	body := buf[doff:int(size)]

	frame := Frame{
		Channel: channel,
	}
	if len(body) == 0 {
		return frame, int(size), nil
	}

	perf, err := decodePerformative(body)
	if err != nil {
		return Frame{}, 0, err
	}
	frame = perf
	frame.Channel = channel
	return frame, int(size), nil
}

func decodePerformative(body []byte) (Frame, error) {
	desc, off, err := parseDescriptor(body, 0)
	if err != nil {
		return Frame{}, err
	}

	listValue, _, err := parseValue(body, off)
	if err != nil {
		return Frame{}, err
	}
	if listValue.kind != valueList {
		return Frame{}, fmt.Errorf("amqp1: performative descriptor 0x%x has non-list body", desc)
	}

	switch desc {
	case 0x12: // attach
		return parseAttach(listValue.list), nil
	case 0x13: // flow
		return parseFlow(listValue.list), nil
	case 0x14: // transfer
		return parseTransfer(listValue.list), nil
	case 0x15: // disposition
		return parseDisposition(listValue.list), nil
	case 0x16: // detach
		return parseDetach(listValue.list), nil
	default:
		return Frame{Performative: PerformativeUnknown}, nil
	}
}

func parseAttach(fields []amqpValue) Frame {
	frame := Frame{Performative: PerformativeAttach}
	if v, ok := getFieldUint(fields, 1); ok {
		frame.Handle = uint32(v)
		frame.HasHandle = true
	}
	if role, ok := getFieldBool(fields, 2); ok {
		frame.Role = role
		frame.HasRole = true
	}

	sourceAddress := getTerminusAddress(getField(fields, 5))
	targetAddress := getTerminusAddress(getField(fields, 6))
	if frame.HasRole && frame.Role {
		// Role=true => receiver link endpoint; source maps to consumed address.
		frame.Address = sourceAddress
		if frame.Address == "" {
			frame.Address = targetAddress
		}
	} else {
		// Role=false => sender link endpoint; target maps to produced address.
		frame.Address = targetAddress
		if frame.Address == "" {
			frame.Address = sourceAddress
		}
	}
	return frame
}

func parseTransfer(fields []amqpValue) Frame {
	frame := Frame{Performative: PerformativeTransfer}
	if v, ok := getFieldUint(fields, 0); ok {
		frame.Handle = uint32(v)
		frame.HasHandle = true
	}
	return frame
}

func parseDisposition(fields []amqpValue) Frame {
	frame := Frame{Performative: PerformativeDisposition}
	if role, ok := getFieldBool(fields, 0); ok {
		frame.Role = role
		frame.HasRole = true
	}
	return frame
}

func parseFlow(fields []amqpValue) Frame {
	frame := Frame{Performative: PerformativeFlow}
	if v, ok := getFieldUint(fields, 4); ok {
		frame.Handle = uint32(v)
		frame.HasHandle = true
	}
	return frame
}

func parseDetach(fields []amqpValue) Frame {
	frame := Frame{Performative: PerformativeDetach}
	if v, ok := getFieldUint(fields, 0); ok {
		frame.Handle = uint32(v)
		frame.HasHandle = true
	}
	return frame
}

func readPerformativeDescriptor(body []byte) (uint64, bool) {
	desc, _, err := parseDescriptor(body, 0)
	if err != nil {
		return 0, false
	}
	return desc, true
}

func parseDescriptor(buf []byte, off int) (uint64, int, error) {
	if off >= len(buf) || buf[off] != 0x00 {
		return 0, off, errors.New("amqp1: expected described type marker")
	}
	descValue, next, err := parseValue(buf, off+1)
	if err != nil {
		return 0, off, err
	}
	if descValue.kind != valueUint {
		return 0, off, errors.New("amqp1: descriptor is not unsigned integer")
	}
	return descValue.u64, next, nil
}

func parseValue(buf []byte, off int) (amqpValue, int, error) {
	if off >= len(buf) {
		return amqpValue{}, off, ErrNeedsMoreData
	}

	marker := buf[off]
	off++
	switch marker {
	case 0x40: // null
		return amqpValue{kind: valueNull}, off, nil
	case 0x41: // true
		return amqpValue{kind: valueBool, b: true}, off, nil
	case 0x42: // false
		return amqpValue{kind: valueBool, b: false}, off, nil
	case 0x56: // boolean with explicit byte
		if off >= len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		return amqpValue{kind: valueBool, b: buf[off] == 1}, off + 1, nil
	case 0x43: // uint0
		return amqpValue{kind: valueUint, u64: 0}, off, nil
	case 0x52: // smalluint
		if off >= len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		return amqpValue{kind: valueUint, u64: uint64(buf[off])}, off + 1, nil
	case 0x70: // uint
		if off+4 > len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		return amqpValue{kind: valueUint, u64: uint64(binary.BigEndian.Uint32(buf[off : off+4]))}, off + 4, nil
	case 0x44: // ulong0
		return amqpValue{kind: valueUint, u64: 0}, off, nil
	case 0x53: // smallulong
		if off >= len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		return amqpValue{kind: valueUint, u64: uint64(buf[off])}, off + 1, nil
	case 0x80: // ulong
		if off+8 > len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		return amqpValue{kind: valueUint, u64: binary.BigEndian.Uint64(buf[off : off+8])}, off + 8, nil
	case 0xa1: // str8-utf8
		if off >= len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		n := int(buf[off])
		off++
		if off+n > len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		return amqpValue{kind: valueString, s: string(buf[off : off+n])}, off + n, nil
	case 0xb1: // str32-utf8
		if off+4 > len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		n := int(binary.BigEndian.Uint32(buf[off : off+4]))
		off += 4
		if off+n > len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		return amqpValue{kind: valueString, s: string(buf[off : off+n])}, off + n, nil
	case 0x45: // list0
		return amqpValue{kind: valueList, list: []amqpValue{}}, off, nil
	case 0xc0: // list8
		if off+2 > len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		size := int(buf[off])
		count := int(buf[off+1])
		off += 2
		if off+(size-1) > len(buf) || size < 1 {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		end := off + size - 1
		values := make([]amqpValue, 0, count)
		for i := 0; i < count; i++ {
			v, next, err := parseValue(buf, off)
			if err != nil {
				return amqpValue{}, off, err
			}
			values = append(values, v)
			off = next
			if off > end {
				return amqpValue{}, off, errors.New("amqp1: list8 value overflow")
			}
		}
		return amqpValue{kind: valueList, list: values}, end, nil
	case 0xd0: // list32
		if off+8 > len(buf) {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		size := int(binary.BigEndian.Uint32(buf[off : off+4]))
		count := int(binary.BigEndian.Uint32(buf[off+4 : off+8]))
		off += 8
		if off+(size-4) > len(buf) || size < 4 {
			return amqpValue{}, off, ErrNeedsMoreData
		}
		end := off + size - 4
		values := make([]amqpValue, 0, count)
		for i := 0; i < count; i++ {
			v, next, err := parseValue(buf, off)
			if err != nil {
				return amqpValue{}, off, err
			}
			values = append(values, v)
			off = next
			if off > end {
				return amqpValue{}, off, errors.New("amqp1: list32 value overflow")
			}
		}
		return amqpValue{kind: valueList, list: values}, end, nil
	case 0x00: // described type
		descValue, next, err := parseValue(buf, off)
		if err != nil {
			return amqpValue{}, off, err
		}
		if descValue.kind != valueUint {
			return amqpValue{}, off, errors.New("amqp1: described descriptor is not unsigned integer")
		}
		child, next, err := parseValue(buf, next)
		if err != nil {
			return amqpValue{}, off, err
		}
		return amqpValue{kind: valueDescribed, desc: descValue.u64, child: &child}, next, nil
	default:
		return amqpValue{}, off, fmt.Errorf("amqp1: unsupported type marker 0x%x", marker)
	}
}

func getField(fields []amqpValue, idx int) *amqpValue {
	if idx < 0 || idx >= len(fields) {
		return nil
	}
	return &fields[idx]
}

func getFieldUint(fields []amqpValue, idx int) (uint64, bool) {
	v := getField(fields, idx)
	if v == nil || v.kind != valueUint {
		return 0, false
	}
	return v.u64, true
}

func getFieldBool(fields []amqpValue, idx int) (bool, bool) {
	v := getField(fields, idx)
	if v == nil || v.kind != valueBool {
		return false, false
	}
	return v.b, true
}

func getTerminusAddress(v *amqpValue) string {
	if v == nil || v.kind != valueDescribed || v.child == nil {
		return ""
	}
	if v.desc != 0x28 && v.desc != 0x29 { // source / target
		return ""
	}
	if v.child.kind != valueList || len(v.child.list) == 0 {
		return ""
	}
	if v.child.list[0].kind != valueString {
		return ""
	}
	return v.child.list[0].s
}
