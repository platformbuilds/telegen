// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package cqlparser implements CQL v3/v4/v5 frame parsing and stream-ID based
// request/response stitching. CQL is the wire protocol for Apache Cassandra and
// ScyllaDB (default port 9042).
//
// Ported from Pixie's C++ implementation:
// src/stirling/source_connectors/socket_tracer/protocols/cql/
package cqlparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/cqlparser"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// CQL frame header is 9 bytes:
//   version(1) + flags(1) + stream(2) + opcode(1) + length(4)
const HeaderLen = 9

// ErrNeedsMoreData is returned when the buffer does not contain a complete frame.
var ErrNeedsMoreData = errors.New("cql: needs more data")

// Direction represents whether a frame is a request or response.
type Direction int

const (
	DirectionRequest  Direction = iota
	DirectionResponse
)

// Opcode identifies the CQL operation.
type Opcode uint8

const (
	OpcodeError         Opcode = 0x00
	OpcodeStartup       Opcode = 0x01
	OpcodeReady         Opcode = 0x02
	OpcodeAuthenticate  Opcode = 0x03
	OpcodeOptions       Opcode = 0x05
	OpcodeSupported     Opcode = 0x06
	OpcodeQuery         Opcode = 0x07
	OpcodeResult        Opcode = 0x08
	OpcodePrepare       Opcode = 0x09
	OpcodeExecute       Opcode = 0x0A
	OpcodeRegister      Opcode = 0x0B
	OpcodeEvent         Opcode = 0x0C
	OpcodeBatch         Opcode = 0x0D
	OpcodeAuthChallenge Opcode = 0x0E
	OpcodeAuthResponse  Opcode = 0x0F
	OpcodeAuthSuccess   Opcode = 0x10
)

// knownOpcodes is the set of valid CQL opcodes used for detection heuristics.
var knownOpcodes = map[Opcode]bool{
	OpcodeError: true, OpcodeStartup: true, OpcodeReady: true,
	OpcodeAuthenticate: true, OpcodeOptions: true, OpcodeSupported: true,
	OpcodeQuery: true, OpcodeResult: true, OpcodePrepare: true,
	OpcodeExecute: true, OpcodeRegister: true, OpcodeEvent: true,
	OpcodeBatch: true, OpcodeAuthChallenge: true, OpcodeAuthResponse: true,
	OpcodeAuthSuccess: true,
}

// OpcodeName returns a human-readable name for the opcode.
func OpcodeName(op Opcode) string {
	names := map[Opcode]string{
		OpcodeError: "ERROR", OpcodeStartup: "STARTUP", OpcodeReady: "READY",
		OpcodeAuthenticate: "AUTHENTICATE", OpcodeOptions: "OPTIONS",
		OpcodeSupported: "SUPPORTED", OpcodeQuery: "QUERY", OpcodeResult: "RESULT",
		OpcodePrepare: "PREPARE", OpcodeExecute: "EXECUTE", OpcodeRegister: "REGISTER",
		OpcodeEvent: "EVENT", OpcodeBatch: "BATCH", OpcodeAuthChallenge: "AUTH_CHALLENGE",
		OpcodeAuthResponse: "AUTH_RESPONSE", OpcodeAuthSuccess: "AUTH_SUCCESS",
	}
	if name, ok := names[op]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(op))
}

// Frame represents a single CQL protocol frame.
type Frame struct {
	Version   uint8
	Flags     uint8
	StreamID  int16 // negative stream IDs are server-initiated events
	Opcode    Opcode
	Direction Direction
	Body      []byte
	// QueryString is the CQL query text, extracted for QUERY and PREPARE opcodes.
	QueryString string
}

// DecodeFrame decodes one CQL frame from buf.
// Returns the frame, bytes consumed, and any error.
func DecodeFrame(buf []byte) (Frame, int, error) {
	if len(buf) < HeaderLen {
		return Frame{}, 0, ErrNeedsMoreData
	}

	version := buf[0]
	flags := buf[1]
	streamID := int16(binary.BigEndian.Uint16(buf[2:4]))
	opcode := Opcode(buf[4])
	bodyLen := int(binary.BigEndian.Uint32(buf[5:9]))

	// CQL version: high bit indicates response, low 7 bits are version number.
	dir := DirectionRequest
	if version&0x80 != 0 {
		dir = DirectionResponse
	}
	protoVersion := version & 0x7F

	// Pixie supports v3–v5. v1/v2 are obsolete; reject to avoid false positives.
	if protoVersion < 3 || protoVersion > 5 {
		return Frame{}, 0, fmt.Errorf("cql: unsupported protocol version %d", protoVersion)
	}

	if !knownOpcodes[opcode] {
		return Frame{}, 0, fmt.Errorf("cql: unknown opcode 0x%02x", uint8(opcode))
	}

	total := HeaderLen + bodyLen
	if len(buf) < total {
		return Frame{}, 0, ErrNeedsMoreData
	}

	body := buf[HeaderLen:total]
	f := Frame{
		Version:   protoVersion,
		Flags:     flags,
		StreamID:  streamID,
		Opcode:    opcode,
		Direction: dir,
		Body:      body,
	}

	// Extract query string from QUERY and PREPARE frames.
	if (opcode == OpcodeQuery || opcode == OpcodePrepare) && len(body) >= 4 {
		qLen := int(binary.BigEndian.Uint32(body[0:4]))
		if qLen >= 0 && 4+qLen <= len(body) {
			f.QueryString = string(body[4 : 4+qLen])
		}
	}

	return f, total, nil
}

// ParseFrames decodes all complete CQL frames from buf.
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

// Record is a matched CQL request/response pair.
type Record struct {
	StreamID int16
	Request  Frame
	Response Frame
}

// StitchFrames matches CQL frames by their stream ID.
// CQL allows concurrent inflight requests on a single connection (like HTTP/2),
// each identified by a stream ID. This mirrors Pixie's cql::StitchFrames.
func StitchFrames(allFrames []Frame) []Record {
	type reqEntry struct {
		frame Frame
		used  bool
	}
	pending := make(map[int16]*reqEntry)
	var records []Record

	for _, f := range allFrames {
		if f.Direction == DirectionRequest {
			pending[f.StreamID] = &reqEntry{frame: f}
		} else {
			if entry, ok := pending[f.StreamID]; ok && !entry.used {
				entry.used = true
				records = append(records, Record{
					StreamID: f.StreamID,
					Request:  entry.frame,
					Response: f,
				})
			} else {
				// Server-pushed event (stream < 0) or unmatched response.
				records = append(records, Record{StreamID: f.StreamID, Response: f})
			}
		}
	}

	return records
}

// IsCQL returns true if buf looks like a CQL v3–v5 frame.
// Checks version byte and opcode for validity, mirroring Pixie's infer_cql_message.
func IsCQL(buf []byte) bool {
	if len(buf) < HeaderLen {
		return false
	}
	version := buf[0] & 0x7F
	if version < 3 || version > 5 {
		return false
	}
	opcode := Opcode(buf[4])
	return knownOpcodes[opcode]
}
