// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package fdbparser implements the FoundationDB client-cluster binary protocol
// parser. FoundationDB communicates on port 4500 using a custom length-prefixed
// binary framing with a fixed 4-byte connect magic (0x42 0xAB 0xBA 0xFF little-endian,
// appearing on wire as 0xFF 0xBA 0xAB 0x42) at the start of the connection.
//
// Reference: https://github.com/apple/foundationdb/blob/main/fdbrpc/FlowTransport.actor.cpp
// Flow transport: https://github.com/apple/foundationdb/blob/main/fdbrpc/README.md
package fdbparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/fdbparser"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNeedsMoreData is returned when the buffer is too short for a complete packet.
var ErrNeedsMoreData = errors.New("foundationdb: needs more data")

// ConnectPacketMagic is the 4-byte little-endian magic at the start of every
// new FDB connection. On the wire: 0xFF 0xBA 0xAB 0x42 (= 0x42ABBAFFu LE).
var ConnectPacketMagic = [4]byte{0xFF, 0xBA, 0xAB, 0x42}

// ConnectPacketLen is the full size of the FDB connect (handshake) packet.
// connectPacketLength(4) + protocolVersion(8) + connectionID(8) + clientIsLocalAddress(1) +
// canonicalRemotePort(4) + localAddressType(1) + localAddress(16) + localPort(4) = ~46 bytes.
const ConnectPacketMinLen = 28

// PacketHeaderLen is the overhead for a regular (non-connect) FDB packet header.
// token(8) + checkSum(4) + totalLen(4) + payload
const PacketHeaderLen = 16

// FrameType classifies an FDB frame.
type FrameType int

const (
	FrameConnect FrameType = iota // initial handshake
	FrameData                     // regular data frame
)

// WellKnownToken values used by FDB Flow protocol.
const (
	TokenUnset     uint64 = 0
	TokenReserved  uint64 = 1
	TokenEndpoint  uint64 = 2
)

// Packet holds a decoded FDB protocol packet.
type Packet struct {
	Type           FrameType
	// Connect packet fields
	ProtocolVersion uint64
	ConnectPacketLen uint32
	// Data packet fields
	Token    uint64
	Checksum uint32
	// Size of the payload portion (after the 16-byte header)
	PayloadLen uint32
	// Sequence is used to track request-response ordering (best-effort for FDB).
	Sequence uint32
	// StatusCode: 0 = OK, 1 = error (heuristic based on token/payload).
	StatusCode int
}

// DecodeConnectPacket decodes the FDB connect packet from buf.
// The first 4 bytes must be ConnectPacketMagic.
func DecodeConnectPacket(buf []byte) (Packet, int, error) {
	if len(buf) < 8 {
		return Packet{}, 0, ErrNeedsMoreData
	}
	if [4]byte(buf[0:4]) != ConnectPacketMagic {
		return Packet{}, 0, fmt.Errorf("foundationdb: connect packet magic mismatch")
	}
	// connectPacketLength(4) after magic
	cpLen := binary.LittleEndian.Uint32(buf[4:8])
	if cpLen == 0 || cpLen > 4096 {
		return Packet{}, 0, fmt.Errorf("foundationdb: implausible connect packet length %d", cpLen)
	}
	total := int(8 + cpLen)
	if len(buf) < total {
		return Packet{}, 0, ErrNeedsMoreData
	}
	pv := uint64(0)
	if len(buf) >= 16 {
		pv = binary.LittleEndian.Uint64(buf[8:16])
	}
	return Packet{
		Type:             FrameConnect,
		ProtocolVersion:  pv,
		ConnectPacketLen: cpLen,
	}, total, nil
}

// DecodeDataPacket decodes a regular FDB data frame (non-connect).
// FDB data frames: token(8) + checksum(4) + totalLen(4) + payload(totalLen - 16).
func DecodeDataPacket(buf []byte) (Packet, int, error) {
	if len(buf) < PacketHeaderLen {
		return Packet{}, 0, ErrNeedsMoreData
	}
	token := binary.LittleEndian.Uint64(buf[0:8])
	checksum := binary.LittleEndian.Uint32(buf[8:12])
	totalLen := binary.LittleEndian.Uint32(buf[12:16])

	if totalLen < uint32(PacketHeaderLen) || totalLen > 64*1024*1024 {
		return Packet{}, 0, fmt.Errorf("foundationdb: implausible frame length %d", totalLen)
	}
	payloadLen := totalLen - uint32(PacketHeaderLen)
	if uint32(len(buf)) < totalLen {
		return Packet{}, 0, ErrNeedsMoreData
	}
	return Packet{
		Type:       FrameData,
		Token:      token,
		Checksum:   checksum,
		PayloadLen: payloadLen,
	}, int(totalLen), nil
}

// DecodePacket auto-detects and decodes one FDB packet from buf.
func DecodePacket(buf []byte) (Packet, int, error) {
	if len(buf) < 8 {
		return Packet{}, 0, ErrNeedsMoreData
	}
	if [4]byte(buf[0:4]) == ConnectPacketMagic {
		return DecodeConnectPacket(buf)
	}
	return DecodeDataPacket(buf)
}

// ParsePackets decodes all complete FDB packets from buf.
func ParsePackets(buf []byte) ([]Packet, int, error) {
	var pkts []Packet
	consumed := 0
	for len(buf) >= 8 {
		pkt, n, err := DecodePacket(buf)
		if errors.Is(err, ErrNeedsMoreData) {
			break
		}
		if err != nil {
			// Not parseable — skip 8 bytes and try again
			if len(buf) >= 8 {
				buf = buf[8:]
				consumed += 8
			}
			continue
		}
		pkts = append(pkts, pkt)
		buf = buf[n:]
		consumed += n
	}
	return pkts, consumed, nil
}

// IsFDB returns true if buf looks like an FDB connect packet.
func IsFDB(buf []byte) bool {
	return len(buf) >= 4 && [4]byte(buf[0:4]) == ConnectPacketMagic
}

// ProtocolVersionString renders an FDB protocol version in hex notation.
func ProtocolVersionString(v uint64) string {
	return fmt.Sprintf("0x%016x", v)
}

// Record represents a matched FDB request/response pair (heuristic: connect + first data frame).
type Record struct {
	Connect *Packet
	Data    *Packet
}
