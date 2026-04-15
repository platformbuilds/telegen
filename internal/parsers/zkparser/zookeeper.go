// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package zkparser implements the Apache ZooKeeper client/server binary
// (Jute-encoded) protocol parser and request/response stitching.
// ZooKeeper uses a length-prefixed Jute-encoded binary protocol on port 2181.
//
// Reference: https://zookeeper.apache.org/doc/r3.9.0/zookeeperInternals.html
// Wire format: https://github.com/apache/zookeeper/blob/master/zookeeper-server/src/main/java/org/apache/zookeeper/client/ZooKeeperSaslClient.java
package zkparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/zkparser"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNeedsMoreData is returned when the buffer is too short for a complete packet.
var ErrNeedsMoreData = errors.New("zookeeper: needs more data")

// OpCode enumerates ZooKeeper operation codes used in request headers.
type OpCode int32

const (
	OpNotification    OpCode = 0
	OpCreate          OpCode = 1
	OpDelete          OpCode = 2
	OpExists          OpCode = 3
	OpGetData         OpCode = 4
	OpSetData         OpCode = 5
	OpGetACL          OpCode = 6
	OpSetACL          OpCode = 7
	OpGetChildren     OpCode = 8
	OpSync            OpCode = 9
	OpPing            OpCode = 11
	OpGetChildren2    OpCode = 12
	OpCheck           OpCode = 13
	OpMulti           OpCode = 14
	OpCreate2         OpCode = 15
	OpReconfig        OpCode = 16
	OpCheckWatches    OpCode = 17
	OpRemoveWatches   OpCode = 18
	OpCreateContainer OpCode = 19
	OpDeleteContainer OpCode = 20
	OpCreateTTL       OpCode = 21
	OpMultiRead       OpCode = 22
	OpAuth            OpCode = 100
	OpSetWatches      OpCode = 101
	OpSASL            OpCode = 102
	OpGetEphemerals   OpCode = 103
	OpGetAllChildrenNumber OpCode = 104
	OpSetWatches2     OpCode = 105
	// Negative opcodes used in response-only packets
	OpWatcherEvent OpCode = -1
	OpCloseSession OpCode = -11
	OpError        OpCode = -128
)

// Direction represents request or response.
type Direction int

const (
	DirectionRequest  Direction = iota
	DirectionResponse
)

// ConnectRequest is the initial ZooKeeper connect packet (no XID, no opcode header).
type ConnectRequest struct {
	ProtocolVersion int32
	LastZxidSeen    int64
	TimeOut         int32
	SessionID       int64
	PasswordLen     int32
}

// RequestHeader is the header of a regular ZooKeeper request.
type RequestHeader struct {
	XID    int32
	OpCode OpCode
}

// ReplyHeader is the header of a ZooKeeper response.
type ReplyHeader struct {
	XID        int32
	ZXid       int64
	ErrCode    int32
}

// Packet holds a decoded ZooKeeper packet.
type Packet struct {
	Direction Direction
	// Connect is set when this is a ConnectRequest.
	Connect *ConnectRequest
	// Request is set when this is a regular client request.
	Request *RequestHeader
	// Reply is set when this is a server reply.
	Reply *ReplyHeader
	// Path is the znodes path, extracted for applicable operations.
	Path string
}

// OpCodeName returns a human-readable name for a ZooKeeper opcode.
func OpCodeName(op OpCode) string {
	names := map[OpCode]string{
		OpNotification:       "Notification",
		OpCreate:             "Create",
		OpDelete:             "Delete",
		OpExists:             "Exists",
		OpGetData:            "GetData",
		OpSetData:            "SetData",
		OpGetACL:             "GetACL",
		OpSetACL:             "SetACL",
		OpGetChildren:        "GetChildren",
		OpSync:               "Sync",
		OpPing:               "Ping",
		OpGetChildren2:       "GetChildren2",
		OpCheck:              "Check",
		OpMulti:              "Multi",
		OpCreate2:            "Create2",
		OpReconfig:           "Reconfig",
		OpCheckWatches:       "CheckWatches",
		OpRemoveWatches:      "RemoveWatches",
		OpCreateContainer:    "CreateContainer",
		OpDeleteContainer:    "DeleteContainer",
		OpCreateTTL:          "CreateTTL",
		OpMultiRead:          "MultiRead",
		OpAuth:               "Auth",
		OpSetWatches:         "SetWatches",
		OpSASL:               "SASL",
		OpGetEphemerals:      "GetEphemerals",
		OpGetAllChildrenNumber: "GetAllChildrenNumber",
		OpSetWatches2:        "SetWatches2",
		OpWatcherEvent:       "WatcherEvent",
		OpCloseSession:       "CloseSession",
		OpError:              "Error",
	}
	if name, ok := names[op]; ok {
		return name
	}
	return fmt.Sprintf("Op(%d)", int32(op))
}

// ErrCodeName returns a human-readable name for a ZooKeeper error code.
func ErrCodeName(code int32) string {
	codes := map[int32]string{
		0:   "OK",
		-1:  "SystemError",
		-2:  "RuntimeInconsistency",
		-3:  "DataInconsistency",
		-4:  "ConnectionLoss",
		-5:  "MarshallingError",
		-6:  "Unimplemented",
		-7:  "OperationTimeout",
		-8:  "BadArguments",
		-9:  "UnknownSession",
		-100: "APIError",
		-101: "NoNode",
		-102: "NoAuth",
		-103: "BadVersion",
		-108: "NoChildrenForEphemerals",
		-110: "NodeExists",
		-111: "NotEmpty",
		-112: "SessionExpired",
		-113: "InvalidCallback",
		-114: "InvalidACL",
		-115: "AuthFailed",
		-116: "SessionMoved",
		-117: "NotReadOnly",
		-118: "EphemeralOnLocalSession",
		-119: "NowatcherExists",
		-120: "RequestTimeout",
		-121: "NewConfigNoQuorum",
		-122: "ReconfigInProgress",
		-123: "UnknownSession",
	}
	if name, ok := codes[code]; ok {
		return name
	}
	return fmt.Sprintf("ErrCode(%d)", code)
}

const minPacketLen = 4 // 4-byte length prefix

// DecodePacket decodes one ZooKeeper packet from buf.
// ZooKeeper packets are: 4-byte big-endian length + payload.
// The interpretation of the payload depends on context (connect vs. request vs. response).
// We do a best-effort decode: if the XID is -1 (ping) or -2 (auth) or positive
// and the opCode is a known value, we treat it as a request header.
func DecodePacket(buf []byte) (Packet, int, error) {
	if len(buf) < minPacketLen {
		return Packet{}, 0, ErrNeedsMoreData
	}
	pktLen := int(binary.BigEndian.Uint32(buf[0:4]))
	if pktLen <= 0 || pktLen > 0x100000 {
		return Packet{}, 0, fmt.Errorf("zookeeper: implausible packet length %d", pktLen)
	}
	total := 4 + pktLen
	if len(buf) < total {
		return Packet{}, 0, ErrNeedsMoreData
	}
	payload := buf[4:total]

	pkt := Packet{}

	// Connect request: 4-byte protocolVersion (=0) + 8-byte lastZxidSeen + 4-byte timeout + 8-byte sessionId
	// Minimum 24 bytes, and the protocolVersion must be 0.
	if len(payload) >= 28 {
		protoVer := int32(binary.BigEndian.Uint32(payload[0:4]))
		if protoVer == 0 {
			cr := &ConnectRequest{
				ProtocolVersion: protoVer,
				LastZxidSeen:    int64(binary.BigEndian.Uint64(payload[4:12])),
				TimeOut:         int32(binary.BigEndian.Uint32(payload[12:16])),
				SessionID:       int64(binary.BigEndian.Uint64(payload[16:24])),
			}
			if len(payload) >= 28 {
				cr.PasswordLen = int32(binary.BigEndian.Uint32(payload[24:28]))
			}
			pkt.Direction = DirectionRequest
			pkt.Connect = cr
			return pkt, total, nil
		}
	}

	// Request header: XID(4) + OpCode(4) = 8 bytes
	if len(payload) >= 8 {
		xid := int32(binary.BigEndian.Uint32(payload[0:4]))
		opCode := OpCode(int32(binary.BigEndian.Uint32(payload[4:8])))
		if isValidOpCode(opCode) {
			rh := &RequestHeader{XID: xid, OpCode: opCode}
			pkt.Direction = DirectionRequest
			pkt.Request = rh
			// Try to extract the path for path-bearing operations
			if len(payload) >= 12 {
				pathLen := int(binary.BigEndian.Uint32(payload[8:12]))
				if pathLen > 0 && pathLen < 4096 && 12+pathLen <= len(payload) {
					pkt.Path = string(payload[12 : 12+pathLen])
				}
			}
			return pkt, total, nil
		}
	}

	// Reply header: XID(4) + ZXid(8) + ErrCode(4) = 16 bytes
	if len(payload) >= 16 {
		xid := int32(binary.BigEndian.Uint32(payload[0:4]))
		zxid := int64(binary.BigEndian.Uint64(payload[4:12]))
		errCode := int32(binary.BigEndian.Uint32(payload[12:16]))
		// XID -2 = ping response, -1 = watcher event; positive = normal response
		rh := &ReplyHeader{XID: xid, ZXid: zxid, ErrCode: errCode}
		pkt.Direction = DirectionResponse
		pkt.Reply = rh
		return pkt, total, nil
	}

	return Packet{}, total, fmt.Errorf("zookeeper: unrecognized packet format (len=%d)", pktLen)
}

// isValidOpCode returns true if op is a known ZooKeeper operation code.
func isValidOpCode(op OpCode) bool {
	switch op {
	case OpNotification, OpCreate, OpDelete, OpExists, OpGetData, OpSetData,
		OpGetACL, OpSetACL, OpGetChildren, OpSync, OpPing, OpGetChildren2,
		OpCheck, OpMulti, OpCreate2, OpReconfig, OpCheckWatches, OpRemoveWatches,
		OpCreateContainer, OpDeleteContainer, OpCreateTTL, OpMultiRead,
		OpAuth, OpSetWatches, OpSASL, OpGetEphemerals, OpGetAllChildrenNumber,
		OpSetWatches2, OpWatcherEvent, OpCloseSession, OpError:
		return true
	}
	return false
}

// ParsePackets decodes all complete ZooKeeper packets from buf.
func ParsePackets(buf []byte) ([]Packet, int, error) {
	var pkts []Packet
	consumed := 0
	for len(buf) > 0 {
		pkt, n, err := DecodePacket(buf)
		if errors.Is(err, ErrNeedsMoreData) {
			break
		}
		if err != nil {
			// Skip this packet (not parseable), advance by 4 to avoid infinite loop
			if len(buf) >= 4 {
				skip := int(binary.BigEndian.Uint32(buf[0:4])) + 4
				if skip <= 0 || skip > len(buf) {
					break
				}
				buf = buf[skip:]
				consumed += skip
				continue
			}
			break
		}
		pkts = append(pkts, pkt)
		buf = buf[n:]
		consumed += n
	}
	return pkts, consumed, nil
}

// Record is a matched ZooKeeper request + response pair.
type Record struct {
	XID      int32
	Request  *Packet
	Response *Packet
}

// StitchPackets matches ZooKeeper request/response pairs by XID.
func StitchPackets(pkts []Packet) []Record {
	pending := make(map[int32]*Packet)
	var records []Record

	for i := range pkts {
		pkt := &pkts[i]
		switch pkt.Direction {
		case DirectionRequest:
			if pkt.Request != nil {
				pending[pkt.Request.XID] = pkt
			}
		case DirectionResponse:
			if pkt.Reply != nil {
				if req, ok := pending[pkt.Reply.XID]; ok {
					records = append(records, Record{XID: pkt.Reply.XID, Request: req, Response: pkt})
					delete(pending, pkt.Reply.XID)
				} else {
					records = append(records, Record{XID: pkt.Reply.XID, Response: pkt})
				}
			}
		}
	}

	return records
}

// IsZooKeeper returns true if buf looks like ZooKeeper protocol data.
func IsZooKeeper(buf []byte) bool {
	if len(buf) < 12 {
		return false
	}
	pktLen := int(binary.BigEndian.Uint32(buf[0:4]))
	if pktLen <= 0 || pktLen > 0x100000 {
		return false
	}
	if len(buf) < 4+pktLen {
		// Can still be ZK if len is plausible
		return pktLen < 0x10000
	}
	// Check connect request (protoVer=0)
	if len(buf) >= 8 {
		protoVer := int32(binary.BigEndian.Uint32(buf[4:8]))
		if protoVer == 0 && pktLen >= 24 {
			return true
		}
	}
	// Check request header (valid opCode)
	if len(buf) >= 12 {
		opCode := OpCode(int32(binary.BigEndian.Uint32(buf[8:12])))
		return isValidOpCode(opCode)
	}
	return false
}
