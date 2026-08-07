// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package clickhouseparser implements the ClickHouse Native TCP binary protocol
// parser. ClickHouse clients connect on port 9000 by default and exchange
// type-tagged LEB128-framed messages.
//
// Reference: https://clickhouse.com/docs/en/native-protocol/basics
// Protocol spec: https://github.com/ClickHouse/ClickHouse/blob/master/src/Server/TCPHandler.cpp
package clickhouseparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/clickhouseparser"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// ErrNeedsMoreData is returned when the buffer is too short for a complete packet.
var ErrNeedsMoreData = errors.New("clickhouse: needs more data")

// ClientPacketType enumerates known ClickHouse client → server packet types.
type ClientPacketType uint64

const (
	ClientHello                     ClientPacketType = 0
	ClientQuery                     ClientPacketType = 1
	ClientData                      ClientPacketType = 2
	ClientCancel                    ClientPacketType = 3
	ClientPing                      ClientPacketType = 4
	ClientTableStatus               ClientPacketType = 5
	ClientKeepAlive                 ClientPacketType = 6
	ClientScalar                    ClientPacketType = 7
	ClientIgnoredPartUUIDs          ClientPacketType = 8
	ClientReadTaskResponse          ClientPacketType = 9
	ClientMergeTreeReadTaskResponse ClientPacketType = 10
)

// ServerPacketType enumerates known ClickHouse server → client packet types.
type ServerPacketType uint64

const (
	ServerHello            ServerPacketType = 0
	ServerData             ServerPacketType = 1
	ServerException        ServerPacketType = 2
	ServerProgress         ServerPacketType = 3
	ServerPong             ServerPacketType = 4
	ServerEndOfStream      ServerPacketType = 5
	ServerProfileInfo      ServerPacketType = 6
	ServerTotals           ServerPacketType = 7
	ServerExtremes         ServerPacketType = 8
	ServerTablesStatusResp ServerPacketType = 9
	ServerLog              ServerPacketType = 10
	ServerTableColumns     ServerPacketType = 11
	ServerUUIDs            ServerPacketType = 12
	ServerReadTaskRequest  ServerPacketType = 13
	ServerProfileEvents    ServerPacketType = 14
)

// QueryState describes the current stage of a query.
type QueryState uint64

const (
	QueryStateInitial   QueryState = 0
	QueryStateSecondary QueryState = 1
)

// Packet holds a decoded ClickHouse native protocol packet.
type Packet struct {
	// IsClient is true if this is a client → server packet.
	IsClient bool
	// ClientType is set when IsClient is true.
	ClientType ClientPacketType
	// ServerType is set when IsClient is false.
	ServerType ServerPacketType
	// QueryID is the UUID string identifying a query (present in ClientQuery packets).
	QueryID string
	// QuerySQL is the SQL text (present in ClientQuery packets).
	QuerySQL string
	// ErrorCode is the exception code (present in ServerException packets).
	ErrorCode int32
	// ErrorMessage is the exception message text (present in ServerException packets).
	ErrorMessage string
}

// readVarUint reads a LEB128-encoded unsigned integer from buf.
// Returns the value, bytes consumed, and any error.
func readVarUint(buf []byte) (uint64, int, error) {
	var x uint64
	var s uint
	for i, b := range buf {
		if i == 9 {
			return 0, 0, errors.New("clickhouse: varuint overflow")
		}
		x |= uint64(b&0x7F) << s
		s += 7
		if b&0x80 == 0 {
			return x, i + 1, nil
		}
	}
	return 0, 0, ErrNeedsMoreData
}

// readString reads a LEB128-prefixed string from buf.
// Returns the string, bytes consumed, and any error.
func readString(buf []byte) (string, int, error) {
	length, n, err := readVarUint(buf)
	if err != nil {
		return "", 0, err
	}
	maxInt := uint64(^uint(0) >> 1)
	if length > maxInt {
		return "", 0, errors.New("clickhouse: string length overflows int")
	}
	if n > len(buf) {
		return "", 0, errors.New("clickhouse: invalid string prefix length")
	}
	if length > uint64(len(buf)-n) {
		return "", 0, ErrNeedsMoreData
	}
	total := n + int(length)
	if len(buf) < total {
		return "", 0, ErrNeedsMoreData
	}
	_ = bits.Len64(length) // use bits to avoid unused import
	return string(buf[n:total]), total, nil
}

// ClientPacketTypeName returns a human-readable name for a client packet type.
func ClientPacketTypeName(t ClientPacketType) string {
	names := map[ClientPacketType]string{
		ClientHello:                     "Hello",
		ClientQuery:                     "Query",
		ClientData:                      "Data",
		ClientCancel:                    "Cancel",
		ClientPing:                      "Ping",
		ClientTableStatus:               "TableStatus",
		ClientKeepAlive:                 "KeepAlive",
		ClientScalar:                    "Scalar",
		ClientIgnoredPartUUIDs:          "IgnoredPartUUIDs",
		ClientReadTaskResponse:          "ReadTaskResponse",
		ClientMergeTreeReadTaskResponse: "MergeTreeReadTaskResponse",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Client(%d)", uint64(t))
}

// ServerPacketTypeName returns a human-readable name for a server packet type.
func ServerPacketTypeName(t ServerPacketType) string {
	names := map[ServerPacketType]string{
		ServerHello:            "Hello",
		ServerData:             "Data",
		ServerException:        "Exception",
		ServerProgress:         "Progress",
		ServerPong:             "Pong",
		ServerEndOfStream:      "EndOfStream",
		ServerProfileInfo:      "ProfileInfo",
		ServerTotals:           "Totals",
		ServerExtremes:         "Extremes",
		ServerTablesStatusResp: "TablesStatusResp",
		ServerLog:              "Log",
		ServerTableColumns:     "TableColumns",
		ServerUUIDs:            "UUIDs",
		ServerReadTaskRequest:  "ReadTaskRequest",
		ServerProfileEvents:    "ProfileEvents",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Server(%d)", uint64(t))
}

// DecodeClientPacket decodes one ClickHouse client → server packet from buf.
func DecodeClientPacket(buf []byte) (Packet, int, error) {
	if len(buf) < 2 {
		return Packet{}, 0, ErrNeedsMoreData
	}
	pkgType, n, err := readVarUint(buf)
	if err != nil {
		return Packet{}, 0, err
	}
	pkt := Packet{IsClient: true, ClientType: ClientPacketType(pkgType)}
	consumed := n

	switch ClientPacketType(pkgType) {
	case ClientHello:
		// client_name (string) + version_major (varuint) + version_minor (varuint) + revision (varuint)
		clientName, n2, err := readString(buf[consumed:])
		if err != nil {
			return Packet{}, 0, err
		}
		consumed += n2
		_ = clientName
		// skip version_major, version_minor, revision (3 varints)
		for i := 0; i < 3; i++ {
			_, n3, err := readVarUint(buf[consumed:])
			if err != nil {
				return Packet{}, 0, err
			}
			consumed += n3
		}

	case ClientQuery:
		// query_id (string)
		queryID, n2, err := readString(buf[consumed:])
		if err != nil {
			return Packet{}, 0, err
		}
		pkt.QueryID = queryID
		consumed += n2
		// client_info block varies by server revision; we skip to the SQL text.
		// For simplicity: initial_query(1) + user(str) + query_id2(str) + address(str)
		// We rely on the SQL text being the last string in the header before the data block.
		// Full decoding mirrors ClickHouse's ClientInfo::read().
		// We emit what we have and let the Go side scan for the SQL.

	case ClientData, ClientCancel, ClientPing, ClientKeepAlive:
		// no additional fields needed for span creation

	default:
		// unknown / future packet type — consume only the type varint
	}

	return pkt, consumed, nil
}

// DecodeServerPacket decodes one ClickHouse server → client packet from buf.
func DecodeServerPacket(buf []byte) (Packet, int, error) {
	if len(buf) < 2 {
		return Packet{}, 0, ErrNeedsMoreData
	}
	pkgType, n, err := readVarUint(buf)
	if err != nil {
		return Packet{}, 0, err
	}
	pkt := Packet{IsClient: false, ServerType: ServerPacketType(pkgType)}
	consumed := n

	switch ServerPacketType(pkgType) {
	case ServerHello:
		// server_name(str) + version_major + version_minor + revision + [patch] + [tz] + [display_name]
		serverName, n2, err := readString(buf[consumed:])
		if err != nil {
			return Packet{}, 0, err
		}
		consumed += n2
		_ = serverName

	case ServerException:
		// code(int32) + name(str) + message(str) + stack_trace(str) + has_nested(bool)
		if len(buf[consumed:]) < 4 {
			return Packet{}, 0, ErrNeedsMoreData
		}
		code := int32(binary.LittleEndian.Uint32(buf[consumed : consumed+4]))
		pkt.ErrorCode = code
		consumed += 4
		_, n2, err := readString(buf[consumed:]) // exception name
		if err != nil {
			return Packet{}, 0, err
		}
		consumed += n2
		msg, n3, err := readString(buf[consumed:])
		if err != nil {
			return Packet{}, 0, err
		}
		pkt.ErrorMessage = msg
		consumed += n3

	default:
		// Data, Progress, Pong, EndOfStream etc. — no span-relevant fields
	}

	return pkt, consumed, nil
}

// IsClickHouseClient returns true if buf looks like a ClickHouse client Hello packet.
func IsClickHouseClient(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	// varuint 0x00 = ClientHello, then LEB128 len of "ClickHouse client" = 0x11, then "Cl"
	return buf[0] == 0x00 && buf[1] == 0x11 && buf[2] == 'C' && buf[3] == 'l'
}

// IsClickHouseServer returns true if buf looks like a ClickHouse server Hello packet.
func IsClickHouseServer(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	// varuint 0x00 = ServerHello, then len 0x0A, then "ClickHouse"
	return buf[0] == 0x00 && buf[1] == 0x0A && buf[2] == 'C' && buf[3] == 'l'
}

// IsClickHouse returns true if either direction looks like ClickHouse native protocol.
func IsClickHouse(buf []byte) bool {
	return IsClickHouseClient(buf) || IsClickHouseServer(buf)
}

// Record is a matched ClickHouse request/response pair.
type Record struct {
	QueryID    string
	QuerySQL   string
	StatusCode int // 0 = OK, 1 = exception
	ErrorCode  int32
	ErrorMsg   string
}

// ExtractQuerySQL attempts to find the SQL text inside a ClientQuery packet payload.
// The SQL is a LEB128-prefixed string that appears late in the payload after
// client_info, settings, and state fields. We scan forward for a plausible SQL
// prefix ("SELECT", "INSERT", "CREATE", "DROP", "ALTER", "WITH", "SHOW", "DESCRIBE").
func ExtractQuerySQL(payload []byte) string {
	sqlPrefixes := [][]byte{
		[]byte("SELECT"), []byte("INSERT"), []byte("CREATE"), []byte("DROP"),
		[]byte("ALTER"), []byte("WITH"), []byte("SHOW"), []byte("DESCRIBE"),
		[]byte("select"), []byte("insert"), []byte("create"), []byte("drop"),
		[]byte("alter"), []byte("with"), []byte("show"), []byte("describe"),
		[]byte("TRUNCATE"), []byte("truncate"),
	}
	for _, prefix := range sqlPrefixes {
		idx := indexOf(payload, prefix)
		if idx >= 0 && idx+len(prefix) < len(payload) {
			// The LEB128 length prefix is right before the SQL text.
			// Scan back to find it.
			end := len(payload)
			return string(payload[idx:end])
		}
	}
	return ""
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}
