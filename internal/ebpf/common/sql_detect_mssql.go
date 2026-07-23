// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"encoding/binary"
	"log/slog"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/sqlprune"
)

const (
	kMSSQLHeaderLen = 8
	kMSSQLBatch     = 1
	kMSSQLRPC       = 3
	kMSSQLResponse  = 4

	// Maximum size of a single TDS packet as defined by the protocol.
	kMSSQLMaxPacketSize = 32767
)

// isMSSQL checks whether b looks like a TDS packet carrying SQL traffic.
func isMSSQL(b []byte) bool {
	if len(b) < kMSSQLHeaderLen {
		return false
	}

	pktType := b[0]
	if pktType != kMSSQLBatch && pktType != kMSSQLRPC && pktType != kMSSQLResponse {
		return false
	}

	// Status upper nibble is reserved.
	if (b[1] & 0xF0) != 0 {
		return false
	}

	// Length is big-endian in TDS (total packet length including header).
	length := binary.BigEndian.Uint16(b[2:4])
	if length < uint16(kMSSQLHeaderLen) || length > kMSSQLMaxPacketSize {
		return false
	}

	// Window byte is currently unused and should be zero.
	return b[7] == 0
}

func ucs2ToUTF8(b []byte) []byte {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}

	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i += 2 {
		u1 := binary.LittleEndian.Uint16(b[i:])
		if utf16.IsSurrogate(rune(u1)) && i+2 < len(b) {
			u2 := binary.LittleEndian.Uint16(b[i+2:])
			if r := utf16.DecodeRune(rune(u1), rune(u2)); r != utf8.RuneError {
				out = utf8.AppendRune(out, r)
				i += 2
				continue
			}
		}
		out = utf8.AppendRune(out, rune(u1))
	}

	return out
}

// extractTDSPayloads iterates over all TDS packets and returns concatenated payload bytes
// with packet headers stripped out.
func extractTDSPayloads(b []byte) []byte {
	total := len(b)
	var payload []byte

	for offset := 0; offset+kMSSQLHeaderLen <= total; {
		pktLen := int(binary.BigEndian.Uint16(b[offset+2 : offset+4]))
		if pktLen < kMSSQLHeaderLen || offset+pktLen > total {
			break
		}
		payloadLen := pktLen - kMSSQLHeaderLen
		if payloadLen > 0 {
			payload = append(payload, b[offset+kMSSQLHeaderLen:offset+pktLen]...)
		}
		offset += pktLen
	}

	return payload
}

func mssqlExtractBatchSQL(b []byte) (string, string, string) {
	if len(b) <= kMSSQLHeaderLen {
		return "", "", ""
	}
	if b[0] == kMSSQLBatch {
		stmt := ucs2ToUTF8(extractTDSPayloads(b))
		return detectSQL(string(stmt))
	}
	return "", "", ""
}

// handleMSSQL parses a TCP request/response pair as MSSQL.
func handleMSSQL(_ *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer []byte) (request.Span, error) {
	var (
		op, table, stmt string
		span            request.Span
	)

	if len(requestBuffer) < kMSSQLHeaderLen {
		slog.Debug("MSSQL request too short")
		return span, errFallback
	}

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMSSQL, requestBuffer)
	sqlError := sqlprune.SQLParseError(request.DBMSSQL, responseBuffer)

	switch sqlCommand {
	case "SQL_BATCH":
		op, table, stmt = mssqlExtractBatchSQL(requestBuffer)
	case "RPC":
		// Best-effort fallback: SQL may be encoded in UCS-2 in RPC payload bytes.
		if len(requestBuffer) > kMSSQLHeaderLen {
			op, table, stmt = detectSQL(string(ucs2ToUTF8(requestBuffer[kMSSQLHeaderLen:])))
		}
	}

	if !validSQL(op, table, request.DBMSSQL) {
		slog.Debug("MSSQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, table, stmt, request.DBMSSQL, sqlCommand, sqlError), nil
}
