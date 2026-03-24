// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package natsparser implements NATS protocol parsing and request/response
// stitching. NATS uses a simple text-based protocol over TCP (default port 4222).
//
// Ported from Pixie's C++ implementation:
// src/stirling/source_connectors/socket_tracer/protocols/nats/
package natsparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/natsparser"

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNeedsMoreData indicates the buffer does not contain a complete NATS message.
var ErrNeedsMoreData = errors.New("nats: needs more data")

// MessageType classifies a NATS protocol message.
type MessageType int

const (
	TypeUnknown    MessageType = iota
	TypeINFO                   // server → client: server info JSON
	TypeCONNECT                // client → server: client options JSON
	TypePUB                    // client → server: publish (no headers)
	TypeHPUB                   // client → server: publish with headers (NATS 2.x)
	TypeSUB                    // client → server: subscribe
	TypeUNSUB                  // client → server: unsubscribe
	TypeMSG                    // server → client: message delivery (no headers)
	TypeHMSG                   // server → client: message delivery with headers (NATS 2.x)
	TypePING                   // either direction
	TypePONG                   // either direction
	TypeOK                     // server → client: +OK
	TypeERR                    // server → client: -ERR
)

// Direction of the NATS message.
type Direction int

const (
	DirectionClient Direction = iota // client → server
	DirectionServer                  // server → client
)

// Message represents one parsed NATS protocol message.
type Message struct {
	Type        MessageType
	Direction   Direction
	Subject     string  // PUB/MSG/SUB: topic subject
	SID         string  // MSG/SUB: subscription ID
	ReplyTo     string  // PUB/MSG: optional reply subject
	PayloadSize int     // declared payload byte count
	Payload     []byte  // message payload (up to PayloadSize bytes)
	HeadersRaw  string  // HPUB/HMSG: raw header block
	ErrText     string  // -ERR: error message
	InfoJSON    string  // INFO: server info JSON
}

// IsClientMessage returns true for messages sent by the client.
func (m *Message) IsClientMessage() bool {
	switch m.Type {
	case TypeCONNECT, TypePUB, TypeHPUB, TypeSUB, TypeUNSUB, TypePING:
		return true
	}
	return false
}

// IsServerMessage returns true for messages sent by the server.
func (m *Message) IsServerMessage() bool {
	switch m.Type {
	case TypeINFO, TypeMSG, TypeHMSG, TypePONG, TypeOK, TypeERR:
		return true
	}
	return false
}

// ParseMessage attempts to parse one complete NATS message from buf.
// Returns the message, bytes consumed, and any error.
// Returns ErrNeedsMoreData if the buffer is incomplete.
func ParseMessage(buf []byte) (Message, int, error) {
	// NATS messages are CRLF-delimited lines.
	idx := bytes.Index(buf, []byte("\r\n"))
	if idx < 0 {
		return Message{}, 0, ErrNeedsMoreData
	}

	line := string(buf[:idx])
	rest := buf[idx+2:] // after CRLF

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return Message{}, 0, errors.New("nats: empty line")
	}

	verb := strings.ToUpper(parts[0])

	switch verb {
	case "INFO":
		info := strings.TrimPrefix(line, "INFO ")
		return Message{Type: TypeINFO, InfoJSON: info, Direction: DirectionServer}, idx + 2, nil

	case "CONNECT":
		return Message{Type: TypeCONNECT, Direction: DirectionClient}, idx + 2, nil

	case "+OK":
		return Message{Type: TypeOK, Direction: DirectionServer}, idx + 2, nil

	case "-ERR":
		errText := strings.TrimPrefix(line, "-ERR ")
		return Message{Type: TypeERR, ErrText: errText, Direction: DirectionServer}, idx + 2, nil

	case "PING":
		return Message{Type: TypePING, Direction: DirectionClient}, idx + 2, nil

	case "PONG":
		return Message{Type: TypePONG, Direction: DirectionServer}, idx + 2, nil

	case "PUB":
		// PUB <subject> [reply-to] <#bytes>\r\n[payload]\r\n
		return parsePUB(parts, rest, idx+2)

	case "HPUB":
		// HPUB <subject> [reply-to] <#header-bytes> <#total-bytes>\r\n[headers]\r\n[payload]\r\n
		return parseHPUB(parts, rest, idx+2)

	case "SUB":
		// SUB <subject> [queue-group] <sid>\r\n
		return parseSUB(parts, idx+2)

	case "UNSUB":
		return Message{Type: TypeUNSUB, Direction: DirectionClient}, idx + 2, nil

	case "MSG":
		// MSG <subject> <sid> [reply-to] <#bytes>\r\n[payload]\r\n
		return parseMSG(parts, rest, idx+2)

	case "HMSG":
		// HMSG <subject> <sid> [reply-to] <#header-bytes> <#total-bytes>\r\n...
		return parseHMSG(parts, rest, idx+2)
	}

	return Message{}, 0, fmt.Errorf("nats: unknown verb %q", verb)
}

func parsePUB(parts []string, payload []byte, headerConsumed int) (Message, int, error) {
	// PUB <subject> [reply-to] <#bytes>
	if len(parts) < 3 {
		return Message{}, 0, errors.New("nats: PUB too few fields")
	}
	var subject, replyTo string
	var sizeStr string
	if len(parts) == 3 {
		subject = parts[1]
		sizeStr = parts[2]
	} else {
		subject = parts[1]
		replyTo = parts[2]
		sizeStr = parts[3]
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		return Message{}, 0, fmt.Errorf("nats: invalid PUB size: %w", err)
	}
	if len(payload) < size+2 {
		return Message{}, 0, ErrNeedsMoreData
	}
	msgPayload := payload[:size]
	return Message{
		Type:        TypePUB,
		Direction:   DirectionClient,
		Subject:     subject,
		ReplyTo:     replyTo,
		PayloadSize: size,
		Payload:     msgPayload,
	}, headerConsumed + size + 2, nil
}

func parseHPUB(parts []string, payload []byte, headerConsumed int) (Message, int, error) {
	if len(parts) < 4 {
		return Message{}, 0, errors.New("nats: HPUB too few fields")
	}
	subject := parts[1]
	totalSize, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return Message{}, 0, fmt.Errorf("nats: invalid HPUB total size: %w", err)
	}
	headerSize, err := strconv.Atoi(parts[len(parts)-2])
	if err != nil {
		return Message{}, 0, fmt.Errorf("nats: invalid HPUB header size: %w", err)
	}
	if len(payload) < totalSize+2 {
		return Message{}, 0, ErrNeedsMoreData
	}
	return Message{
		Type:        TypeHPUB,
		Direction:   DirectionClient,
		Subject:     subject,
		PayloadSize: totalSize - headerSize,
		HeadersRaw:  string(payload[:headerSize]),
		Payload:     payload[headerSize:totalSize],
	}, headerConsumed + totalSize + 2, nil
}

func parseSUB(parts []string, headerConsumed int) (Message, int, error) {
	if len(parts) < 3 {
		return Message{}, 0, errors.New("nats: SUB too few fields")
	}
	subject := parts[1]
	sid := parts[len(parts)-1]
	return Message{
		Type:      TypeSUB,
		Direction: DirectionClient,
		Subject:   subject,
		SID:       sid,
	}, headerConsumed, nil
}

func parseMSG(parts []string, payload []byte, headerConsumed int) (Message, int, error) {
	// MSG <subject> <sid> [reply-to] <#bytes>
	if len(parts) < 4 {
		return Message{}, 0, errors.New("nats: MSG too few fields")
	}
	subject := parts[1]
	sid := parts[2]
	sizeStr := parts[len(parts)-1]
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		return Message{}, 0, fmt.Errorf("nats: invalid MSG size: %w", err)
	}
	if len(payload) < size+2 {
		return Message{}, 0, ErrNeedsMoreData
	}
	return Message{
		Type:        TypeMSG,
		Direction:   DirectionServer,
		Subject:     subject,
		SID:         sid,
		PayloadSize: size,
		Payload:     payload[:size],
	}, headerConsumed + size + 2, nil
}

func parseHMSG(parts []string, payload []byte, headerConsumed int) (Message, int, error) {
	if len(parts) < 5 {
		return Message{}, 0, errors.New("nats: HMSG too few fields")
	}
	subject := parts[1]
	sid := parts[2]
	totalSize, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return Message{}, 0, fmt.Errorf("nats: invalid HMSG total size: %w", err)
	}
	if len(payload) < totalSize+2 {
		return Message{}, 0, ErrNeedsMoreData
	}
	return Message{
		Type:        TypeHMSG,
		Direction:   DirectionServer,
		Subject:     subject,
		SID:         sid,
		PayloadSize: totalSize,
		Payload:     payload[:totalSize],
	}, headerConsumed + totalSize + 2, nil
}

// ParseMessages parses all complete NATS messages from buf.
func ParseMessages(buf []byte) ([]Message, int, error) {
	var messages []Message
	consumed := 0
	for len(buf) > 0 {
		m, n, err := ParseMessage(buf)
		if errors.Is(err, ErrNeedsMoreData) {
			break
		}
		if err != nil {
			// Skip one byte and try again (re-sync).
			buf = buf[1:]
			consumed++
			continue
		}
		messages = append(messages, m)
		buf = buf[n:]
		consumed += n
	}
	return messages, consumed, nil
}

// Record is a matched NATS request/response pair.
// For pub/sub (fire-and-forget), one side may be zero-valued.
type Record struct {
	Request  Message
	Response Message
}

// StitchMessages builds Records from parsed NATS messages.
// PING/PONG are matched; PUB/MSG are emitted as one-sided records.
// This mirrors Pixie's nats::StitchFrames.
func StitchMessages(messages []Message) []Record {
	var records []Record
	pendingPing := false

	for _, m := range messages {
		switch m.Type {
		case TypePING:
			pendingPing = true
		case TypePONG:
			if pendingPing {
				records = append(records, Record{
					Request:  Message{Type: TypePING, Direction: DirectionClient},
					Response: m,
				})
				pendingPing = false
			}
		case TypePUB, TypeHPUB:
			records = append(records, Record{Request: m})
		case TypeMSG, TypeHMSG:
			records = append(records, Record{Response: m})
		case TypeERR:
			records = append(records, Record{Response: m})
		// INFO, CONNECT, SUB, UNSUB, OK are control messages — not span-worthy.
		}
	}

	return records
}

// IsNATS returns true if buf looks like NATS protocol data.
// NATS server always sends "INFO {...}\r\n" immediately on connect.
func IsNATS(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	upper := strings.ToUpper(string(buf[:min4(len(buf), 8)]))
	return strings.HasPrefix(upper, "INFO") ||
		strings.HasPrefix(upper, "PING") ||
		strings.HasPrefix(upper, "PONG") ||
		strings.HasPrefix(upper, "+OK") ||
		strings.HasPrefix(upper, "-ERR") ||
		strings.HasPrefix(upper, "PUB ") ||
		strings.HasPrefix(upper, "MSG ") ||
		strings.HasPrefix(upper, "CONNECT")
}

func min4(a, b int) int {
	if a < b {
		return a
	}
	return b
}
