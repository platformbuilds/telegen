// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package stompparser implements a strict STOMP frame parser.
package stompparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/stompparser"

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

var ErrNeedsMoreData = errors.New("stomp: needs more data")

type Frame struct {
	Command string
	Headers map[string]string
	Body    []byte
}

var validCommands = map[string]struct{}{
	"CONNECT":     {},
	"STOMP":       {},
	"CONNECTED":   {},
	"SEND":        {},
	"SUBSCRIBE":   {},
	"UNSUBSCRIBE": {},
	"ACK":         {},
	"NACK":        {},
	"BEGIN":       {},
	"COMMIT":      {},
	"ABORT":       {},
	"DISCONNECT":  {},
	"MESSAGE":     {},
	"RECEIPT":     {},
	"ERROR":       {},
}

func IsSTOMP(buf []byte) bool {
	command, _, ok := splitFirstLine(buf)
	if !ok {
		return false
	}
	_, exists := validCommands[command]
	return exists
}

func ParseFrames(buf []byte) ([]Frame, int, error) {
	frames := make([]Frame, 0, 4)
	consumed := 0

	for len(buf) > 0 {
		frame, n, err := ParseFrame(buf)
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

func ParseFrame(buf []byte) (Frame, int, error) {
	command, cmdEnd, ok := splitFirstLine(buf)
	if !ok {
		return Frame{}, 0, ErrNeedsMoreData
	}
	if _, exists := validCommands[command]; !exists {
		if looksLikeNearMissCommand(command) {
			return Frame{}, 0, fmt.Errorf("stomp: unknown command %q", command)
		}
		return Frame{}, 0, errors.New("stomp: invalid frame start")
	}

	headers := map[string]string{}
	pos := cmdEnd
	for {
		if pos >= len(buf) {
			return Frame{}, 0, ErrNeedsMoreData
		}

		// Empty line separates headers and body.
		if buf[pos] == '\n' {
			pos++
			break
		}
		if buf[pos] == '\r' {
			if pos+1 >= len(buf) {
				return Frame{}, 0, ErrNeedsMoreData
			}
			if buf[pos+1] != '\n' {
				return Frame{}, 0, errors.New("stomp: invalid CR line ending")
			}
			pos += 2
			break
		}

		line, next, ok := splitLineAt(buf, pos)
		if !ok {
			return Frame{}, 0, ErrNeedsMoreData
		}
		key, value, err := parseHeaderLine(line)
		if err != nil {
			return Frame{}, 0, err
		}
		headers[key] = value
		pos = next
	}

	bodyEnd := bytes.IndexByte(buf[pos:], 0x00)
	if bodyEnd < 0 {
		return Frame{}, 0, ErrNeedsMoreData
	}
	body := append([]byte(nil), buf[pos:pos+bodyEnd]...)
	consumed := pos + bodyEnd + 1

	// Consume any trailing line breaks after frame terminator.
	for consumed < len(buf) && (buf[consumed] == '\n' || buf[consumed] == '\r') {
		consumed++
	}

	return Frame{
		Command: command,
		Headers: headers,
		Body:    body,
	}, consumed, nil
}

func parseHeaderLine(line string) (string, string, error) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", fmt.Errorf("stomp: malformed header line %q", line)
	}
	key := strings.TrimSpace(line[:idx])
	if key == "" {
		return "", "", errors.New("stomp: empty header key")
	}
	rawValue := line[idx+1:]
	return key, unescapeHeaderValue(rawValue), nil
}

func splitFirstLine(buf []byte) (string, int, bool) {
	line, next, ok := splitLineAt(buf, 0)
	if !ok {
		return "", 0, false
	}
	command := strings.TrimSpace(line)
	if command == "" {
		return "", 0, false
	}
	return command, next, true
}

func splitLineAt(buf []byte, start int) (string, int, bool) {
	if start >= len(buf) {
		return "", 0, false
	}

	for i := start; i < len(buf); i++ {
		if buf[i] == '\n' {
			end := i
			if end > start && buf[end-1] == '\r' {
				end--
			}
			return string(buf[start:end]), i + 1, true
		}
	}
	return "", 0, false
}

func unescapeHeaderValue(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' || i+1 >= len(v) {
			b.WriteByte(v[i])
			continue
		}
		i++
		switch v[i] {
		case 'c':
			b.WriteByte(':')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		default:
			b.WriteByte('\\')
			b.WriteByte(v[i])
		}
	}
	return b.String()
}

func looksLikeNearMissCommand(command string) bool {
	if command == "" {
		return false
	}
	for i := 0; i < len(command); i++ {
		if (command[i] < 'A' || command[i] > 'Z') && command[i] != '-' && command[i] != '_' {
			return false
		}
	}
	return true
}
