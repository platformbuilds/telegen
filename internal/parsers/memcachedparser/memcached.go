// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package memcachedparser implements the Memcached ASCII text protocol parser and
// request/response stitching. Memcached uses a simple newline-delimited text
// protocol over TCP (default port 11211).
//
// Reference: https://github.com/memcached/memcached/blob/master/doc/protocol.txt
package memcachedparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/memcachedparser"

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNeedsMoreData is returned when the buffer does not contain a complete message.
var ErrNeedsMoreData = errors.New("memcached: needs more data")

// CommandType classifies the Memcached command verb.
type CommandType int

const (
	CmdUnknown     CommandType = iota
	CmdGet                     // get <key>*
	CmdGets                    // gets <key>* (with CAS token)
	CmdGetAndTouch             // gat <exptime> <key>*
	CmdSet                     // set <key> <flags> <exptime> <bytes> [noreply]
	CmdAdd                     // add <key> <flags> <exptime> <bytes> [noreply]
	CmdReplace                 // replace <key> <flags> <exptime> <bytes> [noreply]
	CmdAppend                  // append <key> <flags> <exptime> <bytes> [noreply]
	CmdPrepend                 // prepend <key> <flags> <exptime> <bytes> [noreply]
	CmdCAS                     // cas <key> <flags> <exptime> <bytes> <cas> [noreply]
	CmdDelete                  // delete <key> [noreply]
	CmdIncr                    // incr <key> <value> [noreply]
	CmdDecr                    // decr <key> <value> [noreply]
	CmdTouch                   // touch <key> <exptime> [noreply]
	CmdStats                   // stats [args]
	CmdFlushAll                // flush_all [exptime] [noreply]
	CmdVersion                 // version
	CmdQuit                    // quit
)

// Direction represents whether this is a request or response message.
type Direction int

const (
	DirectionRequest Direction = iota
	DirectionResponse
)

// statusFromResponse maps a Memcached response line to a synthetic status code.
// 0 = success, 1 = error/miss.
func statusFromResponse(resp string) int {
	resp = strings.TrimSpace(resp)
	switch {
	case resp == "STORED", resp == "DELETED", resp == "TOUCHED",
		strings.HasPrefix(resp, "VALUE "), strings.HasPrefix(resp, "END"),
		resp == "OK", resp == "RESET":
		return 0
	case resp == "NOT_STORED", resp == "EXISTS", resp == "NOT_FOUND",
		strings.HasPrefix(resp, "ERROR"), strings.HasPrefix(resp, "CLIENT_ERROR"),
		strings.HasPrefix(resp, "SERVER_ERROR"):
		return 1
	}
	// Numeric response for incr/decr is a success
	fields := strings.Fields(resp)
	if len(fields) > 0 {
		if _, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			return 0
		}
	}
	return 0 // unknown — treat as success
}

// Message represents a single Memcached protocol message (request or response).
type Message struct {
	Direction Direction
	Command   CommandType
	// CommandStr is the raw command verb (e.g. "get", "set").
	CommandStr string
	// Key is the primary key for the operation (first key for multi-key commands).
	Key string
	// Keys holds all keys for multi-key get commands.
	Keys []string
	// ByteCount is the declared data length for storage commands.
	ByteCount int
	// Flags is the client-opaque flags field for storage commands.
	Flags uint32
	// Exptime is the TTL for storage/touch commands.
	Exptime int64
	// CASToken for CAS command.
	CASToken uint64
	// NoReply indicates the noreply option was set.
	NoReply bool
	// ResponseLine is the first response line for responses.
	ResponseLine string
	// StatusCode: 0=success, 1=error/miss.
	StatusCode int
}

// cmdFromVerb converts a command string to CommandType.
func cmdFromVerb(verb string) CommandType {
	switch strings.ToLower(verb) {
	case "get":
		return CmdGet
	case "gets":
		return CmdGets
	case "gat", "gatq":
		return CmdGetAndTouch
	case "set":
		return CmdSet
	case "add":
		return CmdAdd
	case "replace":
		return CmdReplace
	case "append":
		return CmdAppend
	case "prepend":
		return CmdPrepend
	case "cas":
		return CmdCAS
	case "delete":
		return CmdDelete
	case "incr":
		return CmdIncr
	case "decr":
		return CmdDecr
	case "touch":
		return CmdTouch
	case "stats":
		return CmdStats
	case "flush_all":
		return CmdFlushAll
	case "version":
		return CmdVersion
	case "quit":
		return CmdQuit
	}
	return CmdUnknown
}

// isResponseLine returns true if the line looks like a Memcached server response.
func isResponseLine(line string) bool {
	line = strings.TrimSpace(line)
	prefixes := []string{
		"VALUE ", "END", "STORED", "NOT_STORED", "EXISTS", "NOT_FOUND",
		"ERROR", "CLIENT_ERROR", "SERVER_ERROR", "DELETED", "TOUCHED",
		"OK", "RESET", "STAT ", "VERSION ",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	// numeric (incr/decr response)
	if len(line) > 0 {
		if _, err := strconv.ParseUint(strings.Fields(line)[0], 10, 64); err == nil {
			return true
		}
	}
	return false
}

// DecodeRequest parses a single Memcached ASCII request from buf.
// Returns the Message, bytes consumed, and error.
func DecodeRequest(buf []byte) (Message, int, error) {
	nlIdx := bytes.IndexByte(buf, '\n')
	if nlIdx < 0 {
		return Message{}, 0, ErrNeedsMoreData
	}
	line := strings.TrimRight(string(buf[:nlIdx]), "\r\n")
	consumed := nlIdx + 1

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Message{}, consumed, fmt.Errorf("memcached: empty request line")
	}
	verb := fields[0]
	cmd := cmdFromVerb(verb)
	msg := Message{
		Direction:  DirectionRequest,
		Command:    cmd,
		CommandStr: verb,
	}

	switch cmd {
	case CmdGet, CmdGets:
		// get <key>*
		if len(fields) < 2 {
			return Message{}, consumed, fmt.Errorf("memcached: get requires at least one key")
		}
		msg.Keys = fields[1:]
		msg.Key = fields[1]

	case CmdGetAndTouch:
		// gat <exptime> <key>*
		if len(fields) < 3 {
			return Message{}, consumed, fmt.Errorf("memcached: gat requires exptime and keys")
		}
		exp, _ := strconv.ParseInt(fields[1], 10, 64)
		msg.Exptime = exp
		msg.Keys = fields[2:]
		msg.Key = fields[2]

	case CmdSet, CmdAdd, CmdReplace, CmdAppend, CmdPrepend:
		// <cmd> <key> <flags> <exptime> <bytes> [noreply]
		if len(fields) < 5 {
			return Message{}, consumed, fmt.Errorf("memcached: %s requires key/flags/exptime/bytes", verb)
		}
		msg.Key = fields[1]
		f, _ := strconv.ParseUint(fields[2], 10, 32)
		msg.Flags = uint32(f)
		exp, _ := strconv.ParseInt(fields[3], 10, 64)
		msg.Exptime = exp
		bc, err := strconv.Atoi(fields[4])
		if err != nil || bc < 0 {
			return Message{}, consumed, fmt.Errorf("memcached: invalid byte count: %q", fields[4])
		}
		msg.ByteCount = bc
		if len(fields) >= 6 && fields[5] == "noreply" {
			msg.NoReply = true
		}
		// Skip over the data block + trailing \r\n
		dataEnd := consumed + bc + 2 // data + CRLF
		if len(buf) < dataEnd {
			return Message{}, 0, ErrNeedsMoreData
		}
		consumed = dataEnd

	case CmdCAS:
		// cas <key> <flags> <exptime> <bytes> <cas> [noreply]
		if len(fields) < 6 {
			return Message{}, consumed, fmt.Errorf("memcached: cas requires 5 fields")
		}
		msg.Key = fields[1]
		f, _ := strconv.ParseUint(fields[2], 10, 32)
		msg.Flags = uint32(f)
		exp, _ := strconv.ParseInt(fields[3], 10, 64)
		msg.Exptime = exp
		bc, err := strconv.Atoi(fields[4])
		if err != nil || bc < 0 {
			return Message{}, consumed, fmt.Errorf("memcached: invalid byte count: %q", fields[4])
		}
		msg.ByteCount = bc
		cas, _ := strconv.ParseUint(fields[5], 10, 64)
		msg.CASToken = cas
		if len(fields) >= 7 && fields[6] == "noreply" {
			msg.NoReply = true
		}
		dataEnd := consumed + bc + 2
		if len(buf) < dataEnd {
			return Message{}, 0, ErrNeedsMoreData
		}
		consumed = dataEnd

	case CmdDelete:
		// delete <key> [noreply]
		if len(fields) < 2 {
			return Message{}, consumed, fmt.Errorf("memcached: delete requires key")
		}
		msg.Key = fields[1]
		if len(fields) >= 3 && fields[2] == "noreply" {
			msg.NoReply = true
		}

	case CmdIncr, CmdDecr:
		// incr/decr <key> <value> [noreply]
		if len(fields) < 3 {
			return Message{}, consumed, fmt.Errorf("memcached: %s requires key and value", verb)
		}
		msg.Key = fields[1]

	case CmdTouch:
		// touch <key> <exptime> [noreply]
		if len(fields) < 3 {
			return Message{}, consumed, fmt.Errorf("memcached: touch requires key and exptime")
		}
		msg.Key = fields[1]
		exp, _ := strconv.ParseInt(fields[2], 10, 64)
		msg.Exptime = exp

	case CmdStats, CmdFlushAll, CmdVersion, CmdQuit:
		// no required fields
	}

	return msg, consumed, nil
}

// DecodeResponse parses a single Memcached ASCII response from buf.
// VALUE responses consume until "END\r\n".
func DecodeResponse(buf []byte) (Message, int, error) {
	nlIdx := bytes.IndexByte(buf, '\n')
	if nlIdx < 0 {
		return Message{}, 0, ErrNeedsMoreData
	}
	line := strings.TrimRight(string(buf[:nlIdx]), "\r\n")
	consumed := nlIdx + 1

	msg := Message{
		Direction:    DirectionResponse,
		ResponseLine: line,
		StatusCode:   statusFromResponse(line),
	}

	// VALUE responses: consume all VALUE blocks + END
	if strings.HasPrefix(line, "VALUE ") {
		endIdx := bytes.Index(buf, []byte("END\r\n"))
		if endIdx < 0 {
			endIdx = bytes.Index(buf, []byte("END\n"))
			if endIdx < 0 {
				return Message{}, 0, ErrNeedsMoreData
			}
			consumed = endIdx + 4
		} else {
			consumed = endIdx + 5
		}
	}

	return msg, consumed, nil
}

// Record is a matched request+response pair for a Memcached operation.
type Record struct {
	Request  Message
	Response Message
}

// IsMemcached returns true if buf looks like a Memcached ASCII protocol message.
func IsMemcached(buf []byte) bool {
	if len(buf) < 3 {
		return false
	}
	// Check for common command verbs or response tokens
	verbs := []string{
		"get ", "gets ", "set ", "add ", "replace ", "append ", "prepend ",
		"cas ", "delete ", "incr ", "decr ", "touch ", "gat ", "stats",
		"flush_all", "version", "quit",
		"VALUE ", "STORED", "NOT_STORED", "EXISTS", "NOT_FOUND",
		"ERROR", "CLIENT_ERROR", "SERVER_ERROR", "DELETED", "TOUCHED",
		"END", "STAT ", "OK",
	}
	s := string(buf)
	for _, v := range verbs {
		if strings.HasPrefix(s, v) {
			return true
		}
	}
	// numeric response (incr/decr)
	if isResponseLine(string(buf)) {
		return true
	}
	return false
}

// ParseRequest parses all complete Memcached requests from buf.
func ParseRequest(buf []byte) ([]Message, int, error) {
	var msgs []Message
	consumed := 0
	for len(buf) > 0 {
		msg, n, err := DecodeRequest(buf)
		if errors.Is(err, ErrNeedsMoreData) {
			break
		}
		if err != nil {
			return msgs, consumed, err
		}
		if n <= 0 || n > len(buf) {
			break
		}
		msgs = append(msgs, msg)
		buf = buf[n:]
		consumed += n
	}
	return msgs, consumed, nil
}

// ParseResponse parses all complete Memcached responses from buf.
func ParseResponse(buf []byte) ([]Message, int, error) {
	var msgs []Message
	consumed := 0
	for len(buf) > 0 {
		if !isResponseLine(string(buf)) {
			break
		}
		msg, n, err := DecodeResponse(buf)
		if errors.Is(err, ErrNeedsMoreData) {
			break
		}
		if err != nil {
			return msgs, consumed, err
		}
		if n <= 0 || n > len(buf) {
			break
		}
		msgs = append(msgs, msg)
		buf = buf[n:]
		consumed += n
	}
	return msgs, consumed, nil
}
