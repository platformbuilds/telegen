// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package dubbov2parser implements the Apache Dubbo2 RPC protocol parser.
// Dubbo2 uses a 16-byte fixed header over TCP (default port 20880) with
// optional Hessian2 / Fastjson / Protobuf serialization of the request body.
//
// Reference: https://cn.dubbo.apache.org/en/docs3-v2/java-sdk/reference-manual/protocol/overview/
// Wire protocol: https://github.com/apache/dubbo/blob/3.x/dubbo-remoting/dubbo-remoting-api/src/main/java/org/apache/dubbo/remoting/exchange/codec/ExchangeCodec.java
package dubbov2parser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/dubbov2parser"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNeedsMoreData is returned when the buffer is too short for a complete frame.
var ErrNeedsMoreData = errors.New("dubbo2: needs more data")

// Magic bytes at the start of every Dubbo2 frame.
const (
	MagicByte0 = 0xDA
	MagicByte1 = 0xBB
)

// HeaderLen is the fixed Dubbo2 header size.
const HeaderLen = 16

// Flags byte bit masks.
const (
	FlagRequest    = 0x80 // 1 = request, 0 = response
	FlagTwoWay     = 0x40 // 1 = expects response
	FlagEvent      = 0x20 // 1 = heartbeat event
	FlagSerialMask = 0x1F // serialization id (1-12)
)

// Status byte values for response frames.
const (
	StatusOK                        = 20
	StatusClientTimeout             = 30
	StatusServerTimeout             = 31
	StatusBadRequest                = 40
	StatusBadResponse               = 50
	StatusServiceNotFound           = 60
	StatusServiceError              = 70
	StatusServerError               = 80
	StatusClientError               = 90
	StatusServerThreadpoolExhausted = 100
)

// SerializationID identifies the serialization format.
type SerializationID uint8

const (
	SerializationHessian2    SerializationID = 2
	SerializationJava        SerializationID = 3
	SerializationCompactJava SerializationID = 4
	SerializationFastJSON    SerializationID = 6
	SerializationNative      SerializationID = 7
	SerializationFastJSON2   SerializationID = 8
	SerializationProtobuf    SerializationID = 12
)

// SerializationName returns a human-readable serialization name.
func SerializationName(id SerializationID) string {
	names := map[SerializationID]string{
		SerializationHessian2:    "hessian2",
		SerializationJava:        "java",
		SerializationCompactJava: "compactjava",
		SerializationFastJSON:    "fastjson",
		SerializationNative:      "nativejava",
		SerializationFastJSON2:   "fastjson2",
		SerializationProtobuf:    "protobuf",
	}
	if name, ok := names[id]; ok {
		return name
	}
	return fmt.Sprintf("serial(%d)", uint8(id))
}

// StatusName returns a human-readable Dubbo2 status name.
func StatusName(status uint8) string {
	names := map[uint8]string{
		StatusOK:                        "OK",
		StatusClientTimeout:             "CLIENT_TIMEOUT",
		StatusServerTimeout:             "SERVER_TIMEOUT",
		StatusBadRequest:                "BAD_REQUEST",
		StatusBadResponse:               "BAD_RESPONSE",
		StatusServiceNotFound:           "SERVICE_NOT_FOUND",
		StatusServiceError:              "SERVICE_ERROR",
		StatusServerError:               "SERVER_ERROR",
		StatusClientError:               "CLIENT_ERROR",
		StatusServerThreadpoolExhausted: "SERVER_THREADPOOL_EXHAUSTED",
	}
	if name, ok := names[status]; ok {
		return name
	}
	return fmt.Sprintf("status(%d)", status)
}

// Frame represents a decoded Dubbo2 protocol frame.
type Frame struct {
	IsRequest     bool
	IsTwoWay      bool
	IsEvent       bool
	Serialization SerializationID
	Status        uint8 // response frames only
	RequestID     int64 // 8-byte correlation ID
	DataLength    int32 // body byte count
	// ParsedMethod is the RPC service + method extracted from the body
	// (best-effort; requires Hessian2 decoding or JSON key scanning).
	ParsedMethod  string
	ParsedService string
	ParsedVersion string
	// StatusCode is a synthetic 0/1 for success/error used in spans.
	StatusCode int
}

// DecodeFrame decodes one Dubbo2 frame from buf.
// Returns the Frame, bytes consumed (header only — body bytes are DataLength more),
// and any error.
// NOTE: The full frame size is HeaderLen + DataLength.
func DecodeFrame(buf []byte) (Frame, int, error) {
	if len(buf) < HeaderLen {
		return Frame{}, 0, ErrNeedsMoreData
	}
	// Validate magic
	if buf[0] != MagicByte0 || buf[1] != MagicByte1 {
		return Frame{}, 0, fmt.Errorf("dubbo2: invalid magic bytes 0x%02x 0x%02x", buf[0], buf[1])
	}

	flags := buf[2]
	status := buf[3]
	requestID := int64(binary.BigEndian.Uint64(buf[4:12]))
	dataLen := int32(binary.BigEndian.Uint32(buf[12:16]))

	if dataLen < 0 || dataLen > 16*1024*1024 { // 16MB sanity check
		return Frame{}, 0, fmt.Errorf("dubbo2: implausible data length %d", dataLen)
	}

	isRequest := (flags & FlagRequest) != 0
	isTwoWay := (flags & FlagTwoWay) != 0
	isEvent := (flags & FlagEvent) != 0
	serial := SerializationID(flags & FlagSerialMask)

	statusCode := 0
	if !isRequest && status != StatusOK {
		statusCode = 1
	}

	f := Frame{
		IsRequest:     isRequest,
		IsTwoWay:      isTwoWay,
		IsEvent:       isEvent,
		Serialization: serial,
		Status:        status,
		RequestID:     requestID,
		DataLength:    dataLen,
		StatusCode:    statusCode,
	}

	// Attempt body parsing if body is present in buffer
	totalLen := HeaderLen + int(dataLen)
	if len(buf) >= totalLen && dataLen > 0 {
		body := buf[HeaderLen:totalLen]
		if isRequest && !isEvent {
			f.ParsedService, f.ParsedVersion, f.ParsedMethod = extractDubboRequestFields(body, serial)
		}
	}

	consumed := HeaderLen
	if len(buf) >= totalLen {
		consumed = totalLen
	}
	return f, consumed, nil
}

// extractDubboRequestFields attempts to extract service, version, and method name from
// a Dubbo2 request body. For Hessian2 (the most common serialization), the body format is:
//
//	dubboVersion(string) + serviceName(string) + serviceVersion(string) + methodName(string) + ...
//
// We use a simple length-prefixed string scanner (Hessian2 compact strings start with 0x00..0x1F
// for single-byte length or 0x52 (R) for long strings; Java UTF8 strings use MSB length).
func extractDubboRequestFields(body []byte, serial SerializationID) (service, version, method string) {
	switch serial {
	case SerializationHessian2, SerializationNative, SerializationJava, SerializationCompactJava:
		// Hessian2 compact string: if first byte is in range 0x00-0x1f, it encodes the length directly.
		strs, ok := readHessian2Strings(body, 4)
		if ok && len(strs) >= 4 {
			// strs[0] = dubboVersion, strs[1] = serviceName, strs[2] = serviceVersion, strs[3] = methodName
			service = strs[1]
			version = strs[2]
			method = strs[3]
		}
	case SerializationFastJSON, SerializationFastJSON2:
		// FastJSON body: JSON object with "path", "version", "method" keys
		service, version, method = extractJSONFields(body)
	}
	return
}

// readHessian2Strings reads up to n compact Hessian2 strings from buf.
// Hessian2 compact strings: byte 0x00..0x1F = length (0-31 chars), then UTF-8 bytes.
// Type tag 0x52 ('R') or 0x73 ('s') for longer strings.
func readHessian2Strings(buf []byte, n int) ([]string, bool) {
	var out []string
	i := 0
	for len(out) < n && i < len(buf) {
		b := buf[i]
		switch {
		case b <= 0x1F:
			// Compact string: length = b
			length := int(b)
			i++
			if i+length > len(buf) {
				return out, false
			}
			out = append(out, string(buf[i:i+length]))
			i += length
		case b == 0x52 || b == 0x73:
			// Long string: next 2 bytes = length (big-endian)
			if i+3 > len(buf) {
				return out, false
			}
			length := int(buf[i+1])<<8 | int(buf[i+2])
			i += 3
			if i+length > len(buf) {
				return out, false
			}
			out = append(out, string(buf[i:i+length]))
			i += length
		default:
			// Unknown Hessian2 type tag — stop
			return out, len(out) >= n
		}
	}
	return out, len(out) >= n
}

// extractJSONFields is a minimal JSON field scanner for Dubbo2 FastJSON bodies.
// Looks for "path":"<value>", "version":"<value>", "method":"<value>" keys.
func extractJSONFields(buf []byte) (path, version, method string) {
	s := string(buf)
	path = jsonStringVal(s, "path")
	version = jsonStringVal(s, "version")
	method = jsonStringVal(s, "method")
	return
}

func jsonStringVal(s, key string) string {
	needle := `"` + key + `":"`
	idx := indexOf(s, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := indexOf(s[start:], `"`)
	if end < 0 {
		return s[start:]
	}
	return s[start : start+end]
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Record is a matched Dubbo2 request/response pair.
type Record struct {
	RequestID int64
	Request   Frame
	Response  Frame
}

// ParseFrames decodes all complete Dubbo2 frames from buf, consuming body bytes too.
func ParseFrames(buf []byte) ([]Frame, int, error) {
	var frames []Frame
	consumed := 0
	for len(buf) >= HeaderLen {
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

// StitchFrames matches Dubbo2 request/response pairs by RequestID.
func StitchFrames(frames []Frame) []Record {
	pending := make(map[int64]Frame)
	var records []Record
	for _, f := range frames {
		if f.IsRequest {
			pending[f.RequestID] = f
		} else {
			if req, ok := pending[f.RequestID]; ok {
				records = append(records, Record{RequestID: f.RequestID, Request: req, Response: f})
				delete(pending, f.RequestID)
			}
		}
	}
	return records
}

// IsDubbo2 returns true if buf starts with the Dubbo2 magic bytes.
func IsDubbo2(buf []byte) bool {
	return len(buf) >= 2 && buf[0] == MagicByte0 && buf[1] == MagicByte1
}

// StatusIsOK maps a Dubbo2 HTTP-like status to a boolean.
func StatusIsOK(status uint8) bool {
	return status == StatusOK
}
