// Package parsers provides log parsing capabilities for container runtime formats,
// Kubernetes metadata extraction, and application-specific log parsing (e.g., Spring Boot).
//
// All parsed logs are fully OTLP compliant, following OpenTelemetry semantic conventions:
// https://opentelemetry.io/docs/specs/semconv/general/logs/
package parsers

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

// ErrNotMatched is returned when a parser doesn't match the log format
var ErrNotMatched = errors.New("log format not matched")

// OTLP Semantic Convention attribute keys for logs
// https://opentelemetry.io/docs/specs/semconv/general/logs/
const (
	// Log file attributes
	AttrLogFilePath = "log.file.path" // Full path to the log file
	AttrLogFileName = "log.file.name" // Name of the log file
	AttrLogIOStream = "log.iostream"  // stdout or stderr

	// Log record attributes
	AttrLogRecordUID = "log.record.uid" // Unique identifier for the log record

	// Exception attributes (for error logs)
	AttrExceptionType       = "exception.type"
	AttrExceptionMessage    = "exception.message"
	AttrExceptionStacktrace = "exception.stacktrace"

	// Code attributes
	AttrCodeFunction  = "code.function"
	AttrCodeNamespace = "code.namespace"
	AttrCodeFilepath  = "code.filepath"
	AttrCodeLineno    = "code.lineno"

	// Thread attributes
	AttrThreadID   = "thread.id"
	AttrThreadName = "thread.name"

	// Custom telegen attributes
	AttrLogFormat        = "telegen.log.format"        // Parser format used
	AttrLogOriginalLine  = "telegen.log.original"      // Original unparsed line (debug)
	AttrTracingExported  = "telegen.tracing.exported"  // Spring Boot tracing exported flag
	AttrContainerRuntime = "telegen.container.runtime" // Docker, CRI-O, containerd
	AttrLogPartial       = "telegen.log.partial"       // Partial log line (CRI-O P tag)

	// Body content attributes
	AttrBodyContentType = "body.content_type" // Detected content type: json, xml, text
	AttrBodyOriginal    = "body.original"     // Original body before transformation (optional)

	// XML-specific attributes (for XML log formats)
	AttrXMLFormat     = "xml.format"      // Specific XML format: log4j_xml, nlog_xml, serilog_xml, windows_event_xml, generic_xml
	AttrXMLNamespace  = "xml.namespace"   // XML namespace if present
	AttrXMLRootElement = "xml.root_element" // Root element name
)

// ParsedLog represents a parsed log entry with extracted fields.
// All fields map to OTLP log data model:
// https://opentelemetry.io/docs/specs/otel/logs/data-model/
type ParsedLog struct {
	// Timestamp is the time when the event occurred (OTLP: Timestamp)
	Timestamp time.Time

	// ObservedTimestamp is when the log was observed/collected (OTLP: ObservedTimestamp)
	// If not set, defaults to current time when converting to OTel record
	ObservedTimestamp time.Time

	// Body is the log message content (OTLP: Body)
	Body string

	// Severity is the log level text (OTLP: SeverityText)
	Severity Severity

	// SeverityNumber is the OTLP severity number 1-24 (OTLP: SeverityNumber)
	// https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber
	SeverityNumber int

	// TraceID links this log to a distributed trace (OTLP: TraceId)
	// 32 hex characters (16 bytes)
	TraceID string

	// SpanID links this log to a specific span (OTLP: SpanId)
	// 16 hex characters (8 bytes)
	SpanID string

	// TraceFlags contains trace flags (OTLP: Flags)
	TraceFlags byte

	// Stream indicates stdout or stderr (maps to log.iostream attribute)
	Stream string

	// Format indicates the detected format (docker_json, crio, containerd, spring_boot, etc.)
	Format string

	// ResourceAttributes identify the resource producing the log (k8s.*, service.*, host.*)
	// These map to OTLP Resource attributes
	ResourceAttributes map[string]string

	// Attributes are log record attributes (OTLP: Attributes)
	Attributes map[string]string

	// OriginalLine is the raw unparsed line (for debugging, optional)
	OriginalLine string

	// FilePath is the source file path (maps to log.file.path attribute)
	FilePath string
}

// Severity represents log severity levels
type Severity string

const (
	SeverityUnspecified Severity = ""
	SeverityTrace       Severity = "TRACE"
	SeverityTrace2      Severity = "TRACE2"
	SeverityTrace3      Severity = "TRACE3"
	SeverityTrace4      Severity = "TRACE4"
	SeverityDebug       Severity = "DEBUG"
	SeverityDebug2      Severity = "DEBUG2"
	SeverityDebug3      Severity = "DEBUG3"
	SeverityDebug4      Severity = "DEBUG4"
	SeverityInfo        Severity = "INFO"
	SeverityInfo2       Severity = "INFO2"
	SeverityInfo3       Severity = "INFO3"
	SeverityInfo4       Severity = "INFO4"
	SeverityWarn        Severity = "WARN"
	SeverityWarn2       Severity = "WARN2"
	SeverityWarn3       Severity = "WARN3"
	SeverityWarn4       Severity = "WARN4"
	SeverityError       Severity = "ERROR"
	SeverityError2      Severity = "ERROR2"
	SeverityError3      Severity = "ERROR3"
	SeverityError4      Severity = "ERROR4"
	SeverityFatal       Severity = "FATAL"
	SeverityFatal2      Severity = "FATAL2"
	SeverityFatal3      Severity = "FATAL3"
	SeverityFatal4      Severity = "FATAL4"
)

// SeverityToNumber maps severity levels to OTLP severity numbers
// https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber
var SeverityToNumber = map[Severity]int{
	SeverityUnspecified: 0,
	SeverityTrace:       1,
	SeverityTrace2:      2,
	SeverityTrace3:      3,
	SeverityTrace4:      4,
	SeverityDebug:       5,
	SeverityDebug2:      6,
	SeverityDebug3:      7,
	SeverityDebug4:      8,
	SeverityInfo:        9,
	SeverityInfo2:       10,
	SeverityInfo3:       11,
	SeverityInfo4:       12,
	SeverityWarn:        13,
	SeverityWarn2:       14,
	SeverityWarn3:       15,
	SeverityWarn4:       16,
	SeverityError:       17,
	SeverityError2:      18,
	SeverityError3:      19,
	SeverityError4:      20,
	SeverityFatal:       21,
	SeverityFatal2:      22,
	SeverityFatal3:      23,
	SeverityFatal4:      24,
}

// Parser is the interface for log parsers
type Parser interface {
	// Parse attempts to parse a log line and returns the parsed result
	// Returns error if this parser doesn't match the format
	Parse(line string) (*ParsedLog, error)

	// Name returns the parser name for logging/debugging
	Name() string
}

// Enricher is the interface for log enrichers that add metadata
type Enricher interface {
	// Enrich adds metadata to a parsed log entry
	Enrich(log *ParsedLog, filePath string)

	// Name returns the enricher name for logging/debugging
	Name() string
}

// ToOTelRecord converts a ParsedLog to an OpenTelemetry log.Record
// following the OTLP log data model specification:
// https://opentelemetry.io/docs/specs/otel/logs/data-model/
func (p *ParsedLog) ToOTelRecord() log.Record {
	var rec log.Record

	// Set timestamp (when the event occurred)
	if !p.Timestamp.IsZero() {
		rec.SetTimestamp(p.Timestamp)
	} else {
		rec.SetTimestamp(time.Now())
	}

	// Set observed timestamp (when the log was collected/observed)
	if !p.ObservedTimestamp.IsZero() {
		rec.SetObservedTimestamp(p.ObservedTimestamp)
	} else {
		rec.SetObservedTimestamp(time.Now())
	}

	// Set body (the log message) - sanitize for valid UTF-8
	rec.SetBody(log.StringValue(sanitizeUTF8(p.Body)))

	// Set severity number (OTLP SeverityNumber field)
	if p.SeverityNumber > 0 {
		rec.SetSeverity(log.Severity(p.SeverityNumber))
	}

	// Set severity text (OTLP SeverityText field)
	if p.Severity != "" {
		rec.SetSeverityText(string(p.Severity))
	}

	// Set trace context if available (OTLP TraceId, SpanId, Flags fields)
	// This enables log-to-trace correlation in observability backends
	if p.TraceID != "" {
		if traceID, err := parseTraceID(p.TraceID); err == nil {
			spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID:    traceID,
				TraceFlags: trace.TraceFlags(p.TraceFlags),
			})
			if p.SpanID != "" {
				if spanID, err := parseSpanID(p.SpanID); err == nil {
					spanCtx = trace.NewSpanContext(trace.SpanContextConfig{
						TraceID:    traceID,
						SpanID:     spanID,
						TraceFlags: trace.TraceFlags(p.TraceFlags),
					})
				}
			}
			// Note: The OTel SDK log.Record doesn't yet have SetSpanContext
			// We validate the trace context but rely on attributes for correlation
			// until the SDK adds native support. The spanCtx is validated above.
			_ = spanCtx // Validated but not used until SDK supports it
		}
	}

	// Build attributes list with estimated capacity
	// Use min to prevent theoretical overflow with huge slices
	attrLen := len(p.Attributes)
	resAttrLen := len(p.ResourceAttributes)
	const maxAttrs = 1 << 20 // 1M attrs is way more than any real log
	if attrLen > maxAttrs {
		attrLen = maxAttrs
	}
	if resAttrLen > maxAttrs {
		resAttrLen = maxAttrs
	}
	attrCount := attrLen + resAttrLen + 5
	attrs := make([]log.KeyValue, 0, attrCount)

	// Add log format (telegen-specific)
	if p.Format != "" {
		attrs = append(attrs, log.String(AttrLogFormat, p.Format))
	}

	// Add stream as log.iostream (OTLP semantic convention)
	if p.Stream != "" {
		attrs = append(attrs, log.String(AttrLogIOStream, p.Stream))
	}

	// Add file path as log.file.path (OTLP semantic convention)
	if p.FilePath != "" {
		attrs = append(attrs, log.String(AttrLogFilePath, p.FilePath))
	}

	// Add trace context as attributes for correlation
	// (until OTel SDK log.Record natively supports trace context)
	if p.TraceID != "" {
		attrs = append(attrs, log.String("trace_id", p.TraceID))
	}
	if p.SpanID != "" {
		attrs = append(attrs, log.String("span_id", p.SpanID))
	}

	// Add log record attributes - sanitize values for valid UTF-8
	for k, v := range p.Attributes {
		// Skip trace_id/span_id if already added above
		if k == "trace_id" || k == "span_id" {
			continue
		}
		attrs = append(attrs, log.String(sanitizeUTF8(k), sanitizeUTF8(v)))
	}

	// Add resource attributes - sanitize values for valid UTF-8
	// Note: Ideally these go on the Resource, but we add them as attributes
	// for visibility until we have full Resource support in the pipeline
	for k, v := range p.ResourceAttributes {
		attrs = append(attrs, log.String(sanitizeUTF8(k), sanitizeUTF8(v)))
	}

	rec.AddAttributes(attrs...)

	return rec
}

// parseTraceID parses a hex-encoded trace ID string into a trace.TraceID
func parseTraceID(s string) (trace.TraceID, error) {
	var traceID trace.TraceID
	// Pad to 32 chars if shorter (some systems use shorter IDs)
	if len(s) < 32 {
		s = "00000000000000000000000000000000"[:32-len(s)] + s
	}
	if len(s) > 32 {
		s = s[:32]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return traceID, err
	}
	copy(traceID[:], b)
	return traceID, nil
}

// parseSpanID parses a hex-encoded span ID string into a trace.SpanID
func parseSpanID(s string) (trace.SpanID, error) {
	var spanID trace.SpanID
	// Pad to 16 chars if shorter
	if len(s) < 16 {
		s = "0000000000000000"[:16-len(s)] + s
	}
	if len(s) > 16 {
		s = s[:16]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return spanID, err
	}
	copy(spanID[:], b)
	return spanID, nil
}

// NewParsedLog creates a new ParsedLog with initialized maps
func NewParsedLog() *ParsedLog {
	return &ParsedLog{
		ResourceAttributes: make(map[string]string),
		Attributes:         make(map[string]string),
	}
}

// parseJSON parses a JSON string into a map
func parseJSON(s string) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(s), &result)
	return result, err
}

// sanitizeUTF8 ensures a string contains only valid UTF-8 characters.
// Invalid UTF-8 sequences are replaced with the Unicode replacement character (U+FFFD).
// This is necessary because gRPC/protobuf requires valid UTF-8 for string fields.
func sanitizeUTF8(s string) string {
	if s == "" {
		return s
	}
	
	// Fast path: check if string is already valid UTF-8
	valid := true
	for i := 0; i < len(s); {
		if s[i] < 0x80 {
			// ASCII character - always valid
			i++
			continue
		}
		// Check for valid UTF-8 multi-byte sequences
		r, size := decodeRune(s[i:])
		if r == 0xFFFD && size == 1 {
			// Invalid UTF-8 sequence detected
			valid = false
			break
		}
		i += size
	}
	
	if valid {
		return s
	}
	
	// Slow path: rebuild string with invalid bytes replaced
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] < 0x80 {
			result = append(result, s[i])
			i++
			continue
		}
		r, size := decodeRune(s[i:])
		if r == 0xFFFD && size == 1 {
			// Replace invalid byte with replacement character
			result = append(result, 0xEF, 0xBF, 0xBD) // UTF-8 encoding of U+FFFD
			i++
		} else {
			result = append(result, s[i:i+size]...)
			i += size
		}
	}
	
	return string(result)
}

// decodeRune decodes a UTF-8 rune from the start of the string.
// Returns the rune and its size in bytes. Returns (0xFFFD, 1) for invalid UTF-8.
func decodeRune(s string) (rune, int) {
	if len(s) == 0 {
		return 0xFFFD, 0
	}
	
	b := s[0]
	
	// 1-byte sequence (ASCII)
	if b < 0x80 {
		return rune(b), 1
	}
	
	// Invalid start byte
	if b < 0xC0 || b > 0xF7 {
		return 0xFFFD, 1
	}
	
	// Determine expected length
	var size int
	var min rune
	switch {
	case b < 0xE0:
		size = 2
		min = 0x80
	case b < 0xF0:
		size = 3
		min = 0x800
	default:
		size = 4
		min = 0x10000
	}
	
	if len(s) < size {
		return 0xFFFD, 1
	}
	
	// Extract continuation bytes
	var r rune
	switch size {
	case 2:
		r = rune(b&0x1F)<<6 | rune(s[1]&0x3F)
	case 3:
		r = rune(b&0x0F)<<12 | rune(s[1]&0x3F)<<6 | rune(s[2]&0x3F)
	case 4:
		r = rune(b&0x07)<<18 | rune(s[1]&0x3F)<<12 | rune(s[2]&0x3F)<<6 | rune(s[3]&0x3F)
	}
	
	// Validate continuation bytes and check for overlong encoding
	for i := 1; i < size; i++ {
		if s[i]&0xC0 != 0x80 {
			return 0xFFFD, 1
		}
	}
	
	if r < min || (r >= 0xD800 && r <= 0xDFFF) || r > 0x10FFFF {
		return 0xFFFD, 1
	}
	
	return r, size
}
