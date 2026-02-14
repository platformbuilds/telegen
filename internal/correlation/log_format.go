// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// LogFormat represents a detected log format.
type LogFormat int

const (
	// LogFormatUnknown indicates an unknown log format.
	LogFormatUnknown LogFormat = iota

	// LogFormatJSON indicates JSON formatted logs.
	LogFormatJSON

	// LogFormatLogfmt indicates logfmt formatted logs.
	LogFormatLogfmt

	// LogFormatCEF indicates Common Event Format logs.
	LogFormatCEF

	// LogFormatSyslog indicates syslog formatted logs.
	LogFormatSyslog

	// LogFormatApache indicates Apache/NCSA combined log format.
	LogFormatApache

	// LogFormatNginx indicates NGINX log format.
	LogFormatNginx

	// LogFormatW3C indicates W3C extended log format.
	LogFormatW3C

	// LogFormatPlainText indicates plain text logs.
	LogFormatPlainText
)

// String returns the string representation of the log format.
func (f LogFormat) String() string {
	switch f {
	case LogFormatJSON:
		return "json"
	case LogFormatLogfmt:
		return "logfmt"
	case LogFormatCEF:
		return "cef"
	case LogFormatSyslog:
		return "syslog"
	case LogFormatApache:
		return "apache"
	case LogFormatNginx:
		return "nginx"
	case LogFormatW3C:
		return "w3c"
	case LogFormatPlainText:
		return "plaintext"
	default:
		return "unknown"
	}
}

// LogFormatDetector detects log formats.
type LogFormatDetector struct {
	patterns map[LogFormat]*regexp.Regexp
}

// NewLogFormatDetector creates a new log format detector.
func NewLogFormatDetector() *LogFormatDetector {
	return &LogFormatDetector{
		patterns: map[LogFormat]*regexp.Regexp{
			// Syslog: <priority>timestamp hostname process[pid]: message
			LogFormatSyslog: regexp.MustCompile(`^<\d{1,3}>\s*\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`),

			// CEF: CEF:version|...
			LogFormatCEF: regexp.MustCompile(`^CEF:\d+\|`),

			// Apache combined: IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
			LogFormatApache: regexp.MustCompile(`^\S+\s+-\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]\s+"\w+\s+`),

			// NGINX: Similar to Apache but may have different timestamp format
			LogFormatNginx: regexp.MustCompile(`^\S+\s+-\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]\s+"\w+\s+`),

			// W3C extended: #Fields: date time ...
			LogFormatW3C: regexp.MustCompile(`^#(Fields:|Version:|Date:)`),

			// Logfmt: key=value key="value" pairs
			LogFormatLogfmt: regexp.MustCompile(`^(\w+=[^\s"]+|\w+="[^"]*")(\s+(\w+=[^\s"]+|\w+="[^"]*"))+`),
		},
	}
}

// Detect detects the log format of a log line.
func (d *LogFormatDetector) Detect(logLine string) LogFormat {
	logLine = strings.TrimSpace(logLine)
	if logLine == "" {
		return LogFormatUnknown
	}

	// Check for JSON first (most common in modern systems)
	if d.isJSON(logLine) {
		return LogFormatJSON
	}

	// Check structured formats
	for format, pattern := range d.patterns {
		if pattern.MatchString(logLine) {
			return format
		}
	}

	// Check for logfmt separately (more complex detection)
	if d.isLogfmt(logLine) {
		return LogFormatLogfmt
	}

	return LogFormatPlainText
}

// isJSON checks if the line is valid JSON.
func (d *LogFormatDetector) isJSON(line string) bool {
	line = strings.TrimSpace(line)
	if len(line) < 2 {
		return false
	}

	// Quick check for JSON object or array
	if (line[0] != '{' && line[0] != '[') ||
		(line[len(line)-1] != '}' && line[len(line)-1] != ']') {
		return false
	}

	// Validate JSON
	var js json.RawMessage
	return json.Unmarshal([]byte(line), &js) == nil
}

// isLogfmt checks if the line is logfmt formatted.
func (d *LogFormatDetector) isLogfmt(line string) bool {
	// Must have at least one key=value pair
	if !strings.Contains(line, "=") {
		return false
	}

	// Simple logfmt detection: look for common keys
	commonKeys := []string{"level=", "msg=", "time=", "ts=", "err=", "error=", "caller="}
	matches := 0
	for _, key := range commonKeys {
		if strings.Contains(line, key) {
			matches++
		}
	}

	return matches >= 2
}

// LogEnricher enriches logs with trace context.
type LogEnricher struct {
	detector *LogFormatDetector
}

// NewLogEnricher creates a new log enricher.
func NewLogEnricher() *LogEnricher {
	return &LogEnricher{
		detector: NewLogFormatDetector(),
	}
}

// EnrichedLog represents an enriched log line.
type EnrichedLog struct {
	Original  string
	Enriched  string
	Format    LogFormat
	TraceID   string
	SpanID    string
	Timestamp time.Time
}

// Enrich enriches a log line with trace context.
func (e *LogEnricher) Enrich(logLine string, tc *TraceContext) *EnrichedLog {
	result := &EnrichedLog{
		Original:  logLine,
		Timestamp: time.Now(),
	}

	if tc == nil || !tc.TraceID.IsValid() {
		result.Enriched = logLine
		return result
	}

	result.TraceID = tc.TraceID.String()
	result.SpanID = tc.SpanID.String()
	result.Format = e.detector.Detect(logLine)

	switch result.Format {
	case LogFormatJSON:
		result.Enriched = e.enrichJSON(logLine, tc)
	case LogFormatLogfmt:
		result.Enriched = e.enrichLogfmt(logLine, tc)
	case LogFormatCEF:
		result.Enriched = e.enrichCEF(logLine, tc)
	case LogFormatSyslog:
		result.Enriched = e.enrichSyslog(logLine, tc)
	case LogFormatApache, LogFormatNginx:
		result.Enriched = e.enrichAccessLog(logLine, tc)
	default:
		// Plain text: append trace info
		result.Enriched = e.enrichPlainText(logLine, tc)
	}

	return result
}

// enrichJSON enriches JSON logs.
func (e *LogEnricher) enrichJSON(logLine string, tc *TraceContext) string {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(logLine), &m); err != nil {
		return logLine
	}

	m["trace_id"] = tc.TraceID.String()
	m["span_id"] = tc.SpanID.String()

	if tc.Flags.IsSampled() {
		m["trace_flags"] = tc.Flags.String()
	}

	if tc.TraceState != "" {
		m["trace_state"] = tc.TraceState
	}

	out, err := json.Marshal(m)
	if err != nil {
		return logLine
	}

	return string(out)
}

// enrichLogfmt enriches logfmt logs.
func (e *LogEnricher) enrichLogfmt(logLine string, tc *TraceContext) string {
	var buf bytes.Buffer
	buf.WriteString(strings.TrimRight(logLine, "\n"))
	buf.WriteString(" trace_id=")
	buf.WriteString(tc.TraceID.String())
	buf.WriteString(" span_id=")
	buf.WriteString(tc.SpanID.String())

	if tc.Flags.IsSampled() {
		buf.WriteString(" trace_flags=")
		buf.WriteString(tc.Flags.String())
	}

	return buf.String()
}

// enrichCEF enriches CEF logs.
// CEF format: CEF:version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
func (e *LogEnricher) enrichCEF(logLine string, tc *TraceContext) string {
	// Add to extension field
	logLine = strings.TrimRight(logLine, "\n")

	var buf bytes.Buffer
	buf.WriteString(logLine)
	buf.WriteString(" traceId=")
	buf.WriteString(tc.TraceID.String())
	buf.WriteString(" spanId=")
	buf.WriteString(tc.SpanID.String())

	return buf.String()
}

// enrichSyslog enriches syslog logs.
func (e *LogEnricher) enrichSyslog(logLine string, tc *TraceContext) string {
	// Append structured data
	logLine = strings.TrimRight(logLine, "\n")

	var buf bytes.Buffer
	buf.WriteString(logLine)
	buf.WriteString(" [trace@1 trace_id=\"")
	buf.WriteString(tc.TraceID.String())
	buf.WriteString("\" span_id=\"")
	buf.WriteString(tc.SpanID.String())
	buf.WriteString("\"]")

	return buf.String()
}

// enrichAccessLog enriches Apache/NGINX access logs.
func (e *LogEnricher) enrichAccessLog(logLine string, tc *TraceContext) string {
	// Append trace context as additional field
	logLine = strings.TrimRight(logLine, "\n")

	var buf bytes.Buffer
	buf.WriteString(logLine)
	buf.WriteString(" \"")
	buf.WriteString(tc.TraceID.String())
	buf.WriteString(":")
	buf.WriteString(tc.SpanID.String())
	buf.WriteString("\"")

	return buf.String()
}

// enrichPlainText enriches plain text logs.
func (e *LogEnricher) enrichPlainText(logLine string, tc *TraceContext) string {
	logLine = strings.TrimRight(logLine, "\n")

	var buf bytes.Buffer
	buf.WriteString(logLine)
	buf.WriteString(" [trace_id=")
	buf.WriteString(tc.TraceID.String())
	buf.WriteString(" span_id=")
	buf.WriteString(tc.SpanID.String())
	buf.WriteString("]")

	return buf.String()
}

// DetectAndParseFormat detects format and parses trace context if present.
type ParsedLogLine struct {
	Format    LogFormat
	Body      string
	TraceID   string
	SpanID    string
	Level     string
	Timestamp time.Time
	Attrs     map[string]interface{}
}

// ParseLogLine parses a log line and extracts any existing trace context.
func ParseLogLine(logLine string) *ParsedLogLine {
	detector := NewLogFormatDetector()
	format := detector.Detect(logLine)

	result := &ParsedLogLine{
		Format: format,
		Body:   logLine,
		Attrs:  make(map[string]interface{}),
	}

	switch format {
	case LogFormatJSON:
		parseJSONLog(logLine, result)
	case LogFormatLogfmt:
		parseLogfmtLog(logLine, result)
	}

	return result
}

// parseJSONLog parses a JSON log line.
func parseJSONLog(logLine string, result *ParsedLogLine) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(logLine), &m); err != nil {
		return
	}

	// Extract trace context
	if traceID, ok := m["trace_id"].(string); ok {
		result.TraceID = traceID
		delete(m, "trace_id")
	}
	if spanID, ok := m["span_id"].(string); ok {
		result.SpanID = spanID
		delete(m, "span_id")
	}

	// Extract common fields
	if level, ok := m["level"].(string); ok {
		result.Level = level
	} else if lvl, ok := m["lvl"].(string); ok {
		result.Level = lvl
	} else if severity, ok := m["severity"].(string); ok {
		result.Level = severity
	}

	// Extract timestamp
	for _, key := range []string{"time", "timestamp", "ts", "@timestamp"} {
		if ts, ok := m[key]; ok {
			result.Timestamp = parseTimestamp(ts)
			break
		}
	}

	// Extract message body
	for _, key := range []string{"msg", "message", "log"} {
		if msg, ok := m[key].(string); ok {
			result.Body = msg
			break
		}
	}

	result.Attrs = m
}

// parseLogfmtLog parses a logfmt log line.
func parseLogfmtLog(logLine string, result *ParsedLogLine) {
	// Simple logfmt parser
	parts := strings.Fields(logLine)

	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := kv[0]
		value := strings.Trim(kv[1], "\"")

		switch key {
		case "trace_id":
			result.TraceID = value
		case "span_id":
			result.SpanID = value
		case "level", "lvl":
			result.Level = value
		case "time", "ts", "timestamp":
			result.Timestamp = parseTimestamp(value)
		case "msg", "message":
			result.Body = value
		default:
			result.Attrs[key] = value
		}
	}
}

// parseTimestamp attempts to parse a timestamp from various formats.
func parseTimestamp(v interface{}) time.Time {
	switch ts := v.(type) {
	case string:
		// Try common formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05.000Z",
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
		}
		for _, f := range formats {
			if t, err := time.Parse(f, ts); err == nil {
				return t
			}
		}
	case float64:
		// Unix timestamp
		sec := int64(ts)
		nsec := int64((ts - float64(sec)) * 1e9)
		return time.Unix(sec, nsec)
	case int64:
		// Could be seconds, milliseconds, or nanoseconds
		if ts > 1e18 { // Nanoseconds
			return time.Unix(0, ts)
		} else if ts > 1e15 { // Microseconds
			return time.Unix(0, ts*1000)
		} else if ts > 1e12 { // Milliseconds
			return time.Unix(0, ts*1000000)
		}
		return time.Unix(ts, 0)
	}
	return time.Time{}
}

// MultiFormatEnricher handles multiple log formats.
type MultiFormatEnricher struct {
	enricher *LogEnricher
	detector *LogFormatDetector
	formats  map[string]LogFormat // Cache format per source
}

// NewMultiFormatEnricher creates a new multi-format enricher.
func NewMultiFormatEnricher() *MultiFormatEnricher {
	return &MultiFormatEnricher{
		enricher: NewLogEnricher(),
		detector: NewLogFormatDetector(),
		formats:  make(map[string]LogFormat),
	}
}

// EnrichWithSource enriches a log line, caching format detection per source.
func (m *MultiFormatEnricher) EnrichWithSource(source, logLine string, tc *TraceContext) *EnrichedLog {
	// Use cached format if available
	format, ok := m.formats[source]
	if !ok {
		format = m.detector.Detect(logLine)
		m.formats[source] = format
	}

	result := &EnrichedLog{
		Original:  logLine,
		Format:    format,
		Timestamp: time.Now(),
	}

	if tc == nil || !tc.TraceID.IsValid() {
		result.Enriched = logLine
		return result
	}

	result.TraceID = tc.TraceID.String()
	result.SpanID = tc.SpanID.String()

	// Use the cached format
	switch format {
	case LogFormatJSON:
		result.Enriched = m.enricher.enrichJSON(logLine, tc)
	case LogFormatLogfmt:
		result.Enriched = m.enricher.enrichLogfmt(logLine, tc)
	case LogFormatCEF:
		result.Enriched = m.enricher.enrichCEF(logLine, tc)
	case LogFormatSyslog:
		result.Enriched = m.enricher.enrichSyslog(logLine, tc)
	case LogFormatApache, LogFormatNginx:
		result.Enriched = m.enricher.enrichAccessLog(logLine, tc)
	default:
		result.Enriched = m.enricher.enrichPlainText(logLine, tc)
	}

	return result
}

// ResetFormatCache resets the format cache for a source.
func (m *MultiFormatEnricher) ResetFormatCache(source string) {
	delete(m.formats, source)
}
