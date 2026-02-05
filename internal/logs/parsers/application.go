package parsers

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SpringBootParser parses Spring Boot Logback-formatted logs with trace correlation
// Default format: YYYY-MM-DD HH:MM:SS.mmm LEVEL [app, traceId, spanId, exported] threadId --- [threadName] logger: message
type SpringBootParser struct {
	// Full Spring Boot format with Micrometer tracing
	fullPattern *regexp.Regexp

	// Simpler Spring Boot format without tracing
	simplePattern *regexp.Regexp

	// Basic timestamp + level + message
	basicPattern *regexp.Regexp
}

// NewSpringBootParser creates a new Spring Boot log parser
func NewSpringBootParser() *SpringBootParser {
	return &SpringBootParser{
		// Full format with tracing: 2024-01-15 10:30:45.123 INFO [myapp, abc123, def456, true] 12345 --- [main] c.e.MyClass: message
		fullPattern: regexp.MustCompile(
			`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d{3})\s+` + // timestamp
				`(\w+)\s+` + // level
				`\[([^,]*),\s*([^,]*),\s*([^,]*),\s*([^\]]*)\]\s+` + // [app, traceId, spanId, exported]
				`(\d+)\s+---\s+` + // threadId ---
				`\[([^\]]+)\]\s+` + // [threadName]
				`([^:]+):\s*` + // logger:
				`(.*)$`, // message
		),

		// Simple format without tracing: 2024-01-15 10:30:45.123 INFO 12345 --- [main] c.e.MyClass: message
		simplePattern: regexp.MustCompile(
			`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d{3})\s+` + // timestamp
				`(\w+)\s+` + // level
				`(\d+)\s+---\s+` + // threadId ---
				`\[([^\]]+)\]\s+` + // [threadName]
				`([^:]+):\s*` + // logger:
				`(.*)$`, // message
		),

		// Basic format: 2024-01-15 10:30:45.123 INFO message
		basicPattern: regexp.MustCompile(
			`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d{3})\s+` + // timestamp
				`(\w+)\s+` + // level
				`(.*)$`, // message
		),
	}
}

// Name returns the parser name
func (p *SpringBootParser) Name() string {
	return "spring_boot"
}

// Parse attempts to parse a Spring Boot formatted log line
func (p *SpringBootParser) Parse(line string) (*ParsedLog, error) {
	log := NewParsedLog()
	log.Format = "spring_boot"

	// Try full format with tracing first
	if matches := p.fullPattern.FindStringSubmatch(line); matches != nil {
		log.Timestamp = parseSpringTimestamp(matches[1])
		log.Severity = normalizeSeverity(matches[2])
		log.SeverityNumber = severityToNumber(log.Severity)
		log.Attributes["service.name"] = strings.TrimSpace(matches[3])
		// Set trace context on the struct (OTLP compliant)
		if traceID := strings.TrimSpace(matches[4]); traceID != "" && traceID != "-" {
			log.TraceID = traceID
		}
		if spanID := strings.TrimSpace(matches[5]); spanID != "" && spanID != "-" {
			log.SpanID = spanID
		}
		if exported := strings.TrimSpace(matches[6]); exported != "" {
			log.Attributes[AttrTracingExported] = exported
		}
		log.Attributes[AttrThreadID] = matches[7]
		log.Attributes[AttrThreadName] = strings.TrimSpace(matches[8])
		log.Attributes[AttrCodeNamespace] = strings.TrimSpace(matches[9])
		log.Body = strings.TrimSpace(matches[10])
		return log, nil
	}

	// Try simple format without tracing
	if matches := p.simplePattern.FindStringSubmatch(line); matches != nil {
		log.Timestamp = parseSpringTimestamp(matches[1])
		log.Severity = normalizeSeverity(matches[2])
		log.SeverityNumber = severityToNumber(log.Severity)
		log.Attributes[AttrThreadID] = matches[3]
		log.Attributes[AttrThreadName] = strings.TrimSpace(matches[4])
		log.Attributes[AttrCodeNamespace] = strings.TrimSpace(matches[5])
		log.Body = strings.TrimSpace(matches[6])
		return log, nil
	}

	// Try basic format
	if matches := p.basicPattern.FindStringSubmatch(line); matches != nil {
		log.Timestamp = parseSpringTimestamp(matches[1])
		log.Severity = normalizeSeverity(matches[2])
		log.SeverityNumber = severityToNumber(log.Severity)
		log.Body = strings.TrimSpace(matches[3])
		return log, nil
	}

	// Not a Spring Boot formatted log
	return nil, ErrNotMatched
}

// parseSpringTimestamp parses Spring Boot timestamp format
func parseSpringTimestamp(ts string) time.Time {
	// Normalize comma decimal separator to period
	ts = strings.Replace(ts, ",", ".", 1)

	// Try common Spring Boot timestamp formats
	formats := []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t
		}
	}

	return time.Now()
}

// Log4jParser parses Log4j/Log4j2 formatted logs
type Log4jParser struct {
	// Standard Log4j pattern: YYYY-MM-DD HH:MM:SS,mmm LEVEL [thread] logger - message
	standardPattern *regexp.Regexp

	// Log4j2 pattern with markers: YYYY-MM-DD HH:MM:SS.mmm LEVEL [logger] [thread] message
	log4j2Pattern *regexp.Regexp
}

// NewLog4jParser creates a new Log4j parser
func NewLog4jParser() *Log4jParser {
	return &Log4jParser{
		// Log4j standard: 2024-01-15 10:30:45,123 INFO [main] com.example.MyClass - message
		standardPattern: regexp.MustCompile(
			`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d{3})\s+` + // timestamp
				`(\w+)\s+` + // level
				`\[([^\]]+)\]\s+` + // [thread]
				`([^\s-]+)\s+-?\s*` + // logger -
				`(.*)$`, // message
		),

		// Log4j2: 2024-01-15 10:30:45.123 INFO [com.example.MyClass] [main] message
		log4j2Pattern: regexp.MustCompile(
			`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d{3})\s+` + // timestamp
				`(\w+)\s+` + // level
				`\[([^\]]+)\]\s+` + // [logger]
				`\[([^\]]+)\]\s+` + // [thread]
				`(.*)$`, // message
		),
	}
}

// Name returns the parser name
func (p *Log4jParser) Name() string {
	return "log4j"
}

// Parse attempts to parse a Log4j formatted log line
func (p *Log4jParser) Parse(line string) (*ParsedLog, error) {
	log := NewParsedLog()
	log.Format = "log4j"

	// Try standard Log4j format
	if matches := p.standardPattern.FindStringSubmatch(line); matches != nil {
		log.Timestamp = parseSpringTimestamp(matches[1]) // Same timestamp format
		log.Severity = normalizeSeverity(matches[2])
		log.SeverityNumber = severityToNumber(log.Severity)
		log.Attributes[AttrThreadName] = strings.TrimSpace(matches[3])
		log.Attributes[AttrCodeNamespace] = strings.TrimSpace(matches[4])
		log.Body = strings.TrimSpace(matches[5])
		return log, nil
	}

	// Try Log4j2 format
	if matches := p.log4j2Pattern.FindStringSubmatch(line); matches != nil {
		log.Timestamp = parseSpringTimestamp(matches[1])
		log.Severity = normalizeSeverity(matches[2])
		log.SeverityNumber = severityToNumber(log.Severity)
		log.Attributes[AttrCodeNamespace] = strings.TrimSpace(matches[3])
		log.Attributes[AttrThreadName] = strings.TrimSpace(matches[4])
		log.Body = strings.TrimSpace(matches[5])
		return log, nil
	}

	return nil, ErrNotMatched
}

// GenericTimestampParser handles generic log formats with common timestamp patterns
type GenericTimestampParser struct {
	patterns []struct {
		name     string
		regex    *regexp.Regexp
		layout   string
		hasLevel bool
	}
}

// NewGenericTimestampParser creates a generic timestamp parser
func NewGenericTimestampParser() *GenericTimestampParser {
	p := &GenericTimestampParser{}

	p.patterns = []struct {
		name     string
		regex    *regexp.Regexp
		layout   string
		hasLevel bool
	}{
		// ISO8601 with level: 2024-01-15T10:30:45.123Z INFO message
		{
			name:     "iso8601_level",
			regex:    regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\w+)\s+(.*)$`),
			layout:   time.RFC3339Nano,
			hasLevel: true,
		},
		// ISO8601 without level: 2024-01-15T10:30:45.123Z message
		{
			name:     "iso8601",
			regex:    regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$`),
			layout:   time.RFC3339Nano,
			hasLevel: false,
		},
		// Common log format timestamp with level: [2024-01-15 10:30:45] INFO message
		{
			name:     "bracketed_level",
			regex:    regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+(\w+)\s+(.*)$`),
			layout:   "2006-01-02 15:04:05",
			hasLevel: true,
		},
		// Syslog-like: Jan 15 10:30:45 hostname process[pid]: message
		{
			name:     "syslog",
			regex:    regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`),
			layout:   "Jan 2 15:04:05",
			hasLevel: false,
		},
	}

	return p
}

// Name returns the parser name
func (p *GenericTimestampParser) Name() string {
	return "generic"
}

// Parse attempts to parse using generic timestamp patterns
func (p *GenericTimestampParser) Parse(line string) (*ParsedLog, error) {
	log := NewParsedLog()
	log.Format = "generic"

	for _, pat := range p.patterns {
		matches := pat.regex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		// Parse timestamp
		ts, err := time.Parse(pat.layout, matches[1])
		if err != nil {
			// Try RFC3339 for ISO8601 variants
			if ts, err = time.Parse(time.RFC3339, matches[1]); err != nil {
				continue
			}
		}
		log.Timestamp = ts

		switch pat.name {
		case "iso8601_level":
			log.Severity = normalizeSeverity(matches[2])
			log.SeverityNumber = severityToNumber(log.Severity)
			log.Body = strings.TrimSpace(matches[3])
		case "iso8601":
			log.Body = strings.TrimSpace(matches[2])
		case "bracketed_level":
			log.Severity = normalizeSeverity(matches[2])
			log.SeverityNumber = severityToNumber(log.Severity)
			log.Body = strings.TrimSpace(matches[3])
		case "syslog":
			log.Attributes["host.name"] = matches[2]
			log.Attributes["process.name"] = matches[3]
			if matches[4] != "" {
				log.Attributes["process.pid"] = matches[4]
			}
			log.Body = strings.TrimSpace(matches[5])
		default:
			if pat.hasLevel && len(matches) >= 4 {
				log.Severity = normalizeSeverity(matches[2])
				log.SeverityNumber = severityToNumber(log.Severity)
				log.Body = strings.TrimSpace(matches[3])
			} else if len(matches) >= 3 {
				log.Body = strings.TrimSpace(matches[2])
			}
		}

		return log, nil
	}

	return nil, ErrNotMatched
}

// normalizeSeverity normalizes various severity level names to standard OTLP names
func normalizeSeverity(level string) Severity {
	switch strings.ToUpper(level) {
	case "TRACE", "FINEST", "FINER":
		return SeverityTrace
	case "DEBUG", "FINE", "DBG":
		return SeverityDebug
	case "INFO", "INFORMATION", "INF":
		return SeverityInfo
	case "WARN", "WARNING", "WRN":
		return SeverityWarn
	case "ERROR", "ERR", "SEVERE":
		return SeverityError
	case "FATAL", "CRITICAL", "CRIT", "EMERG", "EMERGENCY", "PANIC":
		return SeverityFatal
	default:
		return SeverityInfo
	}
}

// severityToNumber converts severity to OTLP severity number
func severityToNumber(sev Severity) int {
	if num, ok := SeverityToNumber[sev]; ok {
		return num
	}
	return 0
}

// JSONLogParser attempts to parse JSON-formatted application logs
type JSONLogParser struct{}

// NewJSONLogParser creates a new JSON log parser
func NewJSONLogParser() *JSONLogParser {
	return &JSONLogParser{}
}

// Name returns the parser name
func (p *JSONLogParser) Name() string {
	return "json"
}

// Parse attempts to parse a JSON-formatted log line
func (p *JSONLogParser) Parse(line string) (*ParsedLog, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") {
		return nil, ErrNotMatched
	}

	// Try to parse as JSON log
	data, err := parseJSON(line)
	if err != nil {
		return nil, ErrNotMatched
	}

	log := NewParsedLog()
	log.Format = "json"

	// Extract common log fields
	// Message/body
	for _, key := range []string{"msg", "message", "log", "text", "body"} {
		if v, ok := data[key].(string); ok {
			log.Body = v
			delete(data, key)
			break
		}
	}

	// If no body found, use the raw line
	if log.Body == "" {
		log.Body = line
	}

	// Timestamp
	for _, key := range []string{"time", "timestamp", "ts", "@timestamp", "datetime"} {
		if v, ok := data[key]; ok {
			switch t := v.(type) {
			case string:
				if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
					log.Timestamp = ts
				} else if ts, err := time.Parse(time.RFC3339, t); err == nil {
					log.Timestamp = ts
				}
			case float64:
				// Unix timestamp (seconds or milliseconds)
				if t > 1e12 {
					log.Timestamp = time.UnixMilli(int64(t))
				} else {
					log.Timestamp = time.Unix(int64(t), 0)
				}
			}
			delete(data, key)
			break
		}
	}

	// Level/severity
	for _, key := range []string{"level", "severity", "lvl", "loglevel"} {
		if v, ok := data[key].(string); ok {
			log.Severity = normalizeSeverity(v)
			log.SeverityNumber = severityToNumber(log.Severity)
			delete(data, key)
			break
		}
	}

	// Trace correlation - set on struct for OTLP compliance
	for _, key := range []string{"trace_id", "traceId", "traceID"} {
		if v, ok := data[key].(string); ok {
			log.TraceID = v
			delete(data, key)
			break
		}
	}

	for _, key := range []string{"span_id", "spanId", "spanID"} {
		if v, ok := data[key].(string); ok {
			log.SpanID = v
			delete(data, key)
			break
		}
	}

	// Add remaining fields as attributes
	for key, value := range data {
		switch v := value.(type) {
		case string:
			log.Attributes[key] = v
		case float64:
			log.Attributes[key] = strconv.FormatFloat(v, 'f', -1, 64)
		case bool:
			log.Attributes[key] = strconv.FormatBool(v)
		}
	}

	return log, nil
}
