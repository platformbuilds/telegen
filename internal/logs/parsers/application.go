package parsers

import (
	"encoding/json"
	"encoding/xml"
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

// XMLLogParser attempts to parse XML-formatted application logs.
// Supports multiple XML log formats:
// - Log4j/Log4j2 XML layout
// - NLog XML layout
// - Serilog XML formatter
// - Windows Event Log XML
// - Generic XML logs with common elements (event, log, record, entry)
// - Custom XML formats with attribute extraction
type XMLLogParser struct {
	// Log4j XML patterns
	log4jEventPattern   *regexp.Regexp
	log4jMessagePattern *regexp.Regexp

	// NLog XML patterns
	nlogPattern *regexp.Regexp

	// Serilog XML patterns
	serilogPattern *regexp.Regexp

	// Windows Event Log pattern
	windowsEventPattern *regexp.Regexp

	// Generic XML event pattern
	genericPattern *regexp.Regexp

	// XML declaration detection
	xmlDeclPattern *regexp.Regexp

	// Extract XML attributes: key="value" or key='value'
	attrPattern *regexp.Regexp

	// Extract XML elements: <key>value</key> or <ns:key>value</ns:key>
	elementPattern *regexp.Regexp

	// Extract CDATA content: <![CDATA[content]]>
	cdataPattern *regexp.Regexp

	// Namespace prefix pattern
	namespacePattern *regexp.Regexp
}

// NewXMLLogParser creates a new XML log parser with comprehensive format support
func NewXMLLogParser() *XMLLogParser {
	return &XMLLogParser{
		// Log4j XML: <log4j:event level="INFO" timestamp="1234567890" ...>...</log4j:event>
		log4jEventPattern: regexp.MustCompile(`(?i)<log4j:event[^>]*>`),
		log4jMessagePattern: regexp.MustCompile(`(?i)<log4j:message>(?:<!\[CDATA\[)?([^\]<]+)(?:\]\]>)?</log4j:message>`),

		// NLog XML: <nlog ...><log level="Info" ...>...</log></nlog> or just <log level="Info"...>
		// Note: Must NOT match LogEvent, logentry, logevent, logrecord - use negative lookahead equivalent
		nlogPattern: regexp.MustCompile(`(?i)<(?:nlog:)?log(?:(?:entry|event|record))[^>]*level="([^"]*)"[^>]*>|<(?:nlog:)?log[^a-z][^>]*level="([^"]*)"[^>]*>`),

		// Serilog XML: <LogEvent Timestamp="..." Level="..."...>
		// Must be checked BEFORE NLog pattern
		serilogPattern: regexp.MustCompile(`(?i)<LogEvent\s+[^>]*>`),

		// Windows Event Log: <Event xmlns="..."><System>...</System><EventData>...</EventData></Event>
		windowsEventPattern: regexp.MustCompile(`(?i)<Event[^>]*xmlns[^>]*>`),

		// Generic: <event>, <log>, <record>, <entry>, <logentry>, <logevent> elements
		genericPattern: regexp.MustCompile(`(?i)<(event|log|record|entry|logentry|logevent|logrecord|message)[^>]*>`),

		// XML declaration: <?xml version="1.0" ...?>
		xmlDeclPattern: regexp.MustCompile(`^\s*<\?xml[^?]*\?>`),

		// Extract XML attributes: key="value" or key='value' (supports namespaced attrs)
		attrPattern: regexp.MustCompile(`([\w:.-]+)=["']([^"']*)["']`),

		// Extract XML elements: <key>value</key> or <ns:key>value</ns:key>
		elementPattern: regexp.MustCompile(`<([\w:.-]+)>([^<]*)</[\w:.-]+>`),

		// Extract CDATA content
		cdataPattern: regexp.MustCompile(`<!\[CDATA\[([^\]]*(?:\][^\]]+)*)\]\]>`),

		// Namespace prefix for stripping
		namespacePattern: regexp.MustCompile(`^[\w]+:`),
	}
}

// Name returns the parser name
func (p *XMLLogParser) Name() string {
	return "xml"
}

// Parse attempts to parse an XML-formatted log line
func (p *XMLLogParser) Parse(line string) (*ParsedLog, error) {
	line = strings.TrimSpace(line)

	// Quick detection - must contain XML-like content
	if !p.isXMLContent(line) {
		return nil, ErrNotMatched
	}

	log := NewParsedLog()
	log.Format = "xml"
	log.Attributes[AttrBodyContentType] = "xml"

	// Strip XML declaration if present
	line = p.xmlDeclPattern.ReplaceAllString(line, "")
	line = strings.TrimSpace(line)

	// Try specific XML log formats in order of specificity

	// 1. Log4j/Log4j2 XML format
	if p.log4jEventPattern.MatchString(line) {
		return p.parseLog4jXML(line, log)
	}

	// 2. Serilog XML format (<LogEvent ...>) - check BEFORE NLog
	if p.serilogPattern.MatchString(line) {
		return p.parseSerilogXML(line, log)
	}

	// 3. Windows Event Log XML - check BEFORE generic
	if p.windowsEventPattern.MatchString(line) {
		return p.parseWindowsEventXML(line, log)
	}

	// 4. NLog XML format (<log level="...">) - simple <log> element
	if p.isNLogFormat(line) {
		return p.parseNLogXML(line, log)
	}

	// 5. Generic XML log format
	if p.genericPattern.MatchString(line) {
		return p.parseGenericXML(line, log)
	}

	// 6. Fallback: Any valid XML with attributes
	return p.parseFallbackXML(line, log)
}

// isXMLContent performs quick detection of XML content
func (p *XMLLogParser) isXMLContent(line string) bool {
	// Must contain angle brackets
	if !strings.Contains(line, "<") || !strings.Contains(line, ">") {
		return false
	}

	// Reject HTML documents
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		return false
	}

	// Must start with < (after trimming) or contain XML declaration
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "<") {
		return true
	}

	return false
}

// isNLogFormat checks if line is NLog XML format: <log level="..."> but NOT <LogEvent>, <logentry>, etc.
func (p *XMLLogParser) isNLogFormat(line string) bool {
	lower := strings.ToLower(line)
	
	// Must start with <log (case insensitive) and have level attribute
	if !strings.Contains(lower, "<log") || !strings.Contains(lower, "level=") {
		return false
	}
	
	// Exclude LogEvent (Serilog), logentry, logevent, logrecord
	if strings.Contains(lower, "<logevent") ||
		strings.Contains(lower, "<logentry") ||
		strings.Contains(lower, "<logrecord") {
		return false
	}
	
	// Check for simple <log with level attribute pattern
	if regexp.MustCompile(`(?i)<log\s+[^>]*level=`).MatchString(line) ||
		regexp.MustCompile(`(?i)<nlog:log\s+[^>]*level=`).MatchString(line) {
		return true
	}
	
	return false
}

// parseLog4jXML parses Log4j/Log4j2 XML layout format
func (p *XMLLogParser) parseLog4jXML(line string, log *ParsedLog) (*ParsedLog, error) {
	log.Format = "log4j_xml"

	// Extract level attribute
	if matches := regexp.MustCompile(`(?i)level=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Severity = normalizeSeverity(matches[1])
		log.SeverityNumber = severityToNumber(log.Severity)
	}

	// Extract timestamp (milliseconds since epoch)
	if matches := regexp.MustCompile(`(?i)timestamp=["'](\d+)["']`).FindStringSubmatch(line); matches != nil {
		if ts, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			log.Timestamp = time.UnixMilli(ts)
		}
	}

	// Extract logger name
	if matches := regexp.MustCompile(`(?i)logger=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Attributes[AttrCodeNamespace] = matches[1]
	}

	// Extract thread
	if matches := regexp.MustCompile(`(?i)thread=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Attributes[AttrThreadName] = matches[1]
	}

	// Extract message (with CDATA support)
	log.Body = p.extractXMLMessage(line)
	if log.Body == "" {
		log.Body = line
	}

	// Extract throwable/exception if present
	if matches := regexp.MustCompile(`(?i)<log4j:throwable>(?:<!\[CDATA\[)?([^\]<]+)`).FindStringSubmatch(line); matches != nil {
		log.Attributes[AttrExceptionStacktrace] = strings.TrimSpace(matches[1])
	}

	// Extract remaining attributes
	p.extractXMLAttributes(log, line)

	return log, nil
}

// parseNLogXML parses NLog XML layout format
func (p *XMLLogParser) parseNLogXML(line string, log *ParsedLog) (*ParsedLog, error) {
	log.Format = "nlog_xml"

	// Extract level using simple pattern
	if matches := regexp.MustCompile(`(?i)level=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Severity = normalizeSeverity(matches[1])
		log.SeverityNumber = severityToNumber(log.Severity)
	}

	// Extract timestamp (NLog typically uses ISO8601)
	p.extractTimestamp(log, line)

	// Extract logger
	if matches := regexp.MustCompile(`(?i)logger=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Attributes[AttrCodeNamespace] = matches[1]
	}

	// Extract message
	log.Body = p.extractXMLMessage(line)
	if log.Body == "" {
		log.Body = line
	}

	// Extract exception
	if matches := regexp.MustCompile(`(?i)<exception[^>]*>([^<]*)</exception>`).FindStringSubmatch(line); matches != nil {
		log.Attributes[AttrExceptionMessage] = strings.TrimSpace(matches[1])
	}

	p.extractXMLAttributes(log, line)
	return log, nil
}

// parseSerilogXML parses Serilog XML formatter output
func (p *XMLLogParser) parseSerilogXML(line string, log *ParsedLog) (*ParsedLog, error) {
	log.Format = "serilog_xml"

	// Extract Level attribute
	if matches := regexp.MustCompile(`(?i)Level=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Severity = normalizeSeverity(matches[1])
		log.SeverityNumber = severityToNumber(log.Severity)
	}

	// Extract Timestamp
	if matches := regexp.MustCompile(`(?i)Timestamp=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Timestamp = p.parseTimestampString(matches[1])
	}

	// Extract MessageTemplate or RenderedMessage
	if matches := regexp.MustCompile(`(?i)<RenderedMessage>([^<]*)</RenderedMessage>`).FindStringSubmatch(line); matches != nil {
		log.Body = p.extractCDATA(matches[1])
	} else if matches := regexp.MustCompile(`(?i)<MessageTemplate>([^<]*)</MessageTemplate>`).FindStringSubmatch(line); matches != nil {
		log.Body = p.extractCDATA(matches[1])
	} else {
		log.Body = p.extractXMLMessage(line)
	}

	if log.Body == "" {
		log.Body = line
	}

	// Extract Exception
	if matches := regexp.MustCompile(`(?i)<Exception>([^<]*)</Exception>`).FindStringSubmatch(line); matches != nil {
		log.Attributes[AttrExceptionStacktrace] = p.extractCDATA(matches[1])
	}

	p.extractXMLAttributes(log, line)
	return log, nil
}

// parseWindowsEventXML parses Windows Event Log XML format
func (p *XMLLogParser) parseWindowsEventXML(line string, log *ParsedLog) (*ParsedLog, error) {
	log.Format = "windows_event_xml"

	// Extract Level (Windows uses numeric levels: 1=Critical, 2=Error, 3=Warning, 4=Information)
	if matches := regexp.MustCompile(`(?i)<Level>(\d+)</Level>`).FindStringSubmatch(line); matches != nil {
		level, _ := strconv.Atoi(matches[1])
		switch level {
		case 1:
			log.Severity = SeverityFatal
		case 2:
			log.Severity = SeverityError
		case 3:
			log.Severity = SeverityWarn
		case 4:
			log.Severity = SeverityInfo
		case 5:
			log.Severity = SeverityDebug
		default:
			log.Severity = SeverityInfo
		}
		log.SeverityNumber = severityToNumber(log.Severity)
	}

	// Extract TimeCreated
	if matches := regexp.MustCompile(`(?i)TimeCreated[^>]*SystemTime=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Timestamp = p.parseTimestampString(matches[1])
	}

	// Extract Provider Name
	if matches := regexp.MustCompile(`(?i)Provider[^>]*Name=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Attributes["event.provider"] = matches[1]
	}

	// Extract EventID
	if matches := regexp.MustCompile(`(?i)<EventID[^>]*>(\d+)</EventID>`).FindStringSubmatch(line); matches != nil {
		log.Attributes["event.id"] = matches[1]
	}

	// Extract Computer
	if matches := regexp.MustCompile(`(?i)<Computer>([^<]+)</Computer>`).FindStringSubmatch(line); matches != nil {
		log.ResourceAttributes["host.name"] = matches[1]
	}

	// Extract EventData - look for Data elements anywhere in the line
	// Pattern: <Data>content</Data> or <Data Name="...">content</Data>
	dataMatches := regexp.MustCompile(`(?i)<Data[^>]*>([^<]+)</Data>`).FindAllStringSubmatch(line, -1)
	if len(dataMatches) > 0 {
		var dataParts []string
		for _, dm := range dataMatches {
			if len(dm) > 1 && strings.TrimSpace(dm[1]) != "" {
				dataParts = append(dataParts, strings.TrimSpace(dm[1]))
			}
		}
		if len(dataParts) > 0 {
			log.Body = strings.Join(dataParts, " | ")
		}
	}

	if log.Body == "" {
		// Try Message element
		if matches := regexp.MustCompile(`(?i)<Message>([^<]*)</Message>`).FindStringSubmatch(line); matches != nil {
			log.Body = p.extractCDATA(matches[1])
		}
	}

	if log.Body == "" {
		log.Body = line
	}

	p.extractXMLAttributes(log, line)
	return log, nil
}

// parseGenericXML parses generic XML log formats
func (p *XMLLogParser) parseGenericXML(line string, log *ParsedLog) (*ParsedLog, error) {
	log.Format = "generic_xml"

	// Extract severity from common attribute/element names
	p.extractSeverity(log, line)

	// Extract timestamp
	p.extractTimestamp(log, line)

	// Extract message body
	log.Body = p.extractXMLMessage(line)
	if log.Body == "" {
		log.Body = line
	}

	// Extract trace context if present
	if matches := regexp.MustCompile(`(?i)(?:trace[-_]?id|traceid)=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.TraceID = matches[1]
	}
	if matches := regexp.MustCompile(`(?i)(?:span[-_]?id|spanid)=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.SpanID = matches[1]
	}

	p.extractXMLAttributes(log, line)
	return log, nil
}

// parseFallbackXML handles any XML-like content that wasn't matched by specific parsers
func (p *XMLLogParser) parseFallbackXML(line string, log *ParsedLog) (*ParsedLog, error) {
	// Validate it looks like XML (has attributes or elements)
	if !strings.Contains(line, "=\"") && !strings.Contains(line, "='") && !p.elementPattern.MatchString(line) {
		return nil, ErrNotMatched
	}

	log.Format = "xml"
	log.Body = line

	// Try to extract any timestamp
	p.extractTimestamp(log, line)

	// Try to extract any severity
	p.extractSeverity(log, line)

	// Extract all attributes
	p.extractXMLAttributes(log, line)

	return log, nil
}

// extractXMLMessage extracts message content from common XML message elements
func (p *XMLLogParser) extractXMLMessage(line string) string {
	// Message element patterns in priority order
	msgPatterns := []string{
		`(?i)<(?:log4j:)?message>([^<]*(?:<!\[CDATA\[[^\]]*\]\]>[^<]*)*)</(?:log4j:)?message>`,
		`(?i)<msg>([^<]*)</msg>`,
		`(?i)<body>([^<]*)</body>`,
		`(?i)<text>([^<]*)</text>`,
		`(?i)<content>([^<]*)</content>`,
		`(?i)<data>([^<]*)</data>`,
		`(?i)<description>([^<]*)</description>`,
	}

	for _, pat := range msgPatterns {
		if matches := regexp.MustCompile(pat).FindStringSubmatch(line); matches != nil {
			return strings.TrimSpace(p.extractCDATA(matches[1]))
		}
	}

	return ""
}

// extractCDATA extracts content from CDATA sections or returns the string as-is
func (p *XMLLogParser) extractCDATA(s string) string {
	if matches := p.cdataPattern.FindStringSubmatch(s); matches != nil {
		return strings.TrimSpace(matches[1])
	}
	return strings.TrimSpace(s)
}

// extractTimestamp extracts timestamp from common XML patterns
func (p *XMLLogParser) extractTimestamp(log *ParsedLog, line string) {
	tsPatterns := []string{
		`(?i)timestamp=["']([^"']+)["']`,
		`(?i)time=["']([^"']+)["']`,
		`(?i)datetime=["']([^"']+)["']`,
		`(?i)date=["']([^"']+)["']`,
		`(?i)Snt=["']([^"']+)["']`,    // FIXML
		`(?i)Tm=["']([^"']+)["']`,     // Time shorthand
		`(?i)TS=["']([^"']+)["']`,     // Timestamp shorthand
		`(?i)<timestamp>([^<]+)</timestamp>`,
		`(?i)<time>([^<]+)</time>`,
		`(?i)<datetime>([^<]+)</datetime>`,
	}

	for _, pat := range tsPatterns {
		if matches := regexp.MustCompile(pat).FindStringSubmatch(line); matches != nil {
			if ts := p.parseTimestampString(matches[1]); !ts.IsZero() {
				log.Timestamp = ts
				return
			}
		}
	}
}

// extractSeverity extracts severity level from common XML patterns
func (p *XMLLogParser) extractSeverity(log *ParsedLog, line string) {
	levelPatterns := []string{
		`(?i)level=["']([^"']+)["']`,
		`(?i)severity=["']([^"']+)["']`,
		`(?i)priority=["']([^"']+)["']`,
		`(?i)loglevel=["']([^"']+)["']`,
		`(?i)<level>([^<]+)</level>`,
		`(?i)<severity>([^<]+)</severity>`,
		`(?i)<priority>([^<]+)</priority>`,
	}

	for _, pat := range levelPatterns {
		if matches := regexp.MustCompile(pat).FindStringSubmatch(line); matches != nil {
			log.Severity = normalizeSeverity(matches[1])
			log.SeverityNumber = severityToNumber(log.Severity)
			return
		}
	}
}

// parseTimestampString attempts to parse a timestamp string in various formats
func (p *XMLLogParser) parseTimestampString(s string) time.Time {
	s = strings.TrimSpace(s)

	// Try common timestamp formats
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"01/02/2006 15:04:05",
		"02/01/2006 15:04:05",
		"2006/01/02 15:04:05",
	}

	for _, format := range formats {
		if ts, err := time.Parse(format, s); err == nil {
			return ts
		}
	}

	// Try parsing as Unix timestamp (seconds or milliseconds)
	if tsNum, err := strconv.ParseInt(s, 10, 64); err == nil {
		if tsNum > 1e12 {
			return time.UnixMilli(tsNum)
		}
		return time.Unix(tsNum, 0)
	}

	return time.Time{}
}

// extractXMLAttributes extracts all XML attributes and simple elements as log attributes
func (p *XMLLogParser) extractXMLAttributes(log *ParsedLog, line string) {
	// Skip keys that are already handled specially
	skipKeys := map[string]bool{
		"level":       true,
		"severity":    true,
		"timestamp":   true,
		"time":        true,
		"datetime":    true,
		"message":     true,
		"msg":         true,
		"body":        true,
		"text":        true,
		"xmlns":       true,
		"version":     true,
		"encoding":    true,
	}

	// First, try to parse the full XML structure recursively
	// This extracts ALL nested elements and attributes as key-value pairs
	p.extractFullXMLStructure(log, line, skipKeys)

	// Fallback: Extract XML attributes using regex: key="value" or key='value'
	attrMatches := p.attrPattern.FindAllStringSubmatch(line, -1)
	for _, match := range attrMatches {
		if len(match) >= 3 {
			key := match[1]
			value := match[2]

			// Strip namespace prefix for skip check
			keyLower := strings.ToLower(p.namespacePattern.ReplaceAllString(key, ""))

			// Skip xmlns declarations and already-handled keys
			if strings.HasPrefix(strings.ToLower(key), "xmlns") {
				continue
			}
			if skipKeys[keyLower] || value == "" {
				continue
			}

			// Use original key (with namespace) in attribute - only if not already set
			attrKey := "xml." + key
			if _, exists := log.Attributes[attrKey]; !exists {
				log.Attributes[attrKey] = value
			}
		}
	}

	// Fallback: Extract simple XML elements: <key>value</key>
	elemMatches := p.elementPattern.FindAllStringSubmatch(line, -1)
	for _, match := range elemMatches {
		if len(match) >= 3 {
			key := match[1]
			value := strings.TrimSpace(p.extractCDATA(match[2]))

			keyLower := strings.ToLower(p.namespacePattern.ReplaceAllString(key, ""))

			if skipKeys[keyLower] || value == "" {
				continue
			}

			// Don't overwrite if we already have this from attributes
			if _, exists := log.Attributes["xml."+key]; !exists {
				log.Attributes["xml."+key] = value
			}
		}
	}
}

// extractFullXMLStructure parses XML recursively and extracts ALL elements/attributes as key-value pairs
// using dot notation for nested paths (e.g., xml.root.child.grandchild)
func (p *XMLLogParser) extractFullXMLStructure(log *ParsedLog, data string, skipKeys map[string]bool) {
	decoder := xml.NewDecoder(strings.NewReader(data))
	decoder.Strict = false // Be lenient with malformed XML

	// Stack to track element path
	var pathStack []string

	// Track element counts for array indexing
	elementCounts := make(map[string]int)

	for {
		token, err := decoder.Token()
		if err != nil {
			break // End of document or error
		}

		switch t := token.(type) {
		case xml.StartElement:
			// Get element name (with namespace prefix if present)
			elemName := t.Name.Local
			if t.Name.Space != "" {
				// Use short namespace prefix if available, otherwise skip space
				elemName = t.Name.Local
			}

			// Build the path key
			var pathKey string
			if len(pathStack) > 0 {
				parentPath := strings.Join(pathStack, ".")
				// Check for array elements (same name at same level)
				countKey := parentPath + "." + elemName
				count := elementCounts[countKey]
				if count > 0 {
					pathKey = countKey + "." + strconv.Itoa(count)
				} else {
					pathKey = countKey
				}
				elementCounts[countKey] = count + 1
			} else {
				pathKey = elemName
			}

			pathStack = append(pathStack, elemName)

			// Extract all attributes from this element
			for _, attr := range t.Attr {
				// Skip xmlns declarations
				if strings.HasPrefix(strings.ToLower(attr.Name.Local), "xmlns") ||
					attr.Name.Space == "xmlns" {
					continue
				}

				attrName := attr.Name.Local
				attrNameLower := strings.ToLower(attrName)

				// Skip standard keys unless they have meaningful values
				if skipKeys[attrNameLower] {
					continue
				}

				if attr.Value != "" {
					attrKey := "xml." + pathKey + "." + attrName
					log.Attributes[attrKey] = attr.Value
				}
			}

		case xml.EndElement:
			if len(pathStack) > 0 {
				pathStack = pathStack[:len(pathStack)-1]
			}

		case xml.CharData:
			content := strings.TrimSpace(string(t))
			if content != "" && len(pathStack) > 0 {
				// Build the path for this text content
				pathKey := strings.Join(pathStack, ".")
				attrKey := "xml." + pathKey

				// Check if this is a skip key
				lastElem := pathStack[len(pathStack)-1]
				if !skipKeys[strings.ToLower(lastElem)] {
					// Store the text content - prefer longer values
					if existing, exists := log.Attributes[attrKey]; !exists || len(content) > len(existing) {
						log.Attributes[attrKey] = content
					}
				}
			}

		case xml.Comment:
			// Optionally extract XML comments
			comment := strings.TrimSpace(string(t))
			if comment != "" && len(comment) < 500 {
				if len(pathStack) > 0 {
					pathKey := strings.Join(pathStack, ".")
					log.Attributes["xml."+pathKey+"._comment"] = comment
				}
			}
		}
	}
}

// tryParseXMLStructured attempts to parse XML using encoding/xml for well-formed documents
// This is used as a validation step and to extract nested structures
func (p *XMLLogParser) tryParseXMLStructured(data string) bool {
	decoder := xml.NewDecoder(strings.NewReader(data))
	for {
		_, err := decoder.Token()
		if err != nil {
			// If we got any tokens before error, it's likely XML
			return err.Error() == "EOF"
		}
	}
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
	
	// Handle escaped JSON strings (e.g., "{\"key\":\"value\"}" or '{"key":"value"}')
	// This is common when JSON is embedded in another format or from certain logging frameworks
	if (strings.HasPrefix(line, `"`) && strings.HasSuffix(line, `"`)) ||
		(strings.HasPrefix(line, `'`) && strings.HasSuffix(line, `'`)) {
		// Try to unquote the string
		unquoted, err := strconv.Unquote(line)
		if err == nil && (strings.HasPrefix(unquoted, "{") || strings.HasPrefix(unquoted, "[")) {
			// Recursively parse the unescaped JSON
			return p.Parse(unquoted)
		}
		// Also try simple quote removal for single-quoted JSON
		if strings.HasPrefix(line, `'`) {
			unquoted = line[1 : len(line)-1]
			if strings.HasPrefix(unquoted, "{") || strings.HasPrefix(unquoted, "[") {
				return p.Parse(unquoted)
			}
		}
	}
	
	// Support both JSON objects {...} and arrays [...]
	if !strings.HasPrefix(line, "{") && !strings.HasPrefix(line, "[") {
		return nil, ErrNotMatched
	}

	// Handle JSON arrays - for logging purposes, treat as a single log entry
	if strings.HasPrefix(line, "[") {
		// Validate it's valid JSON
		var arr []interface{}
		if err := json.Unmarshal([]byte(line), &arr); err != nil {
			return nil, ErrNotMatched
		}
		
		log := NewParsedLog()
		log.Format = "json_array"
		log.Body = line
		log.Attributes["json.array_length"] = strconv.Itoa(len(arr))
		return log, nil
	}

	// Try to parse as JSON object
	data, err := parseJSON(line)
	if err != nil {
		return nil, ErrNotMatched
	}

	log := NewParsedLog()
	log.Format = "json"

	// Extract common log fields
	// Message/body - check various common keys used by different logging frameworks
	bodyKeys := []string{
		"msg", "message", "log", "text", "body",  // Standard
		"_msg", "_message",                        // VictoriaMetrics/underscore prefix
		"content", "data", "payload",              // Alternative names
		"event", "raw",                            // Event-based
	}
	for _, key := range bodyKeys {
		if v, ok := data[key].(string); ok {
			log.Body = v
			delete(data, key)
			break
		}
	}

	// If body is escaped JSON, try to parse it recursively
	if log.Body != "" {
		trimmedBody := strings.TrimSpace(log.Body)
		
		// Check for escaped JSON (starts with quote) or raw JSON
		if strings.HasPrefix(trimmedBody, `"`) || strings.HasPrefix(trimmedBody, `'`) {
			// Try to unquote first
			if unquoted, err := strconv.Unquote(trimmedBody); err == nil {
				trimmedBody = unquoted
			} else if strings.HasPrefix(trimmedBody, `'`) && strings.HasSuffix(trimmedBody, `'`) {
				// Handle single quotes
				trimmedBody = trimmedBody[1 : len(trimmedBody)-1]
			}
		}
		
		// If body looks like JSON, try to parse it and merge fields
		if strings.HasPrefix(trimmedBody, "{") {
			if nestedData, err := parseJSON(trimmedBody); err == nil {
				// First, extract message from nested JSON
				nestedBody := ""
				for _, msgKey := range bodyKeys {
					if v, ok := nestedData[msgKey].(string); ok {
						nestedBody = v
						delete(nestedData, msgKey)
						break
					}
				}
				
				// Use nested body if found, otherwise use unescaped JSON
				if nestedBody != "" {
					log.Body = nestedBody
				} else {
					// No message field in nested JSON, use unescaped JSON as body
					log.Body = trimmedBody
				}
				
				// Extract level from nested JSON if not already set
				for _, levelKey := range []string{"level", "severity", "lvl", "loglevel"} {
					if v, ok := nestedData[levelKey].(string); ok {
						log.Severity = normalizeSeverity(v)
						log.SeverityNumber = severityToNumber(log.Severity)
						delete(nestedData, levelKey)
						break
					}
				}
				
				// Merge remaining nested JSON fields into attributes
				for k, v := range nestedData {
					attrValue := jsonValueToString(v)
					if attrValue != "" {
						log.Attributes[k] = attrValue
					}
				}
				log.Attributes["json.nested"] = "true"
			}
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

	// Add remaining fields as attributes with deep extraction
	// This recursively extracts ALL nested keys using dot notation (e.g., json.order.customer.name)
	skipKeys := map[string]bool{
		"msg": true, "message": true, "log": true, "text": true, "body": true,
		"_msg": true, "_message": true, "content": true, "data": true, "payload": true,
		"event": true, "raw": true, "time": true, "timestamp": true, "ts": true,
		"@timestamp": true, "datetime": true, "level": true, "severity": true,
		"lvl": true, "loglevel": true, "trace_id": true, "traceId": true,
		"traceID": true, "span_id": true, "spanId": true, "spanID": true,
	}
	extractJSONStructure(log, data, "json", skipKeys)

	return log, nil
}

// extractJSONStructure recursively extracts all nested JSON keys as dot-notation attributes
// For example: {"order": {"customer": {"name": "John"}}} becomes json.order.customer.name = "John"
func extractJSONStructure(log *ParsedLog, data map[string]interface{}, prefix string, skipKeys map[string]bool) {
	for key, value := range data {
		// Skip already-handled keys at root level
		if prefix == "json" && skipKeys[key] {
			continue
		}

		attrKey := prefix + "." + key

		switch v := value.(type) {
		case map[string]interface{}:
			// Nested object - recurse with extended path
			extractJSONStructure(log, v, attrKey, skipKeys)

		case []interface{}:
			// Array - extract each element with index
			extractJSONArray(log, v, attrKey, skipKeys)

		case string:
			if v != "" {
				log.Attributes[attrKey] = v
			}

		case float64:
			// Check if it's actually an integer
			if v == float64(int64(v)) {
				log.Attributes[attrKey] = strconv.FormatInt(int64(v), 10)
			} else {
				log.Attributes[attrKey] = strconv.FormatFloat(v, 'f', -1, 64)
			}

		case bool:
			log.Attributes[attrKey] = strconv.FormatBool(v)

		case nil:
			// Skip null values

		default:
			// Unknown type - try JSON serialization
			if b, err := json.Marshal(v); err == nil && string(b) != "null" {
				log.Attributes[attrKey] = string(b)
			}
		}
	}
}

// extractJSONArray recursively extracts array elements as indexed attributes
// For example: {"items": ["a", "b"]} becomes json.items.0 = "a", json.items.1 = "b"
// For arrays of objects: {"orders": [{"id": 1}]} becomes json.orders.0.id = "1"
func extractJSONArray(log *ParsedLog, arr []interface{}, prefix string, skipKeys map[string]bool) {
	// Also store array length
	log.Attributes[prefix+"._length"] = strconv.Itoa(len(arr))

	for i, elem := range arr {
		elemKey := prefix + "." + strconv.Itoa(i)

		switch v := elem.(type) {
		case map[string]interface{}:
			// Array of objects - recurse
			extractJSONStructure(log, v, elemKey, skipKeys)

		case []interface{}:
			// Nested array
			extractJSONArray(log, v, elemKey, skipKeys)

		case string:
			if v != "" {
				log.Attributes[elemKey] = v
			}

		case float64:
			if v == float64(int64(v)) {
				log.Attributes[elemKey] = strconv.FormatInt(int64(v), 10)
			} else {
				log.Attributes[elemKey] = strconv.FormatFloat(v, 'f', -1, 64)
			}

		case bool:
			log.Attributes[elemKey] = strconv.FormatBool(v)

		case nil:
			// Skip null values

		default:
			if b, err := json.Marshal(v); err == nil && string(b) != "null" {
				log.Attributes[elemKey] = string(b)
			}
		}
	}
}

// jsonValueToString converts a JSON value to its string representation.
// Handles: string, float64, bool, nil, nested objects, and arrays.
func jsonValueToString(v interface{}) string {
	if v == nil {
		return "" // Skip null values in attributes
	}
	
	switch val := v.(type) {
	case string:
		return val
	case float64:
		// Check if it's actually an integer
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	case map[string]interface{}:
		// Nested object - serialize to JSON string
		if b, err := json.Marshal(val); err == nil {
			return string(b)
		}
		return ""
	case []interface{}:
		// Array - serialize to JSON string
		if b, err := json.Marshal(val); err == nil {
			return string(b)
		}
		return ""
	default:
		// Unknown type - try to convert via JSON
		if b, err := json.Marshal(val); err == nil {
			return string(b)
		}
		return ""
	}
}

// =============================================================================
// FIXML Parser - Financial Information eXchange Markup Language
// =============================================================================

// FIXMLParser parses FIXML (Financial Information eXchange Markup Language) messages
// commonly used in trading systems for order execution, trade reporting, and market data.
// Supports FIX versions 4.x, 5.0, 5.0SP1, 5.0SP2
type FIXMLParser struct {
	// Detect FIXML root element
	fixmlPattern *regexp.Regexp

	// Common FIXML message types
	messageTypePatterns map[string]*regexp.Regexp

	// Extract XML attributes
	attrPattern *regexp.Regexp

	// Common FIXML field mappings to human-readable names
	fieldMappings map[string]string
}

// NewFIXMLParser creates a new FIXML parser for trading system messages
func NewFIXMLParser() *FIXMLParser {
	return &FIXMLParser{
		// Match FIXML root element with version info
		fixmlPattern: regexp.MustCompile(`(?i)<FIXML[^>]*>`),

		// Message type patterns
		messageTypePatterns: map[string]*regexp.Regexp{
			"order":           regexp.MustCompile(`(?i)<(Order|NewOrdSingle|OrdCxlRplcReq|OrdCxlReq)[^>]*>`),
			"execution":       regexp.MustCompile(`(?i)<(ExecRpt|TrdCaptRpt|TrdRpt)[^>]*>`),
			"trade_match":     regexp.MustCompile(`(?i)<(TrdMtchRpt|TrdMtch)[^>]*>`),
			"quote":           regexp.MustCompile(`(?i)<(Quote|QuotReq|MassQuote)[^>]*>`),
			"market_data":     regexp.MustCompile(`(?i)<(MktData|MDReq|MDFullGrp|MDIncGrp)[^>]*>`),
			"position":        regexp.MustCompile(`(?i)<(PosRpt|PosMntReq)[^>]*>`),
			"allocation":      regexp.MustCompile(`(?i)<(Alloc|AllocRpt)[^>]*>`),
			"confirmation":    regexp.MustCompile(`(?i)<(Conf|TrdAllocRpt)[^>]*>`),
			"settlement":      regexp.MustCompile(`(?i)<(SetlInst|SetlObligation)[^>]*>`),
			"security":        regexp.MustCompile(`(?i)<(SecDef|SecList|SecTypReq)[^>]*>`),
			"party":           regexp.MustCompile(`(?i)<(Pty|PtyDtl)[^>]*>`),
			"collateral":      regexp.MustCompile(`(?i)<(CollReq|CollRpt|CollAssgn)[^>]*>`),
		},

		// Extract XML attributes
		attrPattern: regexp.MustCompile(`([\w:]+)=["']([^"']*)["']`),

		// FIXML field tag to human-readable name mapping
		fieldMappings: map[string]string{
			// Identifiers
			"TrdID":    "trade_id",
			"OrdID":    "order_id",
			"ClOrdID":  "client_order_id",
			"ExecID":   "execution_id",
			"SecID":    "security_id",
			"ID":       "id",
			"ReqID":    "request_id",
			"RptID":    "report_id",
			"AllocID":  "allocation_id",
			"ConfID":   "confirmation_id",
			"PosID":    "position_id",

			// Parties
			"SID":      "sender_id",
			"TID":      "target_id",
			"Acct":     "account",
			"AcctIDSrc": "account_id_source",

			// Instrument
			"Sym":      "symbol",
			"InstrmtID": "instrument_id",
			"Src":      "id_source",
			"SecTyp":   "security_type",
			"CFI":      "cfi_code",
			"MMY":      "maturity_month_year",
			"Mat":      "maturity_date",
			"Strk":     "strike_price",
			"StrkCcy":  "strike_currency",
			"OptTyp":   "option_type",
			"Exch":     "exchange",
			"Ccy":      "currency",

			// Pricing/Quantity
			"Px":       "price",
			"LastPx":   "last_price",
			"AvgPx":    "average_price",
			"StopPx":   "stop_price",
			"Qty":      "quantity",
			"LastQty":  "last_quantity",
			"CumQty":   "cumulative_quantity",
			"LeavesQty": "leaves_quantity",
			"MinQty":   "minimum_quantity",
			"OrdQty":   "order_quantity",

			// Order/Trade details
			"Side":     "side",
			"OrdTyp":   "order_type",
			"TmInForce": "time_in_force",
			"ExecTyp":  "execution_type",
			"OrdStat":  "order_status",
			"TrdTyp":   "trade_type",
			"RptTyp":   "report_type",
			"TransTyp": "transaction_type",
			"SettlTyp": "settlement_type",
			"SettlDt":  "settlement_date",

			// Timestamps
			"Snt":      "send_time",
			"TrdDt":    "trade_date",
			"TxnTm":    "transaction_time",
			"BizDt":    "business_date",
			"RegTmStmp": "regulatory_timestamp",
			"TrdRegTS": "trade_regulatory_timestamp",

			// Market
			"LastMkt":  "last_market",
			"MktID":    "market_id",
			"MktSegID": "market_segment_id",

			// Misc
			"v":        "fix_version",
			"xv":       "extension_version",
			"cv":       "custom_version",
			"Txt":      "text",
			"Stat":     "status",
		},
	}
}

// Name returns the parser name
func (p *FIXMLParser) Name() string {
	return "fixml"
}

// Parse attempts to parse a FIXML-formatted message
func (p *FIXMLParser) Parse(line string) (*ParsedLog, error) {
	line = strings.TrimSpace(line)

	// Must contain FIXML root element
	if !p.fixmlPattern.MatchString(line) {
		return nil, ErrNotMatched
	}

	log := NewParsedLog()
	log.Format = "fixml"
	log.Attributes[AttrBodyContentType] = "fixml"

	// Detect message type
	msgType := p.detectMessageType(line)
	log.Attributes["fixml.message_type"] = msgType

	// Extract FIX version info from FIXML root
	if matches := regexp.MustCompile(`(?i)<FIXML[^>]*v=["']([^"']+)["']`).FindStringSubmatch(line); matches != nil {
		log.Attributes["fixml.fix_version"] = matches[1]
	}

	// Extract all attributes and map to human-readable names
	p.extractFIXMLFields(log, line)

	// Extract timestamp
	p.extractFIXMLTimestamp(log, line)

	// Build a summary body
	log.Body = p.buildFIXMLSummary(log, msgType, line)

	return log, nil
}

// detectMessageType identifies the FIXML message type
func (p *FIXMLParser) detectMessageType(line string) string {
	for msgType, pattern := range p.messageTypePatterns {
		if pattern.MatchString(line) {
			return msgType
		}
	}
	return "unknown"
}

// extractFIXMLFields extracts all FIXML attributes and maps them to readable names
func (p *FIXMLParser) extractFIXMLFields(log *ParsedLog, line string) {
	attrMatches := p.attrPattern.FindAllStringSubmatch(line, -1)

	for _, match := range attrMatches {
		if len(match) >= 3 {
			key := match[1]
			value := match[2]

			// Skip empty values and common XML noise
			if value == "" {
				continue
			}
			if strings.HasPrefix(key, "xmlns") {
				continue
			}

			// Map to human-readable name if available
			readableName, hasMapping := p.fieldMappings[key]
			if hasMapping {
				log.Attributes["fixml."+readableName] = value
			} else {
				// Keep original attribute name with fixml prefix
				log.Attributes["fixml."+key] = value
			}
		}
	}
}

// extractFIXMLTimestamp extracts timestamp from common FIXML time fields
func (p *FIXMLParser) extractFIXMLTimestamp(log *ParsedLog, line string) {
	// Priority order for timestamp fields
	tsFields := []string{"Snt", "TxnTm", "TrdRegTS", "RegTmStmp", "TrdDt"}

	for _, field := range tsFields {
		pattern := regexp.MustCompile(field + `=["']([^"']+)["']`)
		if matches := pattern.FindStringSubmatch(line); matches != nil {
			ts := p.parseFIXTimestamp(matches[1])
			if !ts.IsZero() {
				log.Timestamp = ts
				return
			}
		}
	}
}

// parseFIXTimestamp parses FIX timestamp formats
func (p *FIXMLParser) parseFIXTimestamp(s string) time.Time {
	// FIX timestamp formats
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05.999Z",
		"2006-01-02T15:04:05",
		"20060102-15:04:05.999999999",    // FIX UTCTimestamp with nanoseconds
		"20060102-15:04:05.999",          // FIX UTCTimestamp with milliseconds
		"20060102-15:04:05",              // FIX UTCTimestamp
		"20060102",                       // FIX LocalMktDate
	}

	for _, format := range formats {
		if ts, err := time.Parse(format, s); err == nil {
			return ts
		}
	}

	return time.Time{}
}

// buildFIXMLSummary creates a human-readable summary of the FIXML message
func (p *FIXMLParser) buildFIXMLSummary(log *ParsedLog, msgType string, line string) string {
	var parts []string

	// Message type
	parts = append(parts, "FIXML "+strings.ToUpper(msgType))

	// Key fields based on message type
	switch msgType {
	case "trade_match", "execution":
		if tradeID := log.Attributes["fixml.trade_id"]; tradeID != "" {
			parts = append(parts, "TrdID:"+tradeID)
		}
		if sym := log.Attributes["fixml.symbol"]; sym != "" {
			parts = append(parts, "Sym:"+sym)
		}
		if px := log.Attributes["fixml.last_price"]; px != "" {
			parts = append(parts, "Px:"+px)
		}
	case "order":
		if ordID := log.Attributes["fixml.order_id"]; ordID != "" {
			parts = append(parts, "OrdID:"+ordID)
		}
		if sym := log.Attributes["fixml.symbol"]; sym != "" {
			parts = append(parts, "Sym:"+sym)
		}
		if side := log.Attributes["fixml.side"]; side != "" {
			parts = append(parts, "Side:"+p.mapSide(side))
		}
	case "quote":
		if sym := log.Attributes["fixml.symbol"]; sym != "" {
			parts = append(parts, "Sym:"+sym)
		}
	default:
		// Include original line for unknown types
		return line
	}

	if len(parts) <= 1 {
		return line
	}

	return strings.Join(parts, " | ")
}

// mapSide converts FIX side code to readable string
func (p *FIXMLParser) mapSide(code string) string {
	sides := map[string]string{
		"1": "Buy", "2": "Sell", "3": "BuyMinus", "4": "SellPlus",
		"5": "SellShort", "6": "SellShortExempt", "7": "Undisclosed",
		"8": "Cross", "9": "CrossShort", "A": "CrossShortExempt",
		"B": "AsDefined", "C": "Opposite", "D": "Subscribe", "E": "Redeem",
	}
	if readable, ok := sides[code]; ok {
		return readable
	}
	return code
}

// =============================================================================
// ISO 8583 Parser - Card Transaction Messages
// =============================================================================

// ISO8583Parser parses ISO 8583 financial transaction messages
// commonly used for card transactions, ATM, POS, and payment networks.
// Supports both text/hex representations of ISO 8583 messages.
type ISO8583Parser struct {
	// Pattern to detect ISO 8583 message (MTI + bitmap + data elements)
	mtiPattern *regexp.Regexp

	// Data element name mappings (DE1-DE128)
	dataElementNames map[int]string

	// Pattern for hex-encoded messages
	hexPattern *regexp.Regexp

	// Pattern for key-value formatted ISO 8583 (common logging format)
	kvPattern *regexp.Regexp
}

// NewISO8583Parser creates a new ISO 8583 parser for card transaction messages
func NewISO8583Parser() *ISO8583Parser {
	return &ISO8583Parser{
		// MTI pattern: 4-digit message type indicator (e.g., 0100, 0200, 0400, 0800)
		mtiPattern: regexp.MustCompile(`^(0[1248][0123][0-9])`),

		// Hex-encoded bitmap pattern
		hexPattern: regexp.MustCompile(`^[0-9A-Fa-f]{16,}`),

		// Key-value pattern (common in logs): DE002=pan, DE003=processing_code, etc.
		kvPattern: regexp.MustCompile(`(?i)(DE|F|Field|DataElement)[\s_-]?(\d{1,3})\s*[:=]\s*["']?([^"'\s,;]+)["']?`),

		// Standard ISO 8583 data element names
		dataElementNames: map[int]string{
			1:   "bitmap_secondary",
			2:   "pan",
			3:   "processing_code",
			4:   "amount_transaction",
			5:   "amount_settlement",
			6:   "amount_cardholder_billing",
			7:   "transmission_datetime",
			9:   "conversion_rate_settlement",
			10:  "conversion_rate_cardholder_billing",
			11:  "stan",
			12:  "local_transaction_time",
			13:  "local_transaction_date",
			14:  "expiration_date",
			15:  "settlement_date",
			16:  "currency_conversion_date",
			17:  "capture_date",
			18:  "merchant_category_code",
			19:  "acquiring_institution_country",
			22:  "pos_entry_mode",
			23:  "card_sequence_number",
			25:  "pos_condition_code",
			26:  "pos_capture_code",
			27:  "authorization_id_length",
			28:  "amount_transaction_fee",
			29:  "amount_settlement_fee",
			30:  "amount_transaction_processing_fee",
			31:  "amount_settlement_processing_fee",
			32:  "acquiring_institution_id",
			33:  "forwarding_institution_id",
			34:  "pan_extended",
			35:  "track2_data",
			36:  "track3_data",
			37:  "retrieval_reference_number",
			38:  "authorization_code",
			39:  "response_code",
			40:  "service_restriction_code",
			41:  "card_acceptor_terminal_id",
			42:  "card_acceptor_id",
			43:  "card_acceptor_name_location",
			44:  "additional_response_data",
			45:  "track1_data",
			48:  "additional_data_private",
			49:  "currency_code_transaction",
			50:  "currency_code_settlement",
			51:  "currency_code_cardholder_billing",
			52:  "pin_data",
			53:  "security_related_control_info",
			54:  "additional_amounts",
			55:  "emv_data",
			56:  "reserved_iso",
			57:  "reserved_national",
			58:  "reserved_national_2",
			59:  "reserved_national_3",
			60:  "reserved_private",
			61:  "reserved_private_2",
			62:  "reserved_private_3",
			63:  "reserved_private_4",
			64:  "mac",
			70:  "network_management_code",
			90:  "original_data_elements",
			95:  "replacement_amounts",
			100: "receiving_institution_id",
			102: "account_id_1",
			103: "account_id_2",
			120: "record_data",
			123: "pos_data_code",
			124: "nfc_data",
			125: "reserved_private_5",
			126: "reserved_private_6",
			127: "reserved_private_7",
			128: "mac_2",
		},
	}
}

// Name returns the parser name
func (p *ISO8583Parser) Name() string {
	return "iso8583"
}

// Parse attempts to parse an ISO 8583 message
func (p *ISO8583Parser) Parse(line string) (*ParsedLog, error) {
	line = strings.TrimSpace(line)

	// Try different ISO 8583 representations:
	// 1. Key-value format (most common in logs)
	// 2. Raw MTI + bitmap format
	// 3. JSON with ISO 8583 fields

	// Try key-value format first (most common in log files)
	if matches := p.kvPattern.FindAllStringSubmatch(line, -1); len(matches) >= 2 {
		return p.parseKeyValueFormat(line, matches)
	}

	// Try to detect if it's an MTI at the start (0100, 0200, 0400, 0800, etc.)
	if p.mtiPattern.MatchString(line) {
		return p.parseRawFormat(line)
	}

	// Try JSON format with ISO 8583 field names
	if strings.Contains(line, `"mti"`) || strings.Contains(line, `"MTI"`) ||
		strings.Contains(line, `"processing_code"`) || strings.Contains(line, `"pan"`) {
		return p.parseJSONFormat(line)
	}

	// Check for DE[XX] patterns anywhere in the line
	if regexp.MustCompile(`(?i)DE\d{1,3}[=:]`).MatchString(line) {
		return p.parseKeyValueFormat(line, p.kvPattern.FindAllStringSubmatch(line, -1))
	}

	return nil, ErrNotMatched
}

// parseKeyValueFormat parses ISO 8583 from key-value log format
func (p *ISO8583Parser) parseKeyValueFormat(line string, matches [][]string) (*ParsedLog, error) {
	log := NewParsedLog()
	log.Format = "iso8583"
	log.Attributes[AttrBodyContentType] = "iso8583"

	for _, match := range matches {
		if len(match) >= 4 {
			deNum, err := strconv.Atoi(match[2])
			if err != nil {
				continue
			}
			value := match[3]

			// Get human-readable name
			deName := p.getDataElementName(deNum)
			log.Attributes["iso8583."+deName] = value

			// Mask sensitive data
			if deNum == 2 || deNum == 35 || deNum == 45 { // PAN, Track data
				log.Attributes["iso8583."+deName] = p.maskPAN(value)
			}
			if deNum == 52 { // PIN data
				log.Attributes["iso8583."+deName] = "********"
			}
		}
	}

	// Extract MTI if present in the line
	if mtiMatch := regexp.MustCompile(`(?i)(?:MTI|MessageType|MsgType)\s*[:=]\s*["']?(\d{4})["']?`).FindStringSubmatch(line); mtiMatch != nil {
		log.Attributes["iso8583.mti"] = mtiMatch[1]
		log.Attributes["iso8583.message_type"] = p.getMTIDescription(mtiMatch[1])
	}

	// Build summary body
	log.Body = p.buildISO8583Summary(log)

	return log, nil
}

// parseRawFormat parses raw ISO 8583 format (MTI + bitmap + data)
func (p *ISO8583Parser) parseRawFormat(line string) (*ParsedLog, error) {
	log := NewParsedLog()
	log.Format = "iso8583"
	log.Attributes[AttrBodyContentType] = "iso8583"

	// Extract MTI (first 4 characters)
	if len(line) >= 4 {
		mti := line[:4]
		log.Attributes["iso8583.mti"] = mti
		log.Attributes["iso8583.message_type"] = p.getMTIDescription(mti)
	}

	// For raw format, store the entire message as body (further parsing requires spec knowledge)
	log.Body = "ISO8583 " + p.getMTIDescription(log.Attributes["iso8583.mti"]) + " | Raw: " + line

	return log, nil
}

// parseJSONFormat parses ISO 8583 from JSON representation
func (p *ISO8583Parser) parseJSONFormat(line string) (*ParsedLog, error) {
	// Try to parse as JSON
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		return nil, ErrNotMatched
	}

	log := NewParsedLog()
	log.Format = "iso8583"
	log.Attributes[AttrBodyContentType] = "iso8583"

	// Extract known ISO 8583 fields
	fieldMappings := map[string]string{
		"mti":                       "mti",
		"MTI":                       "mti",
		"message_type":              "message_type",
		"pan":                       "pan",
		"PAN":                       "pan",
		"processing_code":           "processing_code",
		"amount":                    "amount_transaction",
		"amount_transaction":        "amount_transaction",
		"stan":                      "stan",
		"STAN":                      "stan",
		"rrn":                       "retrieval_reference_number",
		"RRN":                       "retrieval_reference_number",
		"retrieval_reference_number": "retrieval_reference_number",
		"auth_code":                 "authorization_code",
		"authorization_code":        "authorization_code",
		"response_code":             "response_code",
		"terminal_id":               "card_acceptor_terminal_id",
		"merchant_id":               "card_acceptor_id",
		"currency_code":             "currency_code_transaction",
		"card_expiry":               "expiration_date",
		"mcc":                       "merchant_category_code",
	}

	for jsonKey, isoKey := range fieldMappings {
		if val, ok := data[jsonKey]; ok {
			value := jsonValueToString(val)
			if value == "" {
				continue
			}

			// Mask PAN
			if isoKey == "pan" {
				value = p.maskPAN(value)
			}

			log.Attributes["iso8583."+isoKey] = value
		}
	}

	// Add MTI description
	if mti := log.Attributes["iso8583.mti"]; mti != "" {
		log.Attributes["iso8583.message_type"] = p.getMTIDescription(mti)
	}

	log.Body = p.buildISO8583Summary(log)

	return log, nil
}

// getDataElementName returns the human-readable name for a data element
func (p *ISO8583Parser) getDataElementName(de int) string {
	if name, ok := p.dataElementNames[de]; ok {
		return name
	}
	return "de" + strconv.Itoa(de)
}

// getMTIDescription returns a human-readable description of the MTI
func (p *ISO8583Parser) getMTIDescription(mti string) string {
	if len(mti) != 4 {
		return "Unknown"
	}

	// Message class (position 1)
	class := map[byte]string{
		'0': "Reserved",
		'1': "Authorization",
		'2': "Financial",
		'3': "File Actions",
		'4': "Reversal/Chargeback",
		'5': "Reconciliation",
		'6': "Administrative",
		'7': "Fee Collection",
		'8': "Network Management",
		'9': "Reserved",
	}

	// Message function (position 2)
	function := map[byte]string{
		'0': "Request",
		'1': "Request Response",
		'2': "Advice",
		'3': "Advice Response",
		'4': "Notification",
		'5': "Notification Ack",
		'8': "Response Ack",
		'9': "Negative Ack",
	}

	classDesc := class[mti[1]]
	funcDesc := function[mti[2]]

	if classDesc == "" {
		classDesc = "Unknown"
	}
	if funcDesc == "" {
		funcDesc = "Unknown"
	}

	return classDesc + " " + funcDesc
}

// maskPAN masks a PAN/card number for security
func (p *ISO8583Parser) maskPAN(pan string) string {
	// Remove any non-digit characters
	digits := regexp.MustCompile(`\D`).ReplaceAllString(pan, "")

	if len(digits) < 10 {
		return "****"
	}

	// Show first 6 and last 4 digits
	return digits[:6] + strings.Repeat("*", len(digits)-10) + digits[len(digits)-4:]
}

// buildISO8583Summary creates a human-readable summary of the ISO 8583 message
func (p *ISO8583Parser) buildISO8583Summary(log *ParsedLog) string {
	var parts []string

	// Message type
	if msgType := log.Attributes["iso8583.message_type"]; msgType != "" {
		parts = append(parts, "ISO8583 "+msgType)
	} else if mti := log.Attributes["iso8583.mti"]; mti != "" {
		parts = append(parts, "ISO8583 MTI:"+mti)
	} else {
		parts = append(parts, "ISO8583")
	}

	// Key transaction fields
	if amt := log.Attributes["iso8583.amount_transaction"]; amt != "" {
		// Format amount (typically in minor units)
		parts = append(parts, "Amt:"+amt)
	}
	if respCode := log.Attributes["iso8583.response_code"]; respCode != "" {
		parts = append(parts, "RC:"+respCode+" ("+p.getResponseCodeDescription(respCode)+")")
	}
	if rrn := log.Attributes["iso8583.retrieval_reference_number"]; rrn != "" {
		parts = append(parts, "RRN:"+rrn)
	}
	if stan := log.Attributes["iso8583.stan"]; stan != "" {
		parts = append(parts, "STAN:"+stan)
	}

	return strings.Join(parts, " | ")
}

// getResponseCodeDescription returns description for common ISO 8583 response codes
func (p *ISO8583Parser) getResponseCodeDescription(code string) string {
	codes := map[string]string{
		"00": "Approved",
		"01": "Refer to Issuer",
		"03": "Invalid Merchant",
		"04": "Pick Up Card",
		"05": "Do Not Honor",
		"06": "Error",
		"07": "Pick Up Card Special",
		"08": "Honor with ID",
		"10": "Partial Approval",
		"12": "Invalid Transaction",
		"13": "Invalid Amount",
		"14": "Invalid Card Number",
		"15": "No Such Issuer",
		"19": "Re-enter Transaction",
		"21": "Unable to Back Out",
		"25": "Unable to Locate",
		"28": "File Temporarily Unavailable",
		"30": "Format Error",
		"41": "Lost Card",
		"43": "Stolen Card",
		"51": "Insufficient Funds",
		"54": "Expired Card",
		"55": "Invalid PIN",
		"57": "Transaction Not Permitted",
		"58": "Transaction Not Permitted Terminal",
		"59": "Suspected Fraud",
		"61": "Exceeds Withdrawal Limit",
		"62": "Restricted Card",
		"63": "Security Violation",
		"65": "Exceeds Withdrawal Frequency",
		"68": "Response Timeout",
		"75": "PIN Tries Exceeded",
		"76": "Invalid/Nonexistent Account",
		"77": "Inconsistent Data",
		"78": "No Account",
		"80": "Invalid Date",
		"81": "Encryption Error",
		"82": "CVV Failure",
		"83": "Unable to Verify PIN",
		"85": "No Reason to Decline",
		"86": "Cannot Verify PIN",
		"87": "Purchase Amount Only",
		"88": "MAC Failure",
		"89": "Authentication Failure",
		"91": "Issuer Not Available",
		"92": "Routing Error",
		"94": "Duplicate Transaction",
		"96": "System Error",
	}

	if desc, ok := codes[code]; ok {
		return desc
	}
	return "Unknown"
}
