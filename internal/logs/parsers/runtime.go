package parsers

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// RuntimeFormat represents a container runtime log format
type RuntimeFormat int

const (
	FormatUnknown RuntimeFormat = iota
	FormatDockerJSON
	FormatCRIO
	FormatContainerd
)

// Container runtime log format parsers
// Supports: Docker JSON, CRI-O, containerd

// DockerJSONParser parses Docker JSON log format
// Format: {"log":"message\n","stream":"stdout","time":"2024-01-15T10:30:00.123456789Z"}
type DockerJSONParser struct{}

type dockerLogEntry struct {
	Log    string `json:"log"`
	Stream string `json:"stream"`
	Time   string `json:"time"`
}

// NewDockerJSONParser creates a new Docker JSON log parser
func NewDockerJSONParser() *DockerJSONParser {
	return &DockerJSONParser{}
}

// Name returns the parser name
func (p *DockerJSONParser) Name() string {
	return "docker_json"
}

// Parse parses a Docker JSON log line
func (p *DockerJSONParser) Parse(line string) (*ParsedLog, error) {
	// Quick check - must start with {
	if !strings.HasPrefix(line, "{") {
		return nil, ErrNotMatched
	}

	var entry dockerLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, ErrNotMatched
	}

	// Docker JSON format MUST have the "log" field - this is what distinguishes it
	// from generic application JSON logs. The "time" field alone is not sufficient
	// because many JSON log formats have a "time" field.
	// Docker wraps the actual log message in {"log": "actual message\n", "stream": "stdout", "time": "..."}
	if entry.Log == "" {
		return nil, ErrNotMatched
	}

	result := NewParsedLog()
	result.Format = "docker_json"
	result.OriginalLine = line

	// Parse timestamp
	if entry.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, entry.Time); err == nil {
			result.Timestamp = t
		}
	}

	// Set body (trim trailing newline that Docker adds)
	result.Body = strings.TrimSuffix(entry.Log, "\n")

	// Set stream
	if entry.Stream != "" {
		result.Stream = entry.Stream
	}

	return result, nil
}

// CRIOParser parses CRI-O log format
// Format: 2024-01-15T10:30:00.123456789+00:00 stdout F message
// Where F is the log tag (F=full, P=partial)
type CRIOParser struct {
	regex *regexp.Regexp
}

// NewCRIOParser creates a new CRI-O log parser
func NewCRIOParser() *CRIOParser {
	// CRI-O format: timestamp stream logtag message
	// Timestamp has timezone offset (not Z)
	return &CRIOParser{
		regex: regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2}) (stdout|stderr) ([FP]) (.*)$`),
	}
}

// Name returns the parser name
func (p *CRIOParser) Name() string {
	return "crio"
}

// Parse parses a CRI-O log line
func (p *CRIOParser) Parse(line string) (*ParsedLog, error) {
	// Quick check - CRI-O timestamps have + or - for timezone
	if len(line) < 35 {
		return nil, ErrNotMatched
	}
	// Must not start with { (that's Docker JSON)
	if strings.HasPrefix(line, "{") {
		return nil, ErrNotMatched
	}
	// Check for timezone offset pattern around position 25-30
	if !strings.Contains(line[20:35], "+") && !strings.Contains(line[20:35], "-") {
		return nil, ErrNotMatched
	}

	matches := p.regex.FindStringSubmatch(line)
	if matches == nil {
		return nil, ErrNotMatched
	}

	result := NewParsedLog()
	result.Format = "crio"
	result.OriginalLine = line

	// Parse timestamp (RFC3339 with nanoseconds)
	if t, err := time.Parse("2006-01-02T15:04:05.999999999-07:00", matches[1]); err == nil {
		result.Timestamp = t
	}

	// Set stream
	result.Stream = matches[2]

	// Log tag: F=full message, P=partial (message continues on next line)
	if matches[3] == "P" {
		result.Attributes["log.partial"] = "true"
	}

	// Set body
	result.Body = matches[4]

	return result, nil
}

// ContainerdParser parses containerd log format
// Format: 2024-01-15T10:30:00.123456789Z stdout F message
// Similar to CRI-O but uses Z suffix for UTC
type ContainerdParser struct {
	regex *regexp.Regexp
}

// NewContainerdParser creates a new containerd log parser
func NewContainerdParser() *ContainerdParser {
	// containerd format: timestamp stream logtag message
	// Timestamp ends with Z (UTC)
	return &ContainerdParser{
		regex: regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z) (stdout|stderr) ([FP]) (.*)$`),
	}
}

// Name returns the parser name
func (p *ContainerdParser) Name() string {
	return "containerd"
}

// Parse parses a containerd log line
func (p *ContainerdParser) Parse(line string) (*ParsedLog, error) {
	// Quick check - containerd timestamps end with Z around position 30
	if len(line) < 35 {
		return nil, ErrNotMatched
	}
	// Look for Z followed by space in the timestamp area
	if !strings.Contains(line[25:35], "Z ") {
		return nil, ErrNotMatched
	}
	// Must not start with { (that's Docker JSON)
	if strings.HasPrefix(line, "{") {
		return nil, ErrNotMatched
	}

	matches := p.regex.FindStringSubmatch(line)
	if matches == nil {
		return nil, ErrNotMatched
	}

	result := NewParsedLog()
	result.Format = "containerd"
	result.OriginalLine = line

	// Parse timestamp
	if t, err := time.Parse("2006-01-02T15:04:05.999999999Z", matches[1]); err == nil {
		result.Timestamp = t
	}

	// Set stream
	result.Stream = matches[2]

	// Log tag: F=full message, P=partial
	if matches[3] == "P" {
		result.Attributes["log.partial"] = "true"
	}

	// Set body
	result.Body = matches[4]

	return result, nil
}

// RuntimeFormatRouter routes log lines to the appropriate runtime parser
type RuntimeFormatRouter struct {
	dockerParser     *DockerJSONParser
	crioParser       *CRIOParser
	containerdParser *ContainerdParser
}

// NewRuntimeFormatRouter creates a new runtime format router
func NewRuntimeFormatRouter() *RuntimeFormatRouter {
	return &RuntimeFormatRouter{
		dockerParser:     NewDockerJSONParser(),
		crioParser:       NewCRIOParser(),
		containerdParser: NewContainerdParser(),
	}
}

// Name returns the router name
func (r *RuntimeFormatRouter) Name() string {
	return "runtime_router"
}

// Parse attempts to parse using all runtime parsers and returns the first match
func (r *RuntimeFormatRouter) Parse(line string) (*ParsedLog, error) {
	// Try Docker JSON first (cheapest check - starts with {)
	if strings.HasPrefix(line, "{") {
		if result, err := r.dockerParser.Parse(line); err == nil {
			return result, nil
		}
	}

	// Try containerd (has Z timestamp)
	if len(line) > 30 && strings.Contains(line[25:35], "Z ") {
		if result, err := r.containerdParser.Parse(line); err == nil {
			return result, nil
		}
	}

	// Try CRI-O (has timezone offset)
	if result, err := r.crioParser.Parse(line); err == nil {
		return result, nil
	}

	// No runtime format matched
	return nil, ErrNotMatched
}

// DetectRuntimeFormat detects the container runtime format from a sample line
func DetectRuntimeFormat(line string) RuntimeFormat {
	if strings.HasPrefix(line, "{") {
		var entry dockerLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil && (entry.Log != "" || entry.Time != "") {
			return FormatDockerJSON
		}
	}

	if len(line) > 35 {
		// containerd: timestamp ends with Z
		if strings.Contains(line[25:35], "Z ") {
			return FormatContainerd
		}
		// CRI-O: timestamp has timezone offset
		if strings.Contains(line[20:35], "+") || strings.Contains(line[20:35], "-") {
			return FormatCRIO
		}
	}

	return FormatUnknown
}
