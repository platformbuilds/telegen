// Package converter provides JFR to JSON conversion functionality.
package converter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Options configures the converter
type Options struct {
	ServiceName      string
	PodName          string
	Namespace        string
	ContainerName    string
	NodeName         string
	SampleIntervalMs int
	JFRCommand       string // Path to jfr command. If empty or "native", uses built-in Go parser
	PrettyJSON       bool
	UseNativeParser  bool // Use native Go parser instead of jfr command (default: true)
	Logger           *zap.Logger
}

// Converter converts JFR files to JSON
type Converter struct {
	opts         Options
	logger       *zap.Logger
	nativeParser *NativeParser
	useNative    bool
}

// New creates a new Converter
func New(opts Options) *Converter {
	if opts.SampleIntervalMs <= 0 {
		opts.SampleIntervalMs = 10
	}
	if opts.Logger == nil {
		opts.Logger, _ = zap.NewProduction()
	}

	// Determine if we should use native parser
	// Use native by default unless explicitly disabled or jfr command is specified
	useNative := opts.UseNativeParser || opts.JFRCommand == "" || opts.JFRCommand == "native" || opts.JFRCommand == "jfr"

	// If jfr command is explicitly set to a path, use external parser
	if opts.JFRCommand != "" && opts.JFRCommand != "native" && opts.JFRCommand != "jfr" {
		// Check if it's a valid path
		if _, err := os.Stat(opts.JFRCommand); err == nil {
			useNative = false
		}
	}

	// Force native if jfr command not found
	if !useNative && opts.JFRCommand != "" {
		if _, err := exec.LookPath(opts.JFRCommand); err != nil {
			opts.Logger.Info("jfr command not found, falling back to native parser",
				zap.String("jfr_command", opts.JFRCommand))
			useNative = true
		}
	}

	c := &Converter{
		opts:      opts,
		logger:    opts.Logger,
		useNative: useNative,
	}

	if useNative {
		c.nativeParser = NewNativeParser(opts)
		opts.Logger.Info("Using native Go JFR parser (no external jfr command required)")
	} else {
		opts.Logger.Info("Using external jfr command", zap.String("command", opts.JFRCommand))
	}

	return c
}

// ServiceName returns the configured service name
func (c *Converter) ServiceName() string {
	return c.opts.ServiceName
}

// PodName returns the configured pod name
func (c *Converter) PodName() string {
	return c.opts.PodName
}

// Namespace returns the configured namespace
func (c *Converter) Namespace() string {
	return c.opts.Namespace
}

// NodeName returns the configured node name
func (c *Converter) NodeName() string {
	return c.opts.NodeName
}

// ProfileEvent represents a single profiling event
type ProfileEvent struct {
	Timestamp        string `json:"timestamp"`
	EventType        string `json:"eventType"`
	ServiceName      string `json:"serviceName"`
	ServiceVersion   string `json:"serviceVersion,omitempty"` // JAR/app version if detected
	ProfileType      string `json:"profileType"`
	K8sPodName       string `json:"k8s_pod_name,omitempty"`
	K8sNamespace     string `json:"k8s_namespace,omitempty"`
	K8sContainerName string `json:"k8s_container_name,omitempty"`
	K8sNodeName      string `json:"k8s_node_name,omitempty"`

	// Thread info
	ThreadName string `json:"threadName,omitempty"`
	ThreadID   int64  `json:"threadId,omitempty"`

	// Stack trace info
	TopFunction string `json:"topFunction,omitempty"`
	TopClass    string `json:"topClass,omitempty"`
	TopMethod   string `json:"topMethod,omitempty"`
	StackPath   string `json:"stackPath,omitempty"`
	StackDepth  int    `json:"stackDepth,omitempty"`
	StackTrace  string `json:"stackTrace,omitempty"` // JSON-encoded stack frames

	// Timing
	SampleWeight    int64   `json:"sampleWeight"`
	DurationNs      int64   `json:"durationNs,omitempty"`
	SelfTimeMs      int64   `json:"selfTimeMs,omitempty"`
	SelfTimePercent float64 `json:"selfTimePercent,omitempty"`
	TotalSamples    int64   `json:"totalSamples,omitempty"`

	// Event-specific fields
	State          string `json:"state,omitempty"`
	AllocationSize int64  `json:"allocationSize,omitempty"`
	TLABSize       int64  `json:"tlabSize,omitempty"`
	ObjectClass    string `json:"objectClass,omitempty"`
	MonitorClass   string `json:"monitorClass,omitempty"`
	GCName         string `json:"gcName,omitempty"`
	GCCause        string `json:"gcCause,omitempty"`
}

// StackFrame represents a single frame in the stack trace
type StackFrame struct {
	Class       string `json:"class"`
	Method      string `json:"method"`
	Line        int    `json:"line"`
	BCI         int    `json:"bci"`
	Depth       int    `json:"depth"`
	File        string `json:"file,omitempty"`
	SelfTimeMs  int64  `json:"selfTimeMs"`
	TotalTimeMs int64  `json:"totalTimeMs"`
}

// JFR JSON structures (from jfr print --json)
type jfrOutput struct {
	Recording jfrRecording `json:"recording"`
}

type jfrRecording struct {
	Events []jfrEvent `json:"events"`
}

type jfrEvent struct {
	Type          string                 `json:"type"`
	StartTime     string                 `json:"startTime"`
	Duration      interface{}            `json:"duration"` // Can be int64 or string
	StackTrace    *jfrStackTrace         `json:"stackTrace"`
	SampledThread *jfrThread             `json:"sampledThread"`
	EventThread   *jfrThread             `json:"eventThread"`
	State         string                 `json:"state"`
	Values        map[string]interface{} `json:"-"` // Catch-all for other fields
}

type jfrStackTrace struct {
	Frames []jfrFrame `json:"frames"`
}

type jfrFrame struct {
	Method        jfrMethod `json:"method"`
	LineNumber    int       `json:"lineNumber"`
	BytecodeIndex int       `json:"bytecodeIndex"`
}

type jfrMethod struct {
	Name string  `json:"name"`
	Type jfrType `json:"type"`
}

type jfrType struct {
	Name       string `json:"name"`
	SourceFile string `json:"sourceFile"`
}

type jfrThread struct {
	OSName     string `json:"osName"`
	JavaName   string `json:"javaName"`
	OSThreadID int64  `json:"osThreadId"`
}

// ConvertResult holds the conversion result
type ConvertResult struct {
	Events       []*ProfileEvent
	TotalSamples int64
	Duration     time.Duration
	Error        error
}

// Convert converts a JFR file to JSON profile events
func (c *Converter) Convert(ctx context.Context, jfrPath string) (*ConvertResult, error) {
	// Use native parser if enabled
	if c.useNative && c.nativeParser != nil {
		return c.nativeParser.Parse(jfrPath)
	}

	// Fall back to external jfr command
	return c.convertWithExternalCommand(ctx, jfrPath)
}

// convertWithExternalCommand uses the external jfr command to parse JFR files
func (c *Converter) convertWithExternalCommand(ctx context.Context, jfrPath string) (*ConvertResult, error) {
	start := time.Now()

	c.logger.Debug("Converting JFR file with external command", zap.String("path", jfrPath))

	// Run jfr print --json
	rawJSON, err := c.runJFRCommand(ctx, jfrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to run jfr command: %w", err)
	}

	// Parse JFR JSON
	var jfrData jfrOutput
	if err := json.Unmarshal(rawJSON, &jfrData); err != nil {
		return nil, fmt.Errorf("failed to parse JFR JSON: %w", err)
	}

	// First pass: collect events and count samples
	events := make([]*ProfileEvent, 0, len(jfrData.Recording.Events))
	functionCounts := make(map[string]int64)
	var totalSamples int64

	for _, evt := range jfrData.Recording.Events {
		if !c.isProfileEvent(evt.Type) {
			continue
		}

		profileEvt := c.convertEvent(&evt)
		if profileEvt != nil {
			events = append(events, profileEvt)
			if profileEvt.TopFunction != "" {
				functionCounts[profileEvt.TopFunction]++
				totalSamples++
			}
		}
	}

	// Second pass: calculate self-time percentages
	for _, evt := range events {
		if evt.TopFunction != "" && totalSamples > 0 {
			count := functionCounts[evt.TopFunction]
			evt.SelfTimePercent = float64(count) / float64(totalSamples) * 100
			evt.SelfTimeMs = count * int64(c.opts.SampleIntervalMs)
			evt.TotalSamples = totalSamples
		}
	}

	c.logger.Info("Converted JFR file",
		zap.String("path", jfrPath),
		zap.Int("events", len(events)),
		zap.Int64("totalSamples", totalSamples),
		zap.Duration("duration", time.Since(start)),
	)

	return &ConvertResult{
		Events:       events,
		TotalSamples: totalSamples,
		Duration:     time.Since(start),
	}, nil
}

// WriteJSON writes events to a JSON lines file
func (c *Converter) WriteJSON(events []*ProfileEvent, outputPath string) error {
	// Write to temp file first for atomic rename
	tempPath := outputPath + ".tmp"

	f, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}

	writer := bufio.NewWriter(f)
	encoder := json.NewEncoder(writer)

	if c.opts.PrettyJSON {
		encoder.SetIndent("", "  ")
	}

	for _, evt := range events {
		if err := encoder.Encode(evt); err != nil {
			_ = f.Close()
			_ = os.Remove(tempPath)
			return fmt.Errorf("failed to encode event: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to close file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, outputPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

func (c *Converter) runJFRCommand(ctx context.Context, jfrPath string) ([]byte, error) {
	// Find jfr command
	jfrCmd, err := c.findJFRCommand()
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, jfrCmd, "print", "--json", jfrPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("jfr command failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// findJFRCommand locates the jfr executable
func (c *Converter) findJFRCommand() (string, error) {
	// If custom command is specified, use it directly
	if c.opts.JFRCommand != "" && c.opts.JFRCommand != "jfr" {
		if _, err := os.Stat(c.opts.JFRCommand); err == nil {
			return c.opts.JFRCommand, nil
		}
		// Try to find in PATH
		if path, err := exec.LookPath(c.opts.JFRCommand); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("configured jfr_command '%s' not found", c.opts.JFRCommand)
	}

	// Try PATH first
	if path, err := exec.LookPath("jfr"); err == nil {
		return path, nil
	}

	// Try JAVA_HOME/bin/jfr
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		candidate := filepath.Join(javaHome, "bin", "jfr")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Try common JDK installation paths
	commonPaths := []string{
		// Linux paths
		"/usr/lib/jvm/java-17-openjdk/bin/jfr",
		"/usr/lib/jvm/java-17-openjdk-amd64/bin/jfr",
		"/usr/lib/jvm/java-21-openjdk/bin/jfr",
		"/usr/lib/jvm/java-21-openjdk-amd64/bin/jfr",
		"/usr/lib/jvm/default-java/bin/jfr",
		"/usr/lib/jvm/java/bin/jfr",
		// Alpine/musl
		"/usr/lib/jvm/java-17-openjdk/bin/jfr",
		// Amazon Linux / RHEL
		"/usr/lib/jvm/java-17-amazon-corretto/bin/jfr",
		"/usr/lib/jvm/java-21-amazon-corretto/bin/jfr",
		// macOS paths
		"/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home/bin/jfr",
		"/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home/bin/jfr",
		"/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home/bin/jfr",
		"/Library/Java/JavaVirtualMachines/zulu-21.jdk/Contents/Home/bin/jfr",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			c.logger.Info("Found jfr command", zap.String("path", path))
			return path, nil
		}
	}

	// Try to find any jfr in /usr/lib/jvm
	jvmDirs := []string{"/usr/lib/jvm", "/Library/Java/JavaVirtualMachines"}
	for _, jvmDir := range jvmDirs {
		if entries, err := os.ReadDir(jvmDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					candidate := filepath.Join(jvmDir, entry.Name(), "bin", "jfr")
					if _, err := os.Stat(candidate); err == nil {
						c.logger.Info("Found jfr command", zap.String("path", candidate))
						return candidate, nil
					}
					// macOS structure
					candidate = filepath.Join(jvmDir, entry.Name(), "Contents", "Home", "bin", "jfr")
					if _, err := os.Stat(candidate); err == nil {
						c.logger.Info("Found jfr command", zap.String("path", candidate))
						return candidate, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("jfr command not found. Please ensure JDK 11+ is installed and either: " +
		"1) Add JAVA_HOME/bin to PATH, " +
		"2) Set JAVA_HOME environment variable, or " +
		"3) Configure 'jfr_command' in pipelines.jfr config with the full path to jfr executable")
}

func (c *Converter) isProfileEvent(eventType string) bool {
	profileEvents := []string{
		"jdk.ExecutionSample",
		"jdk.NativeMethodSample",
		"jdk.ObjectAllocationInNewTLAB",
		"jdk.ObjectAllocationOutsideTLAB",
		"jdk.JavaMonitorEnter",
		"jdk.JavaMonitorWait",
		"jdk.ThreadPark",
		"jdk.GarbageCollection",
	}

	for _, pe := range profileEvents {
		if strings.Contains(eventType, pe) || strings.Contains(pe, eventType) {
			return true
		}
	}
	return false
}

func (c *Converter) convertEvent(evt *jfrEvent) *ProfileEvent {
	pe := &ProfileEvent{
		Timestamp:        evt.StartTime,
		EventType:        evt.Type,
		ServiceName:      c.opts.ServiceName,
		K8sPodName:       c.opts.PodName,
		K8sNamespace:     c.opts.Namespace,
		K8sContainerName: c.opts.ContainerName,
		K8sNodeName:      c.opts.NodeName,
	}

	// Thread info
	thread := evt.SampledThread
	if thread == nil {
		thread = evt.EventThread
	}
	if thread != nil {
		pe.ThreadName = thread.OSName
		if pe.ThreadName == "" {
			pe.ThreadName = thread.JavaName
		}
		pe.ThreadID = thread.OSThreadID
	}

	// Stack trace
	if evt.StackTrace != nil && len(evt.StackTrace.Frames) > 0 {
		frames := make([]StackFrame, 0, len(evt.StackTrace.Frames))
		pathParts := make([]string, 0, 10)

		for i, f := range evt.StackTrace.Frames {
			frame := StackFrame{
				Class:  f.Method.Type.Name,
				Method: f.Method.Name,
				Line:   f.LineNumber,
				BCI:    f.BytecodeIndex,
				Depth:  i,
				File:   f.Method.Type.SourceFile,
			}
			frames = append(frames, frame)

			// Build path (short class name + method)
			shortClass := f.Method.Type.Name
			if idx := strings.LastIndex(shortClass, "."); idx >= 0 {
				shortClass = shortClass[idx+1:]
			}
			if len(pathParts) < 10 {
				pathParts = append(pathParts, fmt.Sprintf("%s.%s", shortClass, f.Method.Name))
			}
		}

		// Top frame
		top := frames[0]
		pe.TopClass = top.Class
		pe.TopMethod = top.Method
		pe.TopFunction = fmt.Sprintf("%s.%s", top.Class, top.Method)
		pe.StackPath = strings.Join(pathParts, " > ")
		pe.StackDepth = len(frames)

		// Serialize stack trace
		if stackJSON, err := json.Marshal(frames); err == nil {
			pe.StackTrace = string(stackJSON)
		}
	}

	// Event-specific fields
	pe.ProfileType = c.getProfileType(evt.Type)
	pe.State = evt.State

	switch {
	case strings.Contains(evt.Type, "ExecutionSample"), strings.Contains(evt.Type, "NativeMethodSample"):
		pe.SampleWeight = 1
		pe.DurationNs = int64(c.opts.SampleIntervalMs) * 1_000_000

	case strings.Contains(evt.Type, "ObjectAllocation"):
		// These fields would need to be extracted from the raw event
		pe.SampleWeight = 1

	case strings.Contains(evt.Type, "JavaMonitor"):
		pe.DurationNs = c.parseDuration(evt.Duration)
		pe.SampleWeight = pe.DurationNs

	case strings.Contains(evt.Type, "GarbageCollection"):
		pe.DurationNs = c.parseDuration(evt.Duration)
		pe.SampleWeight = pe.DurationNs

	default:
		pe.SampleWeight = 1
	}

	return pe
}

func (c *Converter) getProfileType(eventType string) string {
	switch {
	case strings.Contains(eventType, "ExecutionSample"):
		return "cpu"
	case strings.Contains(eventType, "NativeMethodSample"):
		return "cpu_native"
	case strings.Contains(eventType, "ObjectAllocation"):
		return "allocation"
	case strings.Contains(eventType, "JavaMonitor"):
		return "lock"
	case strings.Contains(eventType, "GarbageCollection"):
		return "gc"
	default:
		return "other"
	}
}

func (c *Converter) parseDuration(d interface{}) int64 {
	switch v := d.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		// Try parsing as duration
		if dur, err := time.ParseDuration(v); err == nil {
			return dur.Nanoseconds()
		}
	}
	return 0
}
