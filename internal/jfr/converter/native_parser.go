// Package converter provides JFR to JSON conversion functionality.
// native_parser.go implements a pure Go JFR parser using github.com/grafana/jfr-parser
// This eliminates the need for the external jfr command from JDK.
package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	jfrparser "github.com/grafana/jfr-parser/parser"
	"github.com/grafana/jfr-parser/parser/types"
	"go.uber.org/zap"
)

// NativeParser parses JFR files using pure Go (no external jfr command needed)
type NativeParser struct {
	opts   Options
	logger *zap.Logger
}

// NewNativeParser creates a new native JFR parser
func NewNativeParser(opts Options) *NativeParser {
	if opts.SampleIntervalMs <= 0 {
		opts.SampleIntervalMs = 10
	}
	if opts.Logger == nil {
		opts.Logger, _ = zap.NewProduction()
	}
	return &NativeParser{
		opts:   opts,
		logger: opts.Logger,
	}
}

// inferServiceNameFromPath extracts a service name from the JFR file path.
// It looks for common patterns like:
//   - petclinic_2026-01-31_recording.jfr → petclinic
//   - myapp-recording-001.jfr → myapp
//   - /path/to/appname/recording.jfr → appname
func inferServiceNameFromPath(jfrPath string) string {
	// Get just the filename without extension
	base := filepath.Base(jfrPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))

	// Remove common suffixes like _recording, -recording, _profile, etc.
	suffixPatterns := regexp.MustCompile(`[-_](recording|profile|dump|jfr|flight[-_]?recorder)[-_\d]*$`)
	name = suffixPatterns.ReplaceAllString(name, "")

	// Remove date/timestamp patterns like _2026-01-31, -20260131, etc.
	datePatterns := regexp.MustCompile(`[-_]\d{4}[-_]?\d{2}[-_]?\d{2}([-_T]\d{2}[-_]?\d{2}[-_]?\d{2})?`)
	name = datePatterns.ReplaceAllString(name, "")

	// Remove trailing numbers and separators
	name = regexp.MustCompile(`[-_]+\d*$`).ReplaceAllString(name, "")
	name = strings.Trim(name, "-_")

	// If we got a reasonable name, return it
	if len(name) >= 2 && name != "jfr" && name != "recording" && name != "profile" {
		return name
	}

	// Fall back to parent directory name
	dir := filepath.Dir(jfrPath)
	if dir != "." && dir != "/" {
		parentDir := filepath.Base(dir)
		if parentDir != "." && parentDir != "/" && len(parentDir) >= 2 {
			return parentDir
		}
	}

	return ""
}

// inferVersionFromPath attempts to extract a version number from the JFR file path.
// It looks for common version patterns like:
//   - myapp-1.2.3_recording.jfr → 1.2.3
//   - petclinic-v2.0.0-SNAPSHOT.jfr → 2.0.0-SNAPSHOT
//   - /app/myservice-3.1.4/recording.jfr → 3.1.4
func inferVersionFromPath(jfrPath string) string {
	// Common version patterns:
	// - semantic version: 1.2.3, v1.2.3
	// - with suffix: 1.2.3-SNAPSHOT, 1.2.3-RC1, 1.2.3.RELEASE
	// - simple: v2, 1.0
	versionPattern := regexp.MustCompile(`[-_v](\d+(?:\.\d+)*(?:[-.](?:SNAPSHOT|RELEASE|RC\d*|M\d*|GA|FINAL|beta|alpha)\d*)?)[-_.]`)

	// Try to find version in filename
	base := filepath.Base(jfrPath)
	if matches := versionPattern.FindStringSubmatch(base); len(matches) > 1 {
		return matches[1]
	}

	// Try parent directory
	dir := filepath.Dir(jfrPath)
	if dir != "." && dir != "/" {
		parentDir := filepath.Base(dir)
		if matches := versionPattern.FindStringSubmatch(parentDir + "-"); len(matches) > 1 {
			return matches[1]
		}
	}

	// Try a simpler pattern for just version at end of name
	simpleVersionPattern := regexp.MustCompile(`[-_](\d+\.\d+(?:\.\d+)?(?:[-.][\w]+)?)$`)
	nameWithoutExt := strings.TrimSuffix(base, filepath.Ext(base))
	if matches := simpleVersionPattern.FindStringSubmatch(nameWithoutExt); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// JFRMetadata contains application and JVM metadata extracted from JFR events
type JFRMetadata struct {
	// From jdk.JVMInformation event
	JVMName       string // e.g., "OpenJDK 64-Bit Server VM"
	JVMVersion    string // e.g., "17.0.1+12"
	JavaArguments string // Command line arguments (main class, jar, etc.)
	PID           int64

	// From jdk.InitialSystemProperty events
	SunJavaCommand  string // sun.java.command property - contains main class or jar
	JavaVersion     string // java.version property
	JavaVMName      string // java.vm.name property
	JavaVMVersion   string // java.vm.version property
	JavaVMVendor    string // java.vm.vendor property
	JavaClassPath   string // java.class.path property
	UserDir         string // user.dir property
	ApplicationName string // if set via -Dapp.name or similar
}

// extractJFRMetadata extracts application metadata from JFR events using the jfr CLI tool.
// This provides accurate service name and version by reading jdk.JVMInformation
// and jdk.InitialSystemProperty events from the JFR file.
// If jfrCommand is empty, it will try to find jfr in PATH.
func extractJFRMetadata(jfrPath, jfrCommand string, logger *zap.Logger) (*JFRMetadata, error) {
	if jfrCommand == "" {
		// Try common locations
		jfrCommand = findJFRCommand()
		if jfrCommand == "" {
			return nil, fmt.Errorf("jfr command not found")
		}
	}

	meta := &JFRMetadata{}

	// Extract JVM information event
	jvmInfo, err := extractJVMInformation(jfrPath, jfrCommand)
	if err != nil {
		logger.Debug("Failed to extract JVM information", zap.Error(err))
	} else {
		meta.JVMName = jvmInfo.JVMName
		meta.JVMVersion = jvmInfo.JVMVersion
		meta.JavaArguments = jvmInfo.JavaArguments
		meta.PID = jvmInfo.PID
	}

	// Extract system properties
	props, err := extractSystemProperties(jfrPath, jfrCommand)
	if err != nil {
		logger.Debug("Failed to extract system properties", zap.Error(err))
	} else {
		meta.SunJavaCommand = props["sun.java.command"]
		meta.JavaVersion = props["java.version"]
		meta.JavaVMName = props["java.vm.name"]
		meta.JavaVMVersion = props["java.vm.version"]
		meta.JavaVMVendor = props["java.vm.vendor"]
		meta.JavaClassPath = props["java.class.path"]
		meta.UserDir = props["user.dir"]
		// Check common app name properties
		if appName := props["app.name"]; appName != "" {
			meta.ApplicationName = appName
		} else if appName := props["application.name"]; appName != "" {
			meta.ApplicationName = appName
		} else if appName := props["spring.application.name"]; appName != "" {
			meta.ApplicationName = appName
		}
	}

	return meta, nil
}

// findJFRCommand looks for the jfr command in common locations
func findJFRCommand() string {
	// Try PATH first
	if path, err := exec.LookPath("jfr"); err == nil {
		return path
	}

	// Try JAVA_HOME
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		jfrPath := filepath.Join(javaHome, "bin", "jfr")
		if _, err := os.Stat(jfrPath); err == nil {
			return jfrPath
		}
	}

	return ""
}

// extractJVMInformation extracts the jdk.JVMInformation event from a JFR file
func extractJVMInformation(jfrPath, jfrCommand string) (*JFRMetadata, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, jfrCommand, "print", "--json", "--events", "jdk.JVMInformation", jfrPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("jfr command failed: %w", err)
	}

	// Parse JSON output
	var result struct {
		Recording struct {
			Events []struct {
				Type   string `json:"type"`
				Values struct {
					JVMName       string `json:"jvmName"`
					JVMVersion    string `json:"jvmVersion"`
					JavaArguments string `json:"javaArguments"`
					PID           int64  `json:"pid"`
				} `json:"values"`
			} `json:"events"`
		} `json:"recording"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JVM information: %w", err)
	}

	meta := &JFRMetadata{}
	if len(result.Recording.Events) > 0 {
		evt := result.Recording.Events[0]
		meta.JVMName = evt.Values.JVMName
		meta.JVMVersion = evt.Values.JVMVersion
		meta.JavaArguments = evt.Values.JavaArguments
		meta.PID = evt.Values.PID
	}

	return meta, nil
}

// extractSystemProperties extracts jdk.InitialSystemProperty events from a JFR file
func extractSystemProperties(jfrPath, jfrCommand string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, jfrCommand, "print", "--json", "--events", "jdk.InitialSystemProperty", jfrPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("jfr command failed: %w", err)
	}

	// Parse JSON output
	var result struct {
		Recording struct {
			Events []struct {
				Type   string `json:"type"`
				Values struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"values"`
			} `json:"events"`
		} `json:"recording"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse system properties: %w", err)
	}

	props := make(map[string]string)
	for _, evt := range result.Recording.Events {
		props[evt.Values.Key] = evt.Values.Value
	}

	return props, nil
}

// parseServiceNameFromMetadata extracts a clean service name from JFR metadata
func parseServiceNameFromMetadata(meta *JFRMetadata) string {
	// Priority:
	// 1. Explicit application name property
	if meta.ApplicationName != "" {
		return meta.ApplicationName
	}

	// 2. Parse from sun.java.command (main class or jar)
	if meta.SunJavaCommand != "" {
		return parseServiceNameFromJavaCommand(meta.SunJavaCommand)
	}

	// 3. Parse from javaArguments
	if meta.JavaArguments != "" {
		return parseServiceNameFromJavaCommand(meta.JavaArguments)
	}

	return ""
}

// parseServiceNameFromJavaCommand extracts service name from java command line
// Examples:
//   - "com.example.MyApp arg1 arg2" → "MyApp"
//   - "myapp.jar arg1" → "myapp"
//   - "/path/to/myapp-1.0.0.jar" → "myapp"
//   - "org.springframework.boot.loader.JarLauncher" with classpath → use jar name
func parseServiceNameFromJavaCommand(cmd string) string {
	if cmd == "" {
		return ""
	}

	// Split into parts and get the first one (the main class or jar)
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	mainPart := parts[0]

	// Check if it's a JAR file
	if strings.HasSuffix(strings.ToLower(mainPart), ".jar") {
		// Extract jar name without extension and version
		jarName := filepath.Base(mainPart)
		jarName = strings.TrimSuffix(jarName, ".jar")
		jarName = strings.TrimSuffix(jarName, ".JAR")

		// Remove version suffix (e.g., myapp-1.0.0 → myapp)
		versionPattern := regexp.MustCompile(`[-_]\d+(\.\d+)*[-.]?\w*$`)
		jarName = versionPattern.ReplaceAllString(jarName, "")

		return jarName
	}

	// It's a main class - extract class name without package
	// e.g., "com.example.MyApp" → "MyApp"
	if strings.Contains(mainPart, ".") {
		parts := strings.Split(mainPart, ".")
		className := parts[len(parts)-1]

		// Handle Spring Boot launchers - they're generic, not useful as service name
		if className == "JarLauncher" || className == "WarLauncher" || className == "PropertiesLauncher" {
			return ""
		}

		return className
	}

	return mainPart
}

// parseVersionFromMetadata extracts version information from JFR metadata
func parseVersionFromMetadata(meta *JFRMetadata) string {
	// Try to extract version from the JAR name in sun.java.command
	if meta.SunJavaCommand != "" {
		if version := extractVersionFromJavaCommand(meta.SunJavaCommand); version != "" {
			return version
		}
	}

	// Fall back to Java version (not ideal but better than nothing for context)
	return ""
}

// extractVersionFromJavaCommand tries to extract version from jar name
// e.g., "myapp-1.2.3.jar" → "1.2.3"
func extractVersionFromJavaCommand(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	mainPart := parts[0]

	// Check if it's a JAR file with version
	if strings.HasSuffix(strings.ToLower(mainPart), ".jar") {
		jarName := filepath.Base(mainPart)
		jarName = strings.TrimSuffix(jarName, ".jar")
		jarName = strings.TrimSuffix(jarName, ".JAR")

		// Extract version from jar name
		versionPattern := regexp.MustCompile(`[-_](\d+(?:\.\d+)*(?:[-.](?:SNAPSHOT|RELEASE|RC\d*|M\d*|GA|FINAL|beta|alpha)\d*)?)$`)
		if matches := versionPattern.FindStringSubmatch(jarName); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// ServiceName returns the configured service name
func (p *NativeParser) ServiceName() string {
	return p.opts.ServiceName
}

// PodName returns the configured pod name
func (p *NativeParser) PodName() string {
	return p.opts.PodName
}

// Namespace returns the configured namespace
func (p *NativeParser) Namespace() string {
	return p.opts.Namespace
}

// NodeName returns the configured node name
func (p *NativeParser) NodeName() string {
	return p.opts.NodeName
}

// Parse parses a JFR file and returns profile events
func (p *NativeParser) Parse(jfrPath string) (*ConvertResult, error) {
	start := time.Now()

	p.logger.Debug("Parsing JFR file natively", zap.String("path", jfrPath))

	// Read entire file
	data, err := os.ReadFile(jfrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JFR file: %w", err)
	}

	// Create parser with symbol processing enabled
	parser := jfrparser.NewParser(data, jfrparser.Options{
		SymbolProcessor: jfrparser.ProcessSymbols,
	})

	// Try to extract metadata from JFR events (using jfr CLI tool if available)
	// This provides the most accurate service name and version
	var jfrMeta *JFRMetadata
	var metaServiceName, metaVersion string
	jfrMeta, err = extractJFRMetadata(jfrPath, p.opts.JFRCommand, p.logger)
	if err != nil {
		p.logger.Debug("Could not extract JFR metadata (jfr CLI not available)", zap.Error(err))
	} else {
		metaServiceName = parseServiceNameFromMetadata(jfrMeta)
		metaVersion = parseVersionFromMetadata(jfrMeta)
		p.logger.Debug("Extracted JFR metadata",
			zap.String("sunJavaCommand", jfrMeta.SunJavaCommand),
			zap.String("javaArguments", jfrMeta.JavaArguments),
			zap.String("applicationName", jfrMeta.ApplicationName),
			zap.String("parsedServiceName", metaServiceName),
			zap.String("parsedVersion", metaVersion),
		)
	}

	// Fallback: infer service name and version from file path
	inferredServiceName := inferServiceNameFromPath(jfrPath)
	inferredVersion := inferVersionFromPath(jfrPath)

	// Parse all events
	events := make([]*ProfileEvent, 0)
	functionCounts := make(map[string]int64)
	var totalSamples int64
	var mainClassName string // Will be detected from stack traces

	for {
		typeID, err := parser.ParseEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Log warning but continue parsing
			p.logger.Debug("Error parsing event", zap.Error(err))
			continue
		}

		// Convert based on event type
		var evt *ProfileEvent
		switch typeID {
		case parser.TypeMap.T_EXECUTION_SAMPLE:
			evt = p.convertExecutionSample(parser)
			// Try to detect main class from the bottom of the stack trace
			if mainClassName == "" && evt.StackPath != "" {
				mainClassName = extractMainClassFromStack(evt.StackPath)
			}
		case parser.TypeMap.T_WALL_CLOCK_SAMPLE:
			evt = p.convertWallClockSample(parser)
		case parser.TypeMap.T_ALLOC_IN_NEW_TLAB:
			evt = p.convertAllocInNewTLAB(parser)
		case parser.TypeMap.T_ALLOC_OUTSIDE_TLAB:
			evt = p.convertAllocOutsideTLAB(parser)
		case parser.TypeMap.T_MONITOR_ENTER:
			evt = p.convertMonitorEnter(parser)
		case parser.TypeMap.T_THREAD_PARK:
			evt = p.convertThreadPark(parser)
		}

		if evt != nil {
			events = append(events, evt)
			if evt.TopFunction != "" {
				functionCounts[evt.TopFunction]++
				totalSamples++
			}
		}
	}

	// Determine final service name with priority:
	// 1. Configured service name (if not default "telegen")
	// 2. Service name from JFR metadata (jdk.InitialSystemProperty: sun.java.command, app.name, etc.)
	// 3. Main class detected from stack traces
	// 4. Inferred from file path
	// 5. Fall back to configured service name
	serviceName := p.opts.ServiceName
	if serviceName == "" || serviceName == "telegen" {
		if metaServiceName != "" {
			serviceName = metaServiceName
		} else if mainClassName != "" {
			serviceName = mainClassName
		} else if inferredServiceName != "" {
			serviceName = inferredServiceName
		}
	}

	// Determine service version with priority:
	// 1. Version from JFR metadata (extracted from jar name in sun.java.command)
	// 2. Version inferred from file path
	serviceVersion := metaVersion
	if serviceVersion == "" {
		serviceVersion = inferredVersion
	}

	// Update all events with the determined service name, version, and calculate percentages
	for _, evt := range events {
		evt.ServiceName = serviceName
		evt.ServiceVersion = serviceVersion
		if evt.TopFunction != "" && totalSamples > 0 {
			count := functionCounts[evt.TopFunction]
			evt.SelfTimePercent = float64(count) / float64(totalSamples) * 100
			evt.SelfTimeMs = count * int64(p.opts.SampleIntervalMs)
			evt.TotalSamples = totalSamples
		}
	}

	p.logger.Info("Parsed JFR file natively",
		zap.String("path", jfrPath),
		zap.String("serviceName", serviceName),
		zap.String("serviceVersion", serviceVersion),
		zap.String("metaServiceName", metaServiceName),
		zap.String("metaVersion", metaVersion),
		zap.String("inferredFromPath", inferredServiceName),
		zap.String("mainClass", mainClassName),
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

// extractMainClassFromStack tries to extract the main class name from the bottom of a stack trace.
// Stack traces typically have the entry point (main class) at the bottom.
// Format: "com/example/MyApp.main;java/lang/Thread.run;..."
func extractMainClassFromStack(stackPath string) string {
	if stackPath == "" {
		return ""
	}

	parts := strings.Split(stackPath, ";")
	if len(parts) == 0 {
		return ""
	}

	// Look for main method or common entry points at the bottom of the stack
	for i := len(parts) - 1; i >= 0 && i >= len(parts)-5; i-- {
		frame := parts[i]
		// Skip JDK/framework internal classes
		if strings.HasPrefix(frame, "java/") ||
			strings.HasPrefix(frame, "jdk/") ||
			strings.HasPrefix(frame, "sun/") ||
			strings.HasPrefix(frame, "javax/") {
			continue
		}

		// Look for .main, .run, or other entry points
		if strings.Contains(frame, ".main") ||
			strings.Contains(frame, ".run") ||
			strings.Contains(frame, "Application.") {
			// Extract class name from "com/example/MyApp.main"
			dotIdx := strings.LastIndex(frame, ".")
			if dotIdx > 0 {
				className := frame[:dotIdx]
				// Get just the simple class name (last part after /)
				slashIdx := strings.LastIndex(className, "/")
				if slashIdx >= 0 {
					return className[slashIdx+1:]
				}
				return className
			}
		}
	}

	return ""
}

// ticksToTimestamp converts JFR event ticks to an absolute timestamp using the chunk header.
// JFR events store StartTime as ticks relative to the chunk's internal clock, not absolute nanoseconds.
// The formula is: absoluteNanos = chunkStartNanos + ((eventTicks - chunkStartTicks) * 1e9 / ticksPerSecond)
func (p *NativeParser) ticksToTimestamp(parser *jfrparser.Parser, eventTicks uint64) string {
	header := parser.ChunkHeader()
	if header.TicksPerSecond == 0 {
		// Fallback: if no tick info, use current time (shouldn't happen with valid JFR)
		return time.Now().Format(time.RFC3339Nano)
	}

	// Calculate delta in ticks from chunk start
	var ticksDelta int64
	if eventTicks >= header.StartTicks {
		ticksDelta = int64(eventTicks - header.StartTicks)
	} else {
		// Handle wrap-around (unlikely but safe)
		ticksDelta = -int64(header.StartTicks - eventTicks)
	}

	// Convert ticks delta to nanoseconds
	nanosDelta := ticksDelta * int64(time.Second) / int64(header.TicksPerSecond)

	// Add to chunk start time (which is already in nanoseconds since epoch)
	absoluteNanos := int64(header.StartNanos) + nanosDelta

	return time.Unix(0, absoluteNanos).Format(time.RFC3339Nano)
}

func (p *NativeParser) convertExecutionSample(parser *jfrparser.Parser) *ProfileEvent {
	sample := &parser.ExecutionSample
	evt := p.baseEvent("jdk.ExecutionSample", "cpu")

	// Get thread state
	ts := parser.GetThreadState(sample.State)
	if ts != nil {
		evt.State = ts.Name
	}

	// Get stack trace
	p.resolveStackTrace(parser, sample.StackTrace, evt)

	evt.Timestamp = p.ticksToTimestamp(parser, sample.StartTime)
	evt.SampleWeight = 1

	return evt
}

func (p *NativeParser) convertWallClockSample(parser *jfrparser.Parser) *ProfileEvent {
	sample := &parser.WallClockSample
	evt := p.baseEvent("jdk.WallClockSample", "wall")

	// Get stack trace
	p.resolveStackTrace(parser, sample.StackTrace, evt)

	evt.Timestamp = p.ticksToTimestamp(parser, sample.StartTime)
	evt.SampleWeight = int64(sample.Samples)

	return evt
}

func (p *NativeParser) convertAllocInNewTLAB(parser *jfrparser.Parser) *ProfileEvent {
	sample := &parser.ObjectAllocationInNewTLAB
	evt := p.baseEvent("jdk.ObjectAllocationInNewTLAB", "alloc")

	// Get stack trace
	p.resolveStackTrace(parser, sample.StackTrace, evt)

	// Allocation info (cast from uint64 to int64)
	evt.TLABSize = int64(sample.TlabSize)
	evt.AllocationSize = int64(sample.AllocationSize)

	// Object class
	class := parser.GetClass(sample.ObjectClass)
	if class != nil {
		evt.ObjectClass = parser.GetSymbolString(class.Name)
	}

	evt.Timestamp = p.ticksToTimestamp(parser, sample.StartTime)
	evt.SampleWeight = int64(sample.AllocationSize)

	return evt
}

func (p *NativeParser) convertAllocOutsideTLAB(parser *jfrparser.Parser) *ProfileEvent {
	sample := &parser.ObjectAllocationOutsideTLAB
	evt := p.baseEvent("jdk.ObjectAllocationOutsideTLAB", "alloc")

	// Get stack trace
	p.resolveStackTrace(parser, sample.StackTrace, evt)

	// Allocation info
	evt.AllocationSize = int64(sample.AllocationSize)

	// Object class
	class := parser.GetClass(sample.ObjectClass)
	if class != nil {
		evt.ObjectClass = parser.GetSymbolString(class.Name)
	}

	evt.Timestamp = p.ticksToTimestamp(parser, sample.StartTime)
	evt.SampleWeight = int64(sample.AllocationSize)

	return evt
}

func (p *NativeParser) convertMonitorEnter(parser *jfrparser.Parser) *ProfileEvent {
	sample := &parser.JavaMonitorEnter
	evt := p.baseEvent("jdk.JavaMonitorEnter", "lock")

	// Get stack trace
	p.resolveStackTrace(parser, sample.StackTrace, evt)

	// Monitor class
	class := parser.GetClass(sample.MonitorClass)
	if class != nil {
		evt.MonitorClass = parser.GetSymbolString(class.Name)
	}

	evt.Timestamp = p.ticksToTimestamp(parser, sample.StartTime)
	evt.DurationNs = int64(sample.Duration)
	evt.SampleWeight = int64(sample.Duration)

	return evt
}

func (p *NativeParser) convertThreadPark(parser *jfrparser.Parser) *ProfileEvent {
	sample := &parser.ThreadPark
	evt := p.baseEvent("jdk.ThreadPark", "lock")

	// Get stack trace
	p.resolveStackTrace(parser, sample.StackTrace, evt)

	// Park class
	class := parser.GetClass(sample.ParkedClass)
	if class != nil {
		evt.MonitorClass = parser.GetSymbolString(class.Name)
	}

	evt.Timestamp = p.ticksToTimestamp(parser, sample.StartTime)
	evt.DurationNs = int64(sample.Duration)
	evt.SampleWeight = int64(sample.Duration)

	return evt
}

func (p *NativeParser) baseEvent(eventType, profileType string) *ProfileEvent {
	return &ProfileEvent{
		EventType:        eventType,
		ProfileType:      profileType,
		ServiceName:      p.opts.ServiceName,
		K8sPodName:       p.opts.PodName,
		K8sNamespace:     p.opts.Namespace,
		K8sContainerName: p.opts.ContainerName,
		K8sNodeName:      p.opts.NodeName,
	}
}

func (p *NativeParser) resolveStackTrace(parser *jfrparser.Parser, stackTraceRef types.StackTraceRef, evt *ProfileEvent) {
	stackTrace := parser.GetStacktrace(stackTraceRef)
	if stackTrace == nil || len(stackTrace.Frames) == 0 {
		return
	}

	evt.StackDepth = len(stackTrace.Frames)

	// Build stack frames
	frames := make([]StackFrame, 0, len(stackTrace.Frames))
	var stackPath []string

	for i, frameRef := range stackTrace.Frames {
		method := parser.GetMethod(frameRef.Method)
		if method == nil {
			continue
		}

		methodName := parser.GetSymbolString(method.Name)
		className := ""

		class := parser.GetClass(method.Type)
		if class != nil {
			className = parser.GetSymbolString(class.Name)
		}

		fullName := className + "." + methodName

		// First frame is the top
		if i == 0 {
			evt.TopFunction = fullName
			evt.TopClass = className
			evt.TopMethod = methodName
		}

		stackPath = append(stackPath, fullName)

		frames = append(frames, StackFrame{
			Class:  className,
			Method: methodName,
			Line:   int(frameRef.LineNumber),
			BCI:    0, // Not available in jfr-parser
			Depth:  i,
		})
	}

	evt.StackPath = strings.Join(stackPath, ";")

	// Encode stack trace as semicolon-separated format for efficiency
	if len(frames) > 0 {
		var sb strings.Builder
		for i, f := range frames {
			if i > 0 {
				sb.WriteString(";")
			}
			sb.WriteString(fmt.Sprintf("%s.%s:%d", f.Class, f.Method, f.Line))
		}
		evt.StackTrace = sb.String()
	}
}
