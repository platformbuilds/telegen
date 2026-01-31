// Package converter provides JFR to JSON conversion functionality.
// native_parser.go implements a pure Go JFR parser using github.com/grafana/jfr-parser
// This eliminates the need for the external jfr command from JDK.
package converter

import (
	"fmt"
	"io"
	"os"
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

	// Parse all events
	events := make([]*ProfileEvent, 0)
	functionCounts := make(map[string]int64)
	var totalSamples int64

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

	// Calculate self-time percentages
	for _, evt := range events {
		if evt.TopFunction != "" && totalSamples > 0 {
			count := functionCounts[evt.TopFunction]
			evt.SelfTimePercent = float64(count) / float64(totalSamples) * 100
			evt.SelfTimeMs = count * int64(p.opts.SampleIntervalMs)
			evt.TotalSamples = totalSamples
		}
	}

	p.logger.Info("Parsed JFR file natively",
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

	evt.Timestamp = time.Unix(0, int64(sample.StartTime)).Format(time.RFC3339Nano)
	evt.SampleWeight = 1

	return evt
}

func (p *NativeParser) convertWallClockSample(parser *jfrparser.Parser) *ProfileEvent {
	sample := &parser.WallClockSample
	evt := p.baseEvent("jdk.WallClockSample", "wall")

	// Get stack trace
	p.resolveStackTrace(parser, sample.StackTrace, evt)

	evt.Timestamp = time.Unix(0, int64(sample.StartTime)).Format(time.RFC3339Nano)
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

	evt.Timestamp = time.Unix(0, int64(sample.StartTime)).Format(time.RFC3339Nano)
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

	evt.Timestamp = time.Unix(0, int64(sample.StartTime)).Format(time.RFC3339Nano)
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

	evt.Timestamp = time.Unix(0, int64(sample.StartTime)).Format(time.RFC3339Nano)
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

	evt.Timestamp = time.Unix(0, int64(sample.StartTime)).Format(time.RFC3339Nano)
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
