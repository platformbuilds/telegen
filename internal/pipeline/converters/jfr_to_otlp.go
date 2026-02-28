package converters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// JFRConverter converts Java Flight Recorder events to OTLP format.
type JFRConverter struct {
	// IncludeStackTraces includes stack traces in log body.
	IncludeStackTraces bool
	// EmitMetrics enables emitting JFR events as metrics where applicable.
	EmitMetrics bool
}

// JFREvent represents a parsed JFR event.
type JFREvent struct {
	Type      string                 `json:"type"`
	StartTime time.Time              `json:"startTime"`
	EndTime   time.Time              `json:"endTime,omitempty"`
	Duration  time.Duration          `json:"duration,omitempty"`
	Thread    *JFRThread             `json:"thread,omitempty"`
	StackTrace *JFRStackTrace        `json:"stackTrace,omitempty"`
	Fields    map[string]interface{} `json:"fields"`
}

// JFRThread represents thread information.
type JFRThread struct {
	Name   string `json:"name"`
	ID     int64  `json:"id"`
	Group  string `json:"group,omitempty"`
	Daemon bool   `json:"daemon"`
}

// JFRStackTrace represents a stack trace.
type JFRStackTrace struct {
	Frames    []JFRFrame `json:"frames"`
	Truncated bool       `json:"truncated"`
}

// JFRFrame represents a single stack frame.
type JFRFrame struct {
	Method    string `json:"method"`
	Class     string `json:"class"`
	LineNumber int   `json:"lineNumber"`
	BytecodeIndex int `json:"bytecodeIndex,omitempty"`
	Type      string `json:"type"` // Interpreted, JIT compiled, Inlined
}

// JFRRecording represents a collection of JFR events.
type JFRRecording struct {
	Events    []JFREvent        `json:"events"`
	Metadata  *JFRMetadata      `json:"metadata,omitempty"`
}

// JFRMetadata contains recording metadata.
type JFRMetadata struct {
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime"`
	Duration  time.Duration `json:"duration"`
	JVMName   string    `json:"jvmName"`
	JVMVersion string   `json:"jvmVersion"`
	PID       int       `json:"pid"`
}

// NewJFRConverter creates a new JFRConverter with default settings.
func NewJFRConverter() *JFRConverter {
	return &JFRConverter{
		IncludeStackTraces: true,
		EmitMetrics:        true,
	}
}

// Name returns the converter name.
func (c *JFRConverter) Name() string {
	return "jfr_to_otlp"
}

// ConvertLogs converts JFR events to OTLP logs.
func (c *JFRConverter) ConvertLogs(ctx context.Context, source interface{}) (plog.Logs, error) {
	recording, ok := source.(*JFRRecording)
	if !ok {
		return plog.Logs{}, fmt.Errorf("expected *JFRRecording, got %T", source)
	}

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()

	// Set resource attributes from metadata.
	if recording.Metadata != nil {
		res := rl.Resource()
		res.Attributes().PutStr("service.name", "java-application")
		res.Attributes().PutStr("process.runtime.name", recording.Metadata.JVMName)
		res.Attributes().PutStr("process.runtime.version", recording.Metadata.JVMVersion)
		res.Attributes().PutInt("process.pid", int64(recording.Metadata.PID))
	}

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("telegen.converter.jfr")
	sl.Scope().SetVersion("1.0.0")

	for _, event := range recording.Events {
		lr := sl.LogRecords().AppendEmpty()
		c.convertEvent(&event, lr)
	}

	return logs, nil
}

// convertEvent converts a single JFR event to a log record.
func (c *JFRConverter) convertEvent(event *JFREvent, lr plog.LogRecord) {
	lr.SetTimestamp(pcommon.NewTimestampFromTime(event.StartTime))
	lr.SetObservedTimestamp(Now())
	
	// Set severity based on event type.
	severity := c.eventSeverity(event.Type)
	lr.SetSeverityNumber(severity)
	lr.SetSeverityText(severity.String())

	// Set event type as the body.
	lr.Body().SetStr(event.Type)

	// Set attributes.
	attrs := lr.Attributes()
	attrs.PutStr("jfr.event.type", event.Type)
	
	if event.Duration > 0 {
		attrs.PutInt("jfr.event.duration_ns", int64(event.Duration))
	}

	// Thread info.
	if event.Thread != nil {
		attrs.PutStr("thread.name", event.Thread.Name)
		attrs.PutInt("thread.id", event.Thread.ID)
		if event.Thread.Group != "" {
			attrs.PutStr("thread.group", event.Thread.Group)
		}
		attrs.PutBool("thread.daemon", event.Thread.Daemon)
	}

	// Event-specific fields.
	for k, v := range event.Fields {
		c.setAttributeValue(attrs, "jfr."+k, v)
	}

	// Stack trace.
	if c.IncludeStackTraces && event.StackTrace != nil && len(event.StackTrace.Frames) > 0 {
		stackJSON, err := json.Marshal(event.StackTrace)
		if err == nil {
			attrs.PutStr("jfr.stack_trace", string(stackJSON))
		}
	}
}

// eventSeverity returns the appropriate severity for a JFR event type.
func (c *JFRConverter) eventSeverity(eventType string) plog.SeverityNumber {
	// Map JFR event types to severity levels.
	switch eventType {
	case "jdk.JavaMonitorWait", "jdk.JavaMonitorEnter":
		return plog.SeverityNumberDebug
	case "jdk.ThreadStart", "jdk.ThreadEnd", "jdk.ThreadPark":
		return plog.SeverityNumberInfo
	case "jdk.GCPhasePause", "jdk.GarbageCollection":
		return plog.SeverityNumberInfo
	case "jdk.Compilation", "jdk.CompilerPhase":
		return plog.SeverityNumberDebug
	case "jdk.ObjectAllocationInNewTLAB", "jdk.ObjectAllocationOutsideTLAB":
		return plog.SeverityNumberDebug
	case "jdk.CPULoad", "jdk.ThreadCPULoad":
		return plog.SeverityNumberInfo
	case "jdk.JavaErrorThrow", "jdk.JavaExceptionThrow":
		return plog.SeverityNumberError
	case "jdk.ExecutionSample", "jdk.NativeMethodSample":
		return plog.SeverityNumberDebug
	default:
		return plog.SeverityNumberInfo
	}
}

// setAttributeValue sets an attribute value with proper type handling.
func (c *JFRConverter) setAttributeValue(attrs pcommon.Map, key string, value interface{}) {
	switch v := value.(type) {
	case string:
		attrs.PutStr(key, v)
	case int:
		attrs.PutInt(key, int64(v))
	case int64:
		attrs.PutInt(key, v)
	case float64:
		attrs.PutDouble(key, v)
	case bool:
		attrs.PutBool(key, v)
	case map[string]interface{}:
		// Nested object - serialize to JSON.
		jsonBytes, err := json.Marshal(v)
		if err == nil {
			attrs.PutStr(key, string(jsonBytes))
		}
	default:
		// Try string conversion.
		attrs.PutStr(key, fmt.Sprintf("%v", v))
	}
}

// ConvertMetrics converts JFR events to OTLP metrics where applicable.
func (c *JFRConverter) ConvertMetrics(ctx context.Context, source interface{}) (pmetric.Metrics, error) {
	recording, ok := source.(*JFRRecording)
	if !ok {
		return pmetric.Metrics{}, fmt.Errorf("expected *JFRRecording, got %T", source)
	}

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	
	if recording.Metadata != nil {
		res := rm.Resource()
		res.Attributes().PutStr("service.name", "java-application")
		res.Attributes().PutStr("process.runtime.name", recording.Metadata.JVMName)
	}

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen.converter.jfr")
	sm.Scope().SetVersion("1.0.0")

	// Aggregate events into metrics.
	c.aggregateGCMetrics(recording.Events, sm)
	c.aggregateCPUMetrics(recording.Events, sm)
	c.aggregateAllocationMetrics(recording.Events, sm)

	return metrics, nil
}

// aggregateGCMetrics aggregates GC-related events into metrics.
func (c *JFRConverter) aggregateGCMetrics(events []JFREvent, sm pmetric.ScopeMetrics) {
	var gcCount int64
	var gcDurationTotal int64

	for _, event := range events {
		if event.Type == "jdk.GarbageCollection" || event.Type == "jdk.GCPhasePause" {
			gcCount++
			gcDurationTotal += int64(event.Duration)
		}
	}

	if gcCount > 0 {
		// GC count metric.
		m := sm.Metrics().AppendEmpty()
		m.SetName("jvm.gc.collections")
		m.SetDescription("Number of garbage collections")
		sum := m.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(gcCount)
		dp.SetTimestamp(Now())

		// GC duration metric.
		m2 := sm.Metrics().AppendEmpty()
		m2.SetName("jvm.gc.duration")
		m2.SetDescription("Total time spent in garbage collection")
		m2.SetUnit("ns")
		sum2 := m2.SetEmptySum()
		sum2.SetIsMonotonic(true)
		sum2.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		dp2 := sum2.DataPoints().AppendEmpty()
		dp2.SetIntValue(gcDurationTotal)
		dp2.SetTimestamp(Now())
	}
}

// aggregateCPUMetrics aggregates CPU-related events into metrics.
func (c *JFRConverter) aggregateCPUMetrics(events []JFREvent, sm pmetric.ScopeMetrics) {
	var lastCPUEvent *JFREvent
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == "jdk.CPULoad" {
			lastCPUEvent = &events[i]
			break
		}
	}

	if lastCPUEvent != nil {
		if jvmUser, ok := lastCPUEvent.Fields["jvmUser"].(float64); ok {
			m := sm.Metrics().AppendEmpty()
			m.SetName("jvm.cpu.user")
			m.SetDescription("JVM user CPU usage")
			m.SetUnit("1")
			gauge := m.SetEmptyGauge()
			dp := gauge.DataPoints().AppendEmpty()
			dp.SetDoubleValue(jvmUser)
			dp.SetTimestamp(Now())
		}

		if jvmSystem, ok := lastCPUEvent.Fields["jvmSystem"].(float64); ok {
			m := sm.Metrics().AppendEmpty()
			m.SetName("jvm.cpu.system")
			m.SetDescription("JVM system CPU usage")
			m.SetUnit("1")
			gauge := m.SetEmptyGauge()
			dp := gauge.DataPoints().AppendEmpty()
			dp.SetDoubleValue(jvmSystem)
			dp.SetTimestamp(Now())
		}
	}
}

// aggregateAllocationMetrics aggregates allocation-related events.
func (c *JFRConverter) aggregateAllocationMetrics(events []JFREvent, sm pmetric.ScopeMetrics) {
	var tlabAllocations int64
	var tlabSize int64
	var outsideTlabAllocations int64
	var outsideTlabSize int64

	for _, event := range events {
		switch event.Type {
		case "jdk.ObjectAllocationInNewTLAB":
			tlabAllocations++
			if size, ok := event.Fields["tlabSize"].(float64); ok {
				tlabSize += int64(size)
			}
		case "jdk.ObjectAllocationOutsideTLAB":
			outsideTlabAllocations++
			if size, ok := event.Fields["allocationSize"].(float64); ok {
				outsideTlabSize += int64(size)
			}
		}
	}

	if tlabAllocations > 0 || outsideTlabAllocations > 0 {
		m := sm.Metrics().AppendEmpty()
		m.SetName("jvm.memory.allocated")
		m.SetDescription("Total bytes allocated")
		m.SetUnit("By")
		sum := m.SetEmptySum()
		sum.SetIsMonotonic(true)
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(tlabSize + outsideTlabSize)
		dp.SetTimestamp(Now())
	}
}
