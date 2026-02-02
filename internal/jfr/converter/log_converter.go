// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package converter provides JFR to JSON and OTLP conversion functionality.
package converter

import (
	"encoding/json"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/platformbuilds/telegen/internal/sigdef"
)

// LogExportConfig holds configuration for log export
type LogExportConfig struct {
	ServiceName   string
	Namespace     string
	PodName       string
	ContainerName string
	NodeName      string
	ClusterName   string
}

// LogConverter converts JFR profile events to OTLP Logs
type LogConverter struct {
	config LogExportConfig
}

// NewLogConverter creates a new LogConverter
func NewLogConverter(cfg LogExportConfig) *LogConverter {
	return &LogConverter{config: cfg}
}

// ProfileLogRecord represents a JFR profile event in JSON format for OTLP Logs
// This structure follows OpenTelemetry semantic conventions
type ProfileLogRecord struct {
	// Timestamp in RFC3339 format
	Timestamp string `json:"timestamp"`

	// Profile type (cpu, allocation, lock, gc)
	ProfileType string `json:"profile.type"`

	// Event type from JFR
	EventType string `json:"event.type"`

	// Thread information
	Thread ThreadInfo `json:"thread,omitempty"`

	// Stack trace information
	StackTrace StackTraceInfo `json:"stack_trace,omitempty"`

	// Sample metrics
	Sample SampleInfo `json:"sample"`

	// Resource attributes
	Resource ResourceInfo `json:"resource"`

	// Event-specific data
	EventData map[string]interface{} `json:"event_data,omitempty"`
}

// ThreadInfo contains thread metadata
type ThreadInfo struct {
	Name string `json:"name,omitempty"`
	ID   int64  `json:"id,omitempty"`
}

// StackTraceInfo contains stack trace data
type StackTraceInfo struct {
	Frames    []StackFrameInfo `json:"frames,omitempty"`
	Depth     int              `json:"depth"`
	TopClass  string           `json:"top_class,omitempty"`
	TopMethod string           `json:"top_method,omitempty"`
	Path      string           `json:"path,omitempty"`
}

// StackFrameInfo contains individual stack frame data
type StackFrameInfo struct {
	Class      string `json:"class"`
	Method     string `json:"method"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	BCI        int    `json:"bytecode_index,omitempty"`
	ModuleName string `json:"module,omitempty"`
}

// SampleInfo contains sample metrics
type SampleInfo struct {
	Weight          int64   `json:"weight"`
	DurationNs      int64   `json:"duration_ns,omitempty"`
	SelfTimeMs      int64   `json:"self_time_ms,omitempty"`
	SelfTimePercent float64 `json:"self_time_percent,omitempty"`
	TotalSamples    int64   `json:"total_samples,omitempty"`
}

// ResourceInfo contains resource attributes following OTel semantic conventions
type ResourceInfo struct {
	ServiceName      string `json:"service.name,omitempty"`
	ServiceVersion   string `json:"service.version,omitempty"`
	ServiceNamespace string `json:"service.namespace,omitempty"`
	K8sPodName       string `json:"k8s.pod.name,omitempty"`
	K8sNamespaceName string `json:"k8s.namespace.name,omitempty"`
	K8sContainerName string `json:"k8s.container.name,omitempty"`
	K8sNodeName      string `json:"k8s.node.name,omitempty"`
	K8sClusterName   string `json:"k8s.cluster.name,omitempty"`
}

// ConvertToLogs converts profile events to OTLP Logs
func (c *LogConverter) ConvertToLogs(events []*ProfileEvent) plog.Logs {
	logs := plog.NewLogs()
	if len(events) == 0 {
		return logs
	}

	rl := logs.ResourceLogs().AppendEmpty()

	// Use service name/version from events if available (inferred from JFR file)
	serviceName := c.config.ServiceName
	serviceVersion := ""
	if len(events) > 0 && events[0].ServiceName != "" {
		serviceName = events[0].ServiceName
	}
	if len(events) > 0 && events[0].ServiceVersion != "" {
		serviceVersion = events[0].ServiceVersion
	}
	c.setResourceAttributesWithVersion(rl.Resource(), serviceName, serviceVersion)

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("telegen.jfr")
	sl.Scope().SetVersion("1.0.0")

	for _, event := range events {
		lr := sl.LogRecords().AppendEmpty()
		c.profileEventToLogRecord(event, lr)
	}

	return logs
}

// ConvertToJSON converts profile events to JSON log records
func (c *LogConverter) ConvertToJSON(events []*ProfileEvent) ([][]byte, error) {
	records := make([][]byte, 0, len(events))

	for _, event := range events {
		record := c.profileEventToJSONRecord(event)
		data, err := json.Marshal(record)
		if err != nil {
			continue
		}
		records = append(records, data)
	}

	return records, nil
}

// ConvertToJSONString converts profile events to newline-delimited JSON string
func (c *LogConverter) ConvertToJSONString(events []*ProfileEvent) (string, error) {
	var result string
	for _, event := range events {
		record := c.profileEventToJSONRecord(event)
		data, err := json.Marshal(record)
		if err != nil {
			continue
		}
		result += string(data) + "\n"
	}
	return result, nil
}

//nolint:unused // reserved for resource attribute injection
func (c *LogConverter) setResourceAttributes(resource pcommon.Resource) {
	attrs := resource.Attributes()

	if c.config.ServiceName != "" {
		attrs.PutStr("service.name", c.config.ServiceName)
	}
	if c.config.Namespace != "" {
		attrs.PutStr("service.namespace", c.config.Namespace)
	}
	if c.config.PodName != "" {
		attrs.PutStr("k8s.pod.name", c.config.PodName)
	}
	if c.config.ContainerName != "" {
		attrs.PutStr("k8s.container.name", c.config.ContainerName)
	}
	if c.config.NodeName != "" {
		attrs.PutStr("k8s.node.name", c.config.NodeName)
	}
	if c.config.ClusterName != "" {
		attrs.PutStr("k8s.cluster.name", c.config.ClusterName)
	}

	// Set telemetry SDK attributes
	attrs.PutStr("telemetry.sdk.name", "telegen")
	attrs.PutStr("telemetry.sdk.language", "java")
	attrs.PutStr("telemetry.sdk.version", "1.0.0")
}

func (c *LogConverter) setResourceAttributesWithVersion(resource pcommon.Resource, serviceName, serviceVersion string) {
	attrs := resource.Attributes()

	if serviceName != "" {
		attrs.PutStr("service.name", serviceName)
	}
	if serviceVersion != "" {
		attrs.PutStr("service.version", serviceVersion)
	}
	if c.config.Namespace != "" {
		attrs.PutStr("service.namespace", c.config.Namespace)
	}
	if c.config.PodName != "" {
		attrs.PutStr("k8s.pod.name", c.config.PodName)
	}
	if c.config.ContainerName != "" {
		attrs.PutStr("k8s.container.name", c.config.ContainerName)
	}
	if c.config.NodeName != "" {
		attrs.PutStr("k8s.node.name", c.config.NodeName)
	}
	if c.config.ClusterName != "" {
		attrs.PutStr("k8s.cluster.name", c.config.ClusterName)
	}

	// Set telemetry SDK attributes
	attrs.PutStr("telemetry.sdk.name", "telegen")
	attrs.PutStr("telemetry.sdk.language", "java")
	attrs.PutStr("telemetry.sdk.version", "1.0.0")
}

func (c *LogConverter) profileEventToLogRecord(event *ProfileEvent, lr plog.LogRecord) {
	// Parse timestamp
	ts, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		ts = time.Now()
	}
	lr.SetTimestamp(pcommon.NewTimestampFromTime(ts))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	// Set severity based on profile type
	lr.SetSeverityText("INFO")
	lr.SetSeverityNumber(plog.SeverityNumberInfo)

	// Set body as JSON
	jsonRecord := c.profileEventToJSONRecord(event)
	if jsonData, err := json.Marshal(jsonRecord); err == nil {
		lr.Body().SetStr(string(jsonData))
	}

	// Set attributes following OTel semantic conventions
	attrs := lr.Attributes()

	// Profile-specific attributes
	attrs.PutStr("profile.type", event.ProfileType)
	attrs.PutStr("event.name", event.EventType)
	attrs.PutStr("event.domain", "jfr")
	attrs.PutStr("event.category", "profiling")

	// Thread attributes (OTel semantic conventions)
	if event.ThreadName != "" {
		attrs.PutStr("thread.name", event.ThreadName)
	}
	if event.ThreadID != 0 {
		attrs.PutInt("thread.id", event.ThreadID)
	}

	// Code attributes (OTel semantic conventions)
	if event.TopFunction != "" {
		attrs.PutStr("code.function", event.TopFunction)
	}
	if event.TopClass != "" {
		attrs.PutStr("code.namespace", event.TopClass)
	}
	if event.StackDepth > 0 {
		attrs.PutInt("code.stacktrace.depth", int64(event.StackDepth))
	}

	// Sample metrics
	attrs.PutInt("profile.sample.weight", event.SampleWeight)
	if event.DurationNs > 0 {
		attrs.PutInt("profile.duration_ns", event.DurationNs)
	}
	if event.SelfTimeMs > 0 {
		attrs.PutInt("profile.self_time_ms", event.SelfTimeMs)
	}
	if event.SelfTimePercent > 0 {
		attrs.PutDouble("profile.self_time_percent", event.SelfTimePercent)
	}
	if event.TotalSamples > 0 {
		attrs.PutInt("profile.total_samples", event.TotalSamples)
	}

	// Event-specific attributes
	if event.State != "" {
		attrs.PutStr("profile.state", event.State)
	}
	if event.AllocationSize > 0 {
		attrs.PutInt("profile.allocation.size", event.AllocationSize)
	}
	if event.TLABSize > 0 {
		attrs.PutInt("profile.tlab.size", event.TLABSize)
	}
	if event.ObjectClass != "" {
		attrs.PutStr("profile.object.class", event.ObjectClass)
	}
	if event.MonitorClass != "" {
		attrs.PutStr("profile.monitor.class", event.MonitorClass)
	}
	if event.GCName != "" {
		attrs.PutStr("profile.gc.name", event.GCName)
	}
	if event.GCCause != "" {
		attrs.PutStr("profile.gc.cause", event.GCCause)
	}

	// K8s attributes
	if event.K8sPodName != "" {
		attrs.PutStr("k8s.pod.name", event.K8sPodName)
	}
	if event.K8sNamespace != "" {
		attrs.PutStr("k8s.namespace.name", event.K8sNamespace)
	}
	if event.K8sContainerName != "" {
		attrs.PutStr("k8s.container.name", event.K8sContainerName)
	}
	if event.K8sNodeName != "" {
		attrs.PutStr("k8s.node.name", event.K8sNodeName)
	}

	// Add telegen signal metadata
	addSignalMetadataToLogRecord(sigdef.JFREventLogs, attrs)
}

// addSignalMetadataToLogRecord adds telegen signal metadata to log record attributes
func addSignalMetadataToLogRecord(metadata *sigdef.SignalMetadata, attrs pcommon.Map) {
	if metadata == nil {
		return
	}
	metadataAttrs := metadata.ToAttributes()
	for _, attr := range metadataAttrs {
		attrs.PutStr(string(attr.Key), attr.Value.AsString())
	}
}

func (c *LogConverter) profileEventToJSONRecord(event *ProfileEvent) *ProfileLogRecord {
	record := &ProfileLogRecord{
		Timestamp:   event.Timestamp,
		ProfileType: event.ProfileType,
		EventType:   event.EventType,
		Thread: ThreadInfo{
			Name: event.ThreadName,
			ID:   event.ThreadID,
		},
		StackTrace: StackTraceInfo{
			Depth:     event.StackDepth,
			TopClass:  event.TopClass,
			TopMethod: event.TopMethod,
			Path:      event.StackPath,
		},
		Sample: SampleInfo{
			Weight:          event.SampleWeight,
			DurationNs:      event.DurationNs,
			SelfTimeMs:      event.SelfTimeMs,
			SelfTimePercent: event.SelfTimePercent,
			TotalSamples:    event.TotalSamples,
		},
		Resource: ResourceInfo{
			ServiceName:      event.ServiceName,
			K8sPodName:       event.K8sPodName,
			K8sNamespaceName: event.K8sNamespace,
			K8sContainerName: event.K8sContainerName,
			K8sNodeName:      event.K8sNodeName,
		},
	}

	// Parse stack frames from JSON
	if event.StackTrace != "" {
		var frames []StackFrame
		if err := json.Unmarshal([]byte(event.StackTrace), &frames); err == nil {
			record.StackTrace.Frames = make([]StackFrameInfo, 0, len(frames))
			for _, f := range frames {
				record.StackTrace.Frames = append(record.StackTrace.Frames, StackFrameInfo{
					Class:  f.Class,
					Method: f.Method,
					File:   f.File,
					Line:   f.Line,
					BCI:    f.BCI,
				})
			}
		}
	}

	// Add event-specific data
	record.EventData = make(map[string]interface{})
	if event.State != "" {
		record.EventData["state"] = event.State
	}
	if event.AllocationSize > 0 {
		record.EventData["allocation_size"] = event.AllocationSize
	}
	if event.TLABSize > 0 {
		record.EventData["tlab_size"] = event.TLABSize
	}
	if event.ObjectClass != "" {
		record.EventData["object_class"] = event.ObjectClass
	}
	if event.MonitorClass != "" {
		record.EventData["monitor_class"] = event.MonitorClass
	}
	if event.GCName != "" {
		record.EventData["gc_name"] = event.GCName
	}
	if event.GCCause != "" {
		record.EventData["gc_cause"] = event.GCCause
	}

	return record
}
