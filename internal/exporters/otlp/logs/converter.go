// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"encoding/json"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// Converter converts ProfileEvents to OTLP Logs
type Converter struct {
	config ExporterConfig
}

// NewConverter creates a new Converter
func NewConverter(cfg ExporterConfig) *Converter {
	return &Converter{config: cfg}
}

// ConvertToLogs converts profile events to OTLP Logs
func (c *Converter) ConvertToLogs(events []*ProfileEvent) plog.Logs {
	logs := plog.NewLogs()
	if len(events) == 0 {
		return logs
	}

	rl := logs.ResourceLogs().AppendEmpty()

	// Use service name/version from events if available
	serviceName := c.config.ServiceName
	serviceVersion := ""
	if len(events) > 0 && events[0].ServiceName != "" {
		serviceName = events[0].ServiceName
	}
	if len(events) > 0 && events[0].ServiceVersion != "" {
		serviceVersion = events[0].ServiceVersion
	}
	c.setResourceAttributes(rl.Resource(), serviceName, serviceVersion)

	sl := rl.ScopeLogs().AppendEmpty()
	scopeName := c.config.ScopeName
	if scopeName == "" {
		scopeName = "telegen.profiler"
	}
	scopeVersion := c.config.ScopeVersion
	if scopeVersion == "" {
		scopeVersion = "1.0.0"
	}
	sl.Scope().SetName(scopeName)
	sl.Scope().SetVersion(scopeVersion)

	for _, event := range events {
		lr := sl.LogRecords().AppendEmpty()
		c.profileEventToLogRecord(event, lr)
	}

	return logs
}

func (c *Converter) setResourceAttributes(resource pcommon.Resource, serviceName, serviceVersion string) {
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
	sdkName := c.config.TelemetrySDKName
	if sdkName == "" {
		sdkName = "telegen"
	}
	sdkLang := c.config.TelemetrySDKLang
	if sdkLang == "" {
		sdkLang = "native"
	}
	sdkVersion := c.config.TelemetrySDKVersion
	if sdkVersion == "" {
		sdkVersion = "1.0.0"
	}
	attrs.PutStr("telemetry.sdk.name", sdkName)
	attrs.PutStr("telemetry.sdk.language", sdkLang)
	attrs.PutStr("telemetry.sdk.version", sdkVersion)
}

func (c *Converter) profileEventToLogRecord(event *ProfileEvent, lr plog.LogRecord) {
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
	if jsonData, err := json.Marshal(event); err == nil {
		lr.Body().SetStr(string(jsonData))
	}

	// Set attributes
	attrs := lr.Attributes()
	attrs.PutStr("profile.type", event.ProfileType)
	attrs.PutStr("profile.event_type", event.EventType)
	if event.ProfileSource != "" {
		attrs.PutStr("profile.source", event.ProfileSource)
	}

	// Resolution status
	if event.ResolutionStatus != "" {
		attrs.PutStr("profile.resolution_status", event.ResolutionStatus)
	}

	// Service and environment metadata
	if event.AppName != "" {
		attrs.PutStr("app.name", event.AppName)
	}
	if event.HostName != "" {
		attrs.PutStr("host.name", event.HostName)
	}
	if event.K8sDeployment != "" {
		attrs.PutStr("k8s.deployment.name", event.K8sDeployment)
	}
	if event.K8sPodName != "" {
		attrs.PutStr("k8s.pod.name", event.K8sPodName)
	}
	if event.K8sNodeName != "" {
		attrs.PutStr("k8s.node.name", event.K8sNodeName)
	}
	if event.K8sNamespace != "" {
		attrs.PutStr("k8s.namespace.name", event.K8sNamespace)
	}

	if event.ThreadName != "" {
		attrs.PutStr("thread.name", event.ThreadName)
	}
	if event.ThreadID != 0 {
		attrs.PutInt("thread.id", event.ThreadID)
	}

	if event.TopFunction != "" {
		attrs.PutStr("code.function", event.TopFunction)
	}
	if event.TopClass != "" {
		attrs.PutStr("code.class", event.TopClass)
	}
	if event.StackDepth > 0 {
		attrs.PutInt("profile.stack_depth", int64(event.StackDepth))
	}

	attrs.PutInt("profile.sample_weight", event.SampleWeight)
	if event.DurationNs > 0 {
		attrs.PutInt("profile.duration_ns", event.DurationNs)
	}
	if event.TotalSamples > 0 {
		attrs.PutInt("profile.total_samples", event.TotalSamples)
	}

	// eBPF-specific attributes
	if event.PID > 0 {
		attrs.PutInt("process.pid", int64(event.PID))
	}
	if event.TID > 0 {
		attrs.PutInt("thread.tid", int64(event.TID))
	}
	if event.Comm != "" {
		attrs.PutStr("process.executable.name", event.Comm)
	}
	if event.ContainerID != "" {
		attrs.PutStr("container.id", event.ContainerID)
	}
	if event.BlockReason != "" {
		attrs.PutStr("profile.block_reason", event.BlockReason)
	}

	// JFR-specific attributes
	if event.State != "" {
		attrs.PutStr("thread.state", event.State)
	}
	if event.ObjectClass != "" {
		attrs.PutStr("profile.object_class", event.ObjectClass)
	}
	if event.GCName != "" {
		attrs.PutStr("profile.gc_name", event.GCName)
	}
}
