// Package converters provides signal format conversion to OTLP.
// These converters transform various signal formats (Prometheus, JFR, security events,
// GPU traces, eBPF profiles) into OTLP pdata types for unified export.
package converters

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Converter is the base interface for all format converters.
type Converter interface {
	// Name returns the converter name.
	Name() string
}

// MetricConverter converts metrics from various formats to OTLP.
type MetricConverter interface {
	Converter
	// ConvertMetrics converts source metrics to OTLP format.
	ConvertMetrics(ctx context.Context, source interface{}) (pmetric.Metrics, error)
}

// TraceConverter converts traces from various formats to OTLP.
type TraceConverter interface {
	Converter
	// ConvertTraces converts source traces to OTLP format.
	ConvertTraces(ctx context.Context, source interface{}) (ptrace.Traces, error)
}

// LogConverter converts logs/events from various formats to OTLP.
type LogConverter interface {
	Converter
	// ConvertLogs converts source logs to OTLP format.
	ConvertLogs(ctx context.Context, source interface{}) (plog.Logs, error)
}

// ProfileConverter converts profiling data to OTLP logs.
type ProfileConverter interface {
	Converter
	// ConvertProfiles converts profiling data to OTLP logs.
	ConvertProfiles(ctx context.Context, source interface{}) (plog.Logs, error)
}

// ResourceBuilder helps construct pcommon.Resource with common attributes.
type ResourceBuilder struct {
	resource pcommon.Resource
}

// NewResourceBuilder creates a new ResourceBuilder.
func NewResourceBuilder() *ResourceBuilder {
	return &ResourceBuilder{
		resource: pcommon.NewResource(),
	}
}

// SetServiceName sets the service.name attribute.
func (rb *ResourceBuilder) SetServiceName(name string) *ResourceBuilder {
	rb.resource.Attributes().PutStr("service.name", name)
	return rb
}

// SetServiceNamespace sets the service.namespace attribute.
func (rb *ResourceBuilder) SetServiceNamespace(ns string) *ResourceBuilder {
	rb.resource.Attributes().PutStr("service.namespace", ns)
	return rb
}

// SetServiceVersion sets the service.version attribute.
func (rb *ResourceBuilder) SetServiceVersion(version string) *ResourceBuilder {
	rb.resource.Attributes().PutStr("service.version", version)
	return rb
}

// SetHostName sets the host.name attribute.
func (rb *ResourceBuilder) SetHostName(name string) *ResourceBuilder {
	rb.resource.Attributes().PutStr("host.name", name)
	return rb
}

// SetHostID sets the host.id attribute.
func (rb *ResourceBuilder) SetHostID(id string) *ResourceBuilder {
	rb.resource.Attributes().PutStr("host.id", id)
	return rb
}

// SetAttribute sets a custom attribute.
func (rb *ResourceBuilder) SetAttribute(key string, value interface{}) *ResourceBuilder {
	switch v := value.(type) {
	case string:
		rb.resource.Attributes().PutStr(key, v)
	case int:
		rb.resource.Attributes().PutInt(key, int64(v))
	case int64:
		rb.resource.Attributes().PutInt(key, v)
	case float64:
		rb.resource.Attributes().PutDouble(key, v)
	case bool:
		rb.resource.Attributes().PutBool(key, v)
	}
	return rb
}

// Build returns the constructed resource.
func (rb *ResourceBuilder) Build() pcommon.Resource {
	return rb.resource
}

// TimestampFromTime converts time.Time to pcommon.Timestamp.
func TimestampFromTime(t time.Time) pcommon.Timestamp {
	return pcommon.NewTimestampFromTime(t)
}

// Now returns the current timestamp.
func Now() pcommon.Timestamp {
	return TimestampFromTime(time.Now())
}

// SeverityFromLevel converts a log level string to plog.SeverityNumber.
func SeverityFromLevel(level string) plog.SeverityNumber {
	switch level {
	case "trace", "TRACE":
		return plog.SeverityNumberTrace
	case "debug", "DEBUG":
		return plog.SeverityNumberDebug
	case "info", "INFO":
		return plog.SeverityNumberInfo
	case "warn", "WARN", "warning", "WARNING":
		return plog.SeverityNumberWarn
	case "error", "ERROR":
		return plog.SeverityNumberError
	case "fatal", "FATAL", "critical", "CRITICAL":
		return plog.SeverityNumberFatal
	default:
		return plog.SeverityNumberUnspecified
	}
}
