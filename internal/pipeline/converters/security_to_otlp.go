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

// SecurityConverter converts security events to OTLP format.
type SecurityConverter struct {
	// IncludeRawEvent includes the raw event data in attributes.
	IncludeRawEvent bool
	// EnrichWithHostInfo adds host information to events.
	EnrichWithHostInfo bool
}

// SecurityEvent represents a security event from eBPF monitoring.
type SecurityEvent struct {
	Type      SecurityEventType      `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  SecuritySeverity       `json:"severity"`
	Process   *ProcessInfo           `json:"process,omitempty"`
	Container *ContainerInfo         `json:"container,omitempty"`
	Details   map[string]interface{} `json:"details"`
	RuleID    string                 `json:"ruleId,omitempty"`
	RuleName  string                 `json:"ruleName,omitempty"`
}

// SecurityEventType represents types of security events.
type SecurityEventType string

const (
	// Syscall events.
	SecurityEventExecve        SecurityEventType = "execve"
	SecurityEventPtrace        SecurityEventType = "ptrace"
	SecurityEventMmap          SecurityEventType = "mmap"
	SecurityEventMprotect      SecurityEventType = "mprotect"
	SecurityEventClone         SecurityEventType = "clone"
	SecurityEventSetuid        SecurityEventType = "setuid"
	SecurityEventSetgid        SecurityEventType = "setgid"
	
	// File integrity events.
	SecurityEventFileCreate    SecurityEventType = "file_create"
	SecurityEventFileModify    SecurityEventType = "file_modify"
	SecurityEventFileDelete    SecurityEventType = "file_delete"
	SecurityEventFileRename    SecurityEventType = "file_rename"
	SecurityEventFilePermChange SecurityEventType = "file_perm_change"
	
	// Container events.
	SecurityEventContainerEscape SecurityEventType = "container_escape"
	SecurityEventPrivilegeEscalation SecurityEventType = "privilege_escalation"
	SecurityEventNamespaceChange SecurityEventType = "namespace_change"
	
	// Network events.
	SecurityEventNetworkConnect SecurityEventType = "network_connect"
	SecurityEventNetworkListen  SecurityEventType = "network_listen"
	SecurityEventDNSQuery       SecurityEventType = "dns_query"
)

// SecuritySeverity represents the severity of a security event.
type SecuritySeverity string

const (
	SecuritySeverityLow      SecuritySeverity = "low"
	SecuritySeverityMedium   SecuritySeverity = "medium"
	SecuritySeverityHigh     SecuritySeverity = "high"
	SecuritySeverityCritical SecuritySeverity = "critical"
)

// ProcessInfo contains process information.
type ProcessInfo struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	UID        int    `json:"uid"`
	GID        int    `json:"gid"`
	Comm       string `json:"comm"`
	Exe        string `json:"exe,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
	StartTime  time.Time `json:"startTime,omitempty"`
}

// ContainerInfo contains container information.
type ContainerInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Image     string `json:"image,omitempty"`
	ImageID   string `json:"imageId,omitempty"`
	Runtime   string `json:"runtime,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	PodName   string `json:"podName,omitempty"`
}

// SecurityEventBatch represents a batch of security events.
type SecurityEventBatch struct {
	Events   []SecurityEvent `json:"events"`
	HostInfo *HostInfo       `json:"hostInfo,omitempty"`
}

// HostInfo contains host information.
type HostInfo struct {
	Hostname string `json:"hostname"`
	HostID   string `json:"hostId,omitempty"`
	OS       string `json:"os,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
}

// NewSecurityConverter creates a new SecurityConverter with default settings.
func NewSecurityConverter() *SecurityConverter {
	return &SecurityConverter{
		IncludeRawEvent:    false,
		EnrichWithHostInfo: true,
	}
}

// Name returns the converter name.
func (c *SecurityConverter) Name() string {
	return "security_to_otlp"
}

// ConvertLogs converts security events to OTLP logs.
func (c *SecurityConverter) ConvertLogs(ctx context.Context, source interface{}) (plog.Logs, error) {
	batch, ok := source.(*SecurityEventBatch)
	if !ok {
		return plog.Logs{}, fmt.Errorf("expected *SecurityEventBatch, got %T", source)
	}

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()

	// Set resource attributes.
	res := rl.Resource()
	res.Attributes().PutStr("service.name", "security-monitor")
	if batch.HostInfo != nil && c.EnrichWithHostInfo {
		res.Attributes().PutStr("host.name", batch.HostInfo.Hostname)
		if batch.HostInfo.HostID != "" {
			res.Attributes().PutStr("host.id", batch.HostInfo.HostID)
		}
		if batch.HostInfo.OS != "" {
			res.Attributes().PutStr("os.type", batch.HostInfo.OS)
		}
		if batch.HostInfo.Kernel != "" {
			res.Attributes().PutStr("os.kernel", batch.HostInfo.Kernel)
		}
	}

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("telegen.security")
	sl.Scope().SetVersion("1.0.0")

	for _, event := range batch.Events {
		lr := sl.LogRecords().AppendEmpty()
		c.convertEvent(&event, lr)
	}

	return logs, nil
}

// convertEvent converts a single security event to a log record.
func (c *SecurityConverter) convertEvent(event *SecurityEvent, lr plog.LogRecord) {
	lr.SetTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))
	lr.SetObservedTimestamp(Now())

	// Set severity.
	severity := c.severityToOTLP(event.Severity)
	lr.SetSeverityNumber(severity)
	lr.SetSeverityText(string(event.Severity))

	// Set body.
	lr.Body().SetStr(fmt.Sprintf("[%s] %s", event.Severity, event.Type))

	// Set attributes.
	attrs := lr.Attributes()
	attrs.PutStr("security.event.type", string(event.Type))
	attrs.PutStr("security.event.category", c.eventCategory(event.Type))

	if event.RuleID != "" {
		attrs.PutStr("security.rule.id", event.RuleID)
	}
	if event.RuleName != "" {
		attrs.PutStr("security.rule.name", event.RuleName)
	}

	// Process info.
	if event.Process != nil {
		attrs.PutInt("process.pid", int64(event.Process.PID))
		attrs.PutInt("process.parent_pid", int64(event.Process.PPID))
		attrs.PutInt("process.uid", int64(event.Process.UID))
		attrs.PutInt("process.gid", int64(event.Process.GID))
		attrs.PutStr("process.command", event.Process.Comm)
		if event.Process.Exe != "" {
			attrs.PutStr("process.executable.path", event.Process.Exe)
		}
		if event.Process.Cmdline != "" {
			attrs.PutStr("process.command_line", event.Process.Cmdline)
		}
		if event.Process.Cwd != "" {
			attrs.PutStr("process.working_directory", event.Process.Cwd)
		}
	}

	// Container info.
	if event.Container != nil {
		attrs.PutStr("container.id", event.Container.ID)
		if event.Container.Name != "" {
			attrs.PutStr("container.name", event.Container.Name)
		}
		if event.Container.Image != "" {
			attrs.PutStr("container.image.name", event.Container.Image)
		}
		if event.Container.ImageID != "" {
			attrs.PutStr("container.image.id", event.Container.ImageID)
		}
		if event.Container.Runtime != "" {
			attrs.PutStr("container.runtime", event.Container.Runtime)
		}
		if event.Container.Namespace != "" {
			attrs.PutStr("k8s.namespace.name", event.Container.Namespace)
		}
		if event.Container.PodName != "" {
			attrs.PutStr("k8s.pod.name", event.Container.PodName)
		}
	}

	// Event-specific details.
	for k, v := range event.Details {
		c.setAttributeValue(attrs, "security.detail."+k, v)
	}

	// Raw event.
	if c.IncludeRawEvent {
		rawJSON, err := json.Marshal(event)
		if err == nil {
			attrs.PutStr("security.event.raw", string(rawJSON))
		}
	}
}

// severityToOTLP converts SecuritySeverity to OTLP severity.
func (c *SecurityConverter) severityToOTLP(sev SecuritySeverity) plog.SeverityNumber {
	switch sev {
	case SecuritySeverityLow:
		return plog.SeverityNumberInfo
	case SecuritySeverityMedium:
		return plog.SeverityNumberWarn
	case SecuritySeverityHigh:
		return plog.SeverityNumberError
	case SecuritySeverityCritical:
		return plog.SeverityNumberFatal
	default:
		return plog.SeverityNumberInfo
	}
}

// eventCategory returns the category for a security event type.
func (c *SecurityConverter) eventCategory(eventType SecurityEventType) string {
	switch eventType {
	case SecurityEventExecve, SecurityEventPtrace, SecurityEventMmap,
		SecurityEventMprotect, SecurityEventClone, SecurityEventSetuid, SecurityEventSetgid:
		return "syscall"
	case SecurityEventFileCreate, SecurityEventFileModify, SecurityEventFileDelete,
		SecurityEventFileRename, SecurityEventFilePermChange:
		return "file_integrity"
	case SecurityEventContainerEscape, SecurityEventPrivilegeEscalation, SecurityEventNamespaceChange:
		return "container"
	case SecurityEventNetworkConnect, SecurityEventNetworkListen, SecurityEventDNSQuery:
		return "network"
	default:
		return "unknown"
	}
}

// setAttributeValue sets an attribute value with proper type handling.
func (c *SecurityConverter) setAttributeValue(attrs pcommon.Map, key string, value interface{}) {
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
	case []string:
		slice := attrs.PutEmptySlice(key)
		for _, s := range v {
			slice.AppendEmpty().SetStr(s)
		}
	default:
		attrs.PutStr(key, fmt.Sprintf("%v", v))
	}
}

// ConvertMetrics converts security events to OTLP metrics (aggregated counts).
func (c *SecurityConverter) ConvertMetrics(ctx context.Context, source interface{}) (pmetric.Metrics, error) {
	batch, ok := source.(*SecurityEventBatch)
	if !ok {
		return pmetric.Metrics{}, fmt.Errorf("expected *SecurityEventBatch, got %T", source)
	}

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	res := rm.Resource()
	res.Attributes().PutStr("service.name", "security-monitor")

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen.security")
	sm.Scope().SetVersion("1.0.0")

	// Aggregate event counts by type and severity.
	typeCounts := make(map[SecurityEventType]int64)
	severityCounts := make(map[SecuritySeverity]int64)
	categoryCounts := make(map[string]int64)

	for _, event := range batch.Events {
		typeCounts[event.Type]++
		severityCounts[event.Severity]++
		categoryCounts[c.eventCategory(event.Type)]++
	}

	// Events by type.
	m := sm.Metrics().AppendEmpty()
	m.SetName("security.events.by_type")
	m.SetDescription("Security events by type")
	sum := m.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	for eventType, count := range typeCounts {
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(count)
		dp.SetTimestamp(Now())
		dp.Attributes().PutStr("event_type", string(eventType))
	}

	// Events by severity.
	m2 := sm.Metrics().AppendEmpty()
	m2.SetName("security.events.by_severity")
	m2.SetDescription("Security events by severity")
	sum2 := m2.SetEmptySum()
	sum2.SetIsMonotonic(true)
	sum2.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	for sev, count := range severityCounts {
		dp := sum2.DataPoints().AppendEmpty()
		dp.SetIntValue(count)
		dp.SetTimestamp(Now())
		dp.Attributes().PutStr("severity", string(sev))
	}

	// Events by category.
	m3 := sm.Metrics().AppendEmpty()
	m3.SetName("security.events.by_category")
	m3.SetDescription("Security events by category")
	sum3 := m3.SetEmptySum()
	sum3.SetIsMonotonic(true)
	sum3.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	for cat, count := range categoryCounts {
		dp := sum3.DataPoints().AppendEmpty()
		dp.SetIntValue(count)
		dp.SetTimestamp(Now())
		dp.Attributes().PutStr("category", cat)
	}

	return metrics, nil
}
