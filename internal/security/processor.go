// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/platformbuilds/telegen/internal/security/rules"
	"github.com/platformbuilds/telegen/internal/sigdef"
)

// Processor processes security events from eBPF and exports them as OTel logs
// Tasks: SEC-014, SEC-015
type Processor struct {
	config   Config
	enricher *Enricher
	rules    *rules.Engine
	alerter  *Alerter
	exporter LogExporter

	// Event channels
	syscallChan chan *SyscallEvent
	execveChan  chan *ExecveEvent
	fileChan    chan *FileEvent
	escapeChan  chan *EscapeEvent

	// Metrics
	eventsProcessed uint64
	eventsDropped   uint64
	alertsSent      uint64

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	logger *slog.Logger
}

// LogExporter interface for exporting logs
type LogExporter interface {
	Export(ctx context.Context, logs plog.Logs) error
}

// NewProcessor creates a new security event processor
func NewProcessor(cfg Config, exporter LogExporter, logger *slog.Logger) (*Processor, error) {
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Processor{
		config:      cfg,
		exporter:    exporter,
		syscallChan: make(chan *SyscallEvent, 1024),
		execveChan:  make(chan *ExecveEvent, 1024),
		fileChan:    make(chan *FileEvent, 1024),
		escapeChan:  make(chan *EscapeEvent, 512),
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger,
	}

	// Initialize enricher
	p.enricher = NewEnricher(cfg, logger)

	// Initialize rules engine
	rulesConfig := rules.Config{
		SensitivePaths:   cfg.FileIntegrity.SensitivePaths,
		ExcludePaths:     cfg.FileIntegrity.ExcludePaths,
		ExcludeProcesses: cfg.SyscallAudit.ExcludeProcesses,
		ExcludeUIDs:      cfg.SyscallAudit.ExcludeUIDs,
		MinSeverity:      rules.Severity(cfg.Alerting.MinSeverity),
	}
	p.rules = rules.NewEngine(rulesConfig, logger)

	// Initialize alerter
	p.alerter = NewAlerter(cfg.Alerting, logger)

	return p, nil
}

// Start starts the processor
func (p *Processor) Start() error {
	p.logger.Info("starting security event processor")

	// Start worker goroutines
	p.wg.Add(4)
	go p.processSyscallEvents()
	go p.processExecveEvents()
	go p.processFileEvents()
	go p.processEscapeEvents()

	return nil
}

// Stop stops the processor
func (p *Processor) Stop() error {
	p.logger.Info("stopping security event processor",
		"events_processed", p.eventsProcessed,
		"events_dropped", p.eventsDropped,
		"alerts_sent", p.alertsSent)

	p.cancel()
	p.wg.Wait()
	return nil
}

// ProcessSyscall queues a syscall event for processing
func (p *Processor) ProcessSyscall(event *SyscallEvent) {
	select {
	case p.syscallChan <- event:
	default:
		p.eventsDropped++
	}
}

// ProcessExecve queues an execve event for processing
func (p *Processor) ProcessExecve(event *ExecveEvent) {
	select {
	case p.execveChan <- event:
	default:
		p.eventsDropped++
	}
}

// ProcessFile queues a file event for processing
func (p *Processor) ProcessFile(event *FileEvent) {
	select {
	case p.fileChan <- event:
	default:
		p.eventsDropped++
	}
}

// ProcessEscape queues an escape event for processing
func (p *Processor) ProcessEscape(event *EscapeEvent) {
	select {
	case p.escapeChan <- event:
	default:
		p.eventsDropped++
	}
}

func (p *Processor) processSyscallEvents() {
	defer p.wg.Done()

	batch := make([]*SyscallEvent, 0, p.config.Export.BatchSize)
	ticker := time.NewTicker(time.Duration(p.config.Export.FlushIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			p.flushSyscallBatch(batch)
			return
		case event := <-p.syscallChan:
			// Enrich the event
			p.enricher.EnrichSyscall(event)

			// Evaluate rules and generate alerts
			if result := p.rules.EvaluateSyscall(event.ProcessName, event.UID, event.PID, event.PPID, int(event.SyscallNr), event.SyscallName); result != nil && result.ShouldAlert {
				event.Severity = Severity(result.Severity)
				alert := &Alert{
					ID:          fmt.Sprintf("syscall-%d-%d", event.PID, event.Timestamp.UnixNano()),
					Timestamp:   event.Timestamp,
					Severity:    Severity(result.Severity),
					Type:        event.Type,
					Title:       result.Title,
					Description: result.Description,
					Event:       &event.SecurityEvent,
					Tags:        result.Tags,
				}
				p.sendAlerts([]*Alert{alert})
			}

			batch = append(batch, event)
			if len(batch) >= p.config.Export.BatchSize {
				p.flushSyscallBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.flushSyscallBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (p *Processor) processExecveEvents() {
	defer p.wg.Done()

	batch := make([]*ExecveEvent, 0, p.config.Export.BatchSize)
	ticker := time.NewTicker(time.Duration(p.config.Export.FlushIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			p.flushExecveBatch(batch)
			return
		case event := <-p.execveChan:
			p.enricher.EnrichExecve(event)

			if result := p.rules.EvaluateExecve(event.ProcessName, event.UID, event.PID, event.PPID, event.Filename, event.Args); result != nil && result.ShouldAlert {
				event.Severity = Severity(result.Severity)
				alert := &Alert{
					ID:          fmt.Sprintf("execve-%d-%d", event.PID, event.Timestamp.UnixNano()),
					Timestamp:   event.Timestamp,
					Severity:    Severity(result.Severity),
					Type:        event.Type,
					Title:       result.Title,
					Description: result.Description,
					Event:       &event.SecurityEvent,
					Tags:        result.Tags,
				}
				p.sendAlerts([]*Alert{alert})
			}

			batch = append(batch, event)
			if len(batch) >= p.config.Export.BatchSize {
				p.flushExecveBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.flushExecveBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (p *Processor) processFileEvents() {
	defer p.wg.Done()

	batch := make([]*FileEvent, 0, p.config.Export.BatchSize)
	ticker := time.NewTicker(time.Duration(p.config.Export.FlushIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			p.flushFileBatch(batch)
			return
		case event := <-p.fileChan:
			// Check if file is in sensitive paths
			if !p.isSensitivePath(event.Filename) {
				continue
			}

			p.enricher.EnrichFile(event)

			if result := p.rules.EvaluateFile(event.ProcessName, event.UID, event.PID, int(event.Operation), event.Filename); result != nil && result.ShouldAlert {
				event.Severity = Severity(result.Severity)
				alert := &Alert{
					ID:          fmt.Sprintf("file-%d-%d", event.PID, event.Timestamp.UnixNano()),
					Timestamp:   event.Timestamp,
					Severity:    Severity(result.Severity),
					Type:        event.Type,
					Title:       result.Title,
					Description: result.Description,
					Event:       &event.SecurityEvent,
					Tags:        result.Tags,
				}
				p.sendAlerts([]*Alert{alert})
			}

			batch = append(batch, event)
			if len(batch) >= p.config.Export.BatchSize {
				p.flushFileBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.flushFileBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (p *Processor) processEscapeEvents() {
	defer p.wg.Done()

	batch := make([]*EscapeEvent, 0, p.config.Export.BatchSize)
	ticker := time.NewTicker(time.Duration(p.config.Export.FlushIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			p.flushEscapeBatch(batch)
			return
		case event := <-p.escapeChan:
			p.enricher.EnrichEscape(event)

			if result := p.rules.EvaluateEscape(event.ProcessName, event.PID, int(event.EscapeType), int(event.Capability), event.InContainer); result != nil && result.ShouldAlert {
				event.Severity = Severity(result.Severity)
				alert := &Alert{
					ID:          fmt.Sprintf("escape-%d-%d", event.PID, event.Timestamp.UnixNano()),
					Timestamp:   event.Timestamp,
					Severity:    Severity(result.Severity),
					Type:        event.Type,
					Title:       result.Title,
					Description: result.Description,
					Event:       &event.SecurityEvent,
					Tags:        result.Tags,
				}
				p.sendAlerts([]*Alert{alert})
			}

			batch = append(batch, event)
			if len(batch) >= p.config.Export.BatchSize {
				p.flushEscapeBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.flushEscapeBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (p *Processor) flushSyscallBatch(batch []*SyscallEvent) {
	if len(batch) == 0 {
		return
	}

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("telegen.security")

	for _, event := range batch {
		lr := sl.LogRecords().AppendEmpty()
		p.syscallToLogRecord(event, lr)
		p.eventsProcessed++
	}

	if err := p.exporter.Export(p.ctx, logs); err != nil {
		p.logger.Error("failed to export syscall events", "error", err)
	}
}

func (p *Processor) flushExecveBatch(batch []*ExecveEvent) {
	if len(batch) == 0 {
		return
	}

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("telegen.security")

	for _, event := range batch {
		lr := sl.LogRecords().AppendEmpty()
		p.execveToLogRecord(event, lr)
		p.eventsProcessed++
	}

	if err := p.exporter.Export(p.ctx, logs); err != nil {
		p.logger.Error("failed to export execve events", "error", err)
	}
}

func (p *Processor) flushFileBatch(batch []*FileEvent) {
	if len(batch) == 0 {
		return
	}

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("telegen.security")

	for _, event := range batch {
		lr := sl.LogRecords().AppendEmpty()
		p.fileToLogRecord(event, lr)
		p.eventsProcessed++
	}

	if err := p.exporter.Export(p.ctx, logs); err != nil {
		p.logger.Error("failed to export file events", "error", err)
	}
}

func (p *Processor) flushEscapeBatch(batch []*EscapeEvent) {
	if len(batch) == 0 {
		return
	}

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("telegen.security")

	for _, event := range batch {
		lr := sl.LogRecords().AppendEmpty()
		p.escapeToLogRecord(event, lr)
		p.eventsProcessed++
	}

	if err := p.exporter.Export(p.ctx, logs); err != nil {
		p.logger.Error("failed to export escape events", "error", err)
	}
}

// SEC-015: Convert security events to OTel LogRecord
func (p *Processor) syscallToLogRecord(event *SyscallEvent, lr plog.LogRecord) {
	lr.SetTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))
	lr.SetSeverityText(string(event.Severity))
	lr.SetSeverityNumber(severityToOtel(event.Severity))

	attrs := lr.Attributes()
	attrs.PutStr("security.event.type", string(event.Type))
	attrs.PutStr("security.event.category", "syscall_audit")
	attrs.PutInt("process.pid", int64(event.PID))
	attrs.PutInt("process.parent_pid", int64(event.PPID))
	attrs.PutInt("process.uid", int64(event.UID))
	attrs.PutInt("process.gid", int64(event.GID))
	attrs.PutStr("process.name", event.ProcessName)
	attrs.PutInt("syscall.nr", int64(event.SyscallNr))
	attrs.PutStr("syscall.name", event.SyscallName)
	attrs.PutInt("syscall.return_value", int64(event.ReturnValue))

	// Add container metadata if available
	if event.ContainerID != "" {
		attrs.PutStr("container.id", event.ContainerID)
	}
	if event.PodName != "" {
		attrs.PutStr("k8s.pod.name", event.PodName)
		attrs.PutStr("k8s.namespace.name", event.PodNamespace)
	}

	// Add telegen signal metadata
	addSignalMetadataToLogRecord(sigdef.SyscallAuditLogs, attrs)

	lr.Body().SetStr(fmt.Sprintf("Syscall %s by process %s (PID: %d)",
		event.SyscallName, event.ProcessName, event.PID))
}

func (p *Processor) execveToLogRecord(event *ExecveEvent, lr plog.LogRecord) {
	lr.SetTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))
	lr.SetSeverityText(string(event.Severity))
	lr.SetSeverityNumber(severityToOtel(event.Severity))

	attrs := lr.Attributes()
	attrs.PutStr("security.event.type", string(event.Type))
	attrs.PutStr("security.event.category", "process_execution")
	attrs.PutInt("process.pid", int64(event.PID))
	attrs.PutInt("process.parent_pid", int64(event.PPID))
	attrs.PutInt("process.uid", int64(event.UID))
	attrs.PutInt("process.gid", int64(event.GID))
	attrs.PutStr("process.name", event.ProcessName)
	attrs.PutStr("process.executable.path", event.Filename)
	attrs.PutInt("process.args_count", int64(event.Argc))
	attrs.PutInt("syscall.return_value", int64(event.ReturnValue))

	// Add command line arguments
	if len(event.Args) > 0 {
		argsSlice := attrs.PutEmptySlice("process.command_args")
		for _, arg := range event.Args {
			argsSlice.AppendEmpty().SetStr(arg)
		}
	}

	if event.ContainerID != "" {
		attrs.PutStr("container.id", event.ContainerID)
	}
	if event.PodName != "" {
		attrs.PutStr("k8s.pod.name", event.PodName)
		attrs.PutStr("k8s.namespace.name", event.PodNamespace)
	}

	// Add telegen signal metadata
	addSignalMetadataToLogRecord(sigdef.ExecveLogs, attrs)

	lr.Body().SetStr(fmt.Sprintf("Process execution: %s (PID: %d, Parent: %d)",
		event.Filename, event.PID, event.PPID))
}

func (p *Processor) fileToLogRecord(event *FileEvent, lr plog.LogRecord) {
	lr.SetTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))
	lr.SetSeverityText(string(event.Severity))
	lr.SetSeverityNumber(severityToOtel(event.Severity))

	attrs := lr.Attributes()
	attrs.PutStr("security.event.type", string(event.Type))
	attrs.PutStr("security.event.category", "file_integrity")
	attrs.PutInt("process.pid", int64(event.PID))
	attrs.PutInt("process.uid", int64(event.UID))
	attrs.PutStr("process.name", event.ProcessName)
	attrs.PutStr("file.path", event.Filename)
	attrs.PutStr("file.operation", event.Operation.String())
	attrs.PutInt("file.inode", int64(event.Inode))
	attrs.PutInt("file.mode", int64(event.Mode))

	if event.Operation == FileOpRename && event.NewFilename != "" {
		attrs.PutStr("file.new_path", event.NewFilename)
	}
	if event.Operation == FileOpChmod {
		attrs.PutInt("file.new_mode", int64(event.NewMode))
	}
	if event.Operation == FileOpChown {
		attrs.PutInt("file.new_uid", int64(event.NewUID))
		attrs.PutInt("file.new_gid", int64(event.NewGID))
	}

	if event.ContainerID != "" {
		attrs.PutStr("container.id", event.ContainerID)
	}
	if event.PodName != "" {
		attrs.PutStr("k8s.pod.name", event.PodName)
		attrs.PutStr("k8s.namespace.name", event.PodNamespace)
	}

	// Add telegen signal metadata
	addSignalMetadataToLogRecord(sigdef.FileIntegrityLogs, attrs)

	lr.Body().SetStr(fmt.Sprintf("File %s: %s by %s (PID: %d)",
		event.Operation.String(), event.Filename, event.ProcessName, event.PID))
}

func (p *Processor) escapeToLogRecord(event *EscapeEvent, lr plog.LogRecord) {
	lr.SetTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))
	lr.SetSeverityText(string(event.Severity))
	lr.SetSeverityNumber(severityToOtel(event.Severity))

	attrs := lr.Attributes()
	attrs.PutStr("security.event.type", string(event.Type))
	attrs.PutStr("security.event.category", "container_escape")
	attrs.PutInt("process.pid", int64(event.PID))
	attrs.PutInt("process.uid", int64(event.UID))
	attrs.PutStr("process.name", event.ProcessName)
	attrs.PutStr("escape.type", event.EscapeType.String())
	attrs.PutBool("container.detected", event.InContainer)

	if event.Capability != 0 {
		attrs.PutStr("capability.name", event.Capability.String())
		attrs.PutInt("capability.value", int64(event.Capability))
	}
	if event.TargetPID != 0 {
		attrs.PutInt("target.pid", int64(event.TargetPID))
	}
	if event.MountSource != "" {
		attrs.PutStr("mount.source", event.MountSource)
		attrs.PutStr("mount.target", event.MountTarget)
		attrs.PutStr("mount.fstype", event.MountFstype)
	}

	if event.ContainerID != "" {
		attrs.PutStr("container.id", event.ContainerID)
	}
	if event.PodName != "" {
		attrs.PutStr("k8s.pod.name", event.PodName)
		attrs.PutStr("k8s.namespace.name", event.PodNamespace)
	}

	// Add telegen signal metadata
	addSignalMetadataToLogRecord(sigdef.ContainerEscapeLogs, attrs)

	lr.Body().SetStr(fmt.Sprintf("Container escape attempt: %s by %s (PID: %d)",
		event.EscapeType.String(), event.ProcessName, event.PID))
}

func (p *Processor) sendAlerts(alerts []*Alert) {
	for _, alert := range alerts {
		if err := p.alerter.Send(p.ctx, alert); err != nil {
			p.logger.Error("failed to send alert", "error", err, "alert_id", alert.ID)
		} else {
			p.alertsSent++
		}
	}
}

func (p *Processor) isSensitivePath(path string) bool {
	// TODO: Implement efficient path matching using compiled regex patterns
	// For now, allow all paths - filtering should be done in userspace for flexibility
	return true
}

func severityToOtel(s Severity) plog.SeverityNumber {
	switch s {
	case SeverityInfo:
		return plog.SeverityNumberInfo
	case SeverityLow:
		return plog.SeverityNumberInfo2
	case SeverityMedium:
		return plog.SeverityNumberWarn
	case SeverityHigh:
		return plog.SeverityNumberError
	case SeverityCritical:
		return plog.SeverityNumberFatal
	default:
		return plog.SeverityNumberInfo
	}
}

// addSignalMetadataToLogRecord adds telegen signal metadata attributes to a log record
func addSignalMetadataToLogRecord(metadata *sigdef.SignalMetadata, attrs pcommon.Map) {
	if metadata == nil {
		return
	}
	metadataAttrs := metadata.ToAttributes()
	for _, attr := range metadataAttrs {
		attrs.PutStr(string(attr.Key), attr.Value.AsString())
	}
}
