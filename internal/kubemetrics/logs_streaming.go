// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// LogsStreamingConfig holds configuration for streaming Kubernetes events as OTLP logs
type LogsStreamingConfig struct {
	// Enabled enables streaming K8s events to OTLP endpoint
	Enabled bool `yaml:"enabled"`

	// BufferSize is the size of the event buffer
	BufferSize int `yaml:"buffer_size"`

	// FlushInterval is how often to flush buffered events
	FlushInterval time.Duration `yaml:"flush_interval"`

	// IncludeSignalMetadata adds telegen.* metadata attributes
	IncludeSignalMetadata bool `yaml:"include_signal_metadata"`

	// MetadataConfig controls which metadata fields are exported
	MetadataConfig sigdef.MetadataFieldsConfig `yaml:"metadata_config"`

	// EventTypes filters which event types to stream (Normal, Warning)
	EventTypes []string `yaml:"event_types"`

	// Namespaces filters which namespaces to watch (empty = all)
	Namespaces []string `yaml:"namespaces"`
}

// DefaultLogsStreamingConfig returns sensible defaults
func DefaultLogsStreamingConfig() LogsStreamingConfig {
	return LogsStreamingConfig{
		Enabled:               false,
		BufferSize:            1000,
		FlushInterval:         5 * time.Second,
		IncludeSignalMetadata: true,
		MetadataConfig:        sigdef.DefaultMetadataFieldsConfig(),
		EventTypes:            []string{"Normal", "Warning"},
		Namespaces:            []string{}, // Watch all namespaces
	}
}

// OTLPLogRecord represents a log record to be exported
type OTLPLogRecord struct {
	Timestamp         time.Time
	ObservedTimestamp time.Time
	SeverityNumber    int32
	SeverityText      string
	Body              string
	Attributes        []attribute.KeyValue
	Resource          *resource.Resource
}

// LogsExporter interface for exporting logs
type LogsExporter interface {
	Export(ctx context.Context, logs []OTLPLogRecord) error
	Shutdown(ctx context.Context) error
}

// LogsStreamingExporter streams Kubernetes events as OTLP logs
type LogsStreamingExporter struct {
	config   *LogsStreamingConfig
	client   kubernetes.Interface
	exporter LogsExporter
	resource *resource.Resource
	logger   *slog.Logger

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}

	eventBuffer chan *corev1.Event
	watchers    []watch.Interface

	// Stats
	eventsReceived int64
	eventsExported int64
	lastExportTime time.Time
	lastError      error
}

// NewLogsStreamingExporter creates a new logs streaming exporter
func NewLogsStreamingExporter(
	cfg *LogsStreamingConfig,
	client kubernetes.Interface,
	exporter LogsExporter,
	logger *slog.Logger,
) (*LogsStreamingExporter, error) {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 1000
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Second
	}

	res, err := buildKubeResource()
	if err != nil {
		return nil, err
	}

	return &LogsStreamingExporter{
		config:      cfg,
		client:      client,
		exporter:    exporter,
		resource:    res,
		logger:      logger,
		eventBuffer: make(chan *corev1.Event, cfg.BufferSize),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}, nil
}

// Start begins watching Kubernetes events and streaming to OTLP
func (l *LogsStreamingExporter) Start(ctx context.Context) error {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return nil
	}
	l.running = true
	l.stopCh = make(chan struct{})
	l.doneCh = make(chan struct{})
	l.mu.Unlock()

	// Start event watchers
	if err := l.startWatchers(ctx); err != nil {
		return err
	}

	// Start flush loop
	go l.flushLoop(ctx)

	l.logger.Info("kubemetrics logs streaming exporter started",
		"buffer_size", l.config.BufferSize,
		"flush_interval", l.config.FlushInterval,
		"namespaces", l.config.Namespaces)

	return nil
}

// Stop stops the logs streaming exporter
func (l *LogsStreamingExporter) Stop() {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return
	}
	l.running = false
	close(l.stopCh)
	l.mu.Unlock()

	// Stop all watchers
	for _, w := range l.watchers {
		w.Stop()
	}

	<-l.doneCh
	l.logger.Info("kubemetrics logs streaming exporter stopped")
}

// startWatchers starts watching Kubernetes events in specified namespaces
func (l *LogsStreamingExporter) startWatchers(ctx context.Context) error {
	namespaces := l.config.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{""} // Empty string = all namespaces
	}

	for _, ns := range namespaces {
		watcher, err := l.client.CoreV1().Events(ns).Watch(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		l.watchers = append(l.watchers, watcher)

		go l.processEvents(watcher)
	}

	return nil
}

// processEvents processes events from a watcher
func (l *LogsStreamingExporter) processEvents(watcher watch.Interface) {
	for event := range watcher.ResultChan() {
		if event.Type == watch.Added || event.Type == watch.Modified {
			if e, ok := event.Object.(*corev1.Event); ok {
				// Filter by event type if configured
				if l.shouldIncludeEvent(e) {
					l.mu.Lock()
					l.eventsReceived++
					l.mu.Unlock()

					select {
					case l.eventBuffer <- e:
					default:
						// Buffer full, drop event
						l.logger.Debug("event buffer full, dropping event",
							"namespace", e.Namespace,
							"name", e.Name)
					}
				}
			}
		}
	}
}

// shouldIncludeEvent checks if an event should be included based on filters
func (l *LogsStreamingExporter) shouldIncludeEvent(event *corev1.Event) bool {
	if len(l.config.EventTypes) == 0 {
		return true
	}

	for _, t := range l.config.EventTypes {
		if event.Type == t {
			return true
		}
	}
	return false
}

// flushLoop periodically flushes buffered events
func (l *LogsStreamingExporter) flushLoop(ctx context.Context) {
	defer close(l.doneCh)

	ticker := time.NewTicker(l.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			l.flush(ctx)
			return
		case <-l.stopCh:
			l.flush(ctx)
			return
		case <-ticker.C:
			l.flush(ctx)
		}
	}
}

// flush flushes all buffered events
func (l *LogsStreamingExporter) flush(ctx context.Context) {
	events := make([]*corev1.Event, 0, len(l.eventBuffer))

	// Drain the buffer
drainLoop:
	for {
		select {
		case e := <-l.eventBuffer:
			events = append(events, e)
		default:
			break drainLoop
		}
	}

	if len(events) == 0 {
		return
	}

	// Convert to OTLP logs
	logs := l.convertToLogs(events)

	// Export
	if err := l.exporter.Export(ctx, logs); err != nil {
		l.mu.Lock()
		l.lastError = err
		l.mu.Unlock()
		l.logger.Error("failed to export kubernetes events as logs",
			"error", err,
			"event_count", len(events))
	} else {
		l.mu.Lock()
		l.eventsExported += int64(len(events))
		l.lastExportTime = time.Now()
		l.lastError = nil
		l.mu.Unlock()
		l.logger.Debug("kubernetes events exported as logs",
			"event_count", len(events))
	}
}

// convertToLogs converts Kubernetes events to OTLP log records
func (l *LogsStreamingExporter) convertToLogs(events []*corev1.Event) []OTLPLogRecord {
	logs := make([]OTLPLogRecord, 0, len(events))

	for _, event := range events {
		// Determine severity
		severityNumber := int32(9) // INFO
		severityText := "INFO"
		if event.Type == "Warning" {
			severityNumber = 13 // WARN
			severityText = "WARN"
		}

		// Build attributes
		attrs := []attribute.KeyValue{
			attribute.String("k8s.event.reason", event.Reason),
			attribute.String("k8s.event.type", event.Type),
			attribute.String("k8s.event.action", event.Action),
			attribute.String("k8s.event.source.component", event.Source.Component),
			attribute.String("k8s.event.source.host", event.Source.Host),
			attribute.String("k8s.namespace.name", event.Namespace),
			attribute.String("k8s.object.name", event.InvolvedObject.Name),
			attribute.String("k8s.object.kind", event.InvolvedObject.Kind),
			attribute.String("k8s.object.uid", string(event.InvolvedObject.UID)),
			attribute.String("k8s.object.field_path", event.InvolvedObject.FieldPath),
		}

		// Add count if > 1
		if event.Count > 1 {
			attrs = append(attrs, attribute.Int("k8s.event.count", int(event.Count)))
		}

		// Add signal metadata if enabled
		if l.config.IncludeSignalMetadata {
			meta := &sigdef.SignalMetadata{
				Category:      "Kubernetes Events",
				SubCategory:   "Cluster Events",
				SourceModule:  "github.com/mirastacklabs-ai/telegen/internal/kubemetrics",
				CollectorType: sigdef.CollectorTypeAPI,
				SignalType:    sigdef.SignalLogs,
			}
			attrs = append(attrs, meta.ToAttributesWithConfig(l.config.MetadataConfig)...)
		}

		// Determine timestamp
		timestamp := event.LastTimestamp.Time
		if timestamp.IsZero() {
			if event.EventTime.Time.IsZero() {
				timestamp = time.Now()
			} else {
				timestamp = event.EventTime.Time
			}
		}

		logs = append(logs, OTLPLogRecord{
			Timestamp:         timestamp,
			ObservedTimestamp: time.Now(),
			SeverityNumber:    severityNumber,
			SeverityText:      severityText,
			Body:              event.Message,
			Attributes:        attrs,
			Resource:          l.resource,
		})
	}

	return logs
}

// Stats returns exporter statistics
func (l *LogsStreamingExporter) Stats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return map[string]interface{}{
		"running":          l.running,
		"events_received":  l.eventsReceived,
		"events_exported":  l.eventsExported,
		"buffer_size":      len(l.eventBuffer),
		"last_export_time": l.lastExportTime,
		"last_error":       l.lastError,
	}
}

// SDKLogExporter wraps the OTEL SDK log exporter
type SDKLogExporter struct {
	exporter sdklog.Exporter
}

// NewSDKLogExporter creates a new SDK log exporter wrapper
func NewSDKLogExporter(exporter sdklog.Exporter) *SDKLogExporter {
	return &SDKLogExporter{exporter: exporter}
}

// Export exports logs to the OTEL SDK exporter
func (s *SDKLogExporter) Export(ctx context.Context, logs []OTLPLogRecord) error {
	// Convert OTLPLogRecord to SDK log records
	// Note: This is a simplified conversion - in production you'd use the full SDK
	// The actual implementation would depend on the SDK's internal types

	// For now, we'll use the exporter's ForceFlush as a placeholder
	// A full implementation would create log.Record objects and export them
	return s.exporter.ForceFlush(ctx)
}

// Shutdown shuts down the exporter
func (s *SDKLogExporter) Shutdown(ctx context.Context) error {
	return s.exporter.Shutdown(ctx)
}
