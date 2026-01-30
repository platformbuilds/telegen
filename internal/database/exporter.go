// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ExporterConfig holds configuration for the database exporter.
type ExporterConfig struct {
	// ServiceName is the name of the service exporting traces.
	ServiceName string

	// BatchSize is the number of events to batch before exporting.
	BatchSize int

	// FlushInterval is how often to flush events.
	FlushInterval time.Duration

	// MaxQueueSize is the maximum number of events to queue.
	MaxQueueSize int

	// EnableTraces enables trace export.
	EnableTraces bool

	// EnableMetrics enables metric export.
	EnableMetrics bool

	// Logger is the logger to use.
	Logger *slog.Logger
}

// DefaultExporterConfig returns the default exporter configuration.
func DefaultExporterConfig() ExporterConfig {
	return ExporterConfig{
		ServiceName:   "database-tracer",
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		MaxQueueSize:  10000,
		EnableTraces:  true,
		EnableMetrics: true,
		Logger:        slog.Default(),
	}
}

// Exporter exports database traces and metrics via OTLP.
type Exporter struct {
	config ExporterConfig

	tracer trace.Tracer
	meter  metric.Meter

	// Metrics
	queryDuration metric.Float64Histogram
	queryCount    metric.Int64Counter
	errorCount    metric.Int64Counter
	activeQueries metric.Int64UpDownCounter

	eventQueue chan *DatabaseEvent
	done       chan struct{}
	wg         sync.WaitGroup
}

// NewExporter creates a new database exporter.
func NewExporter(config ExporterConfig) (*Exporter, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	e := &Exporter{
		config:     config,
		tracer:     otel.Tracer(config.ServiceName),
		meter:      otel.Meter(config.ServiceName),
		eventQueue: make(chan *DatabaseEvent, config.MaxQueueSize),
		done:       make(chan struct{}),
	}

	// Initialize metrics
	var err error

	e.queryDuration, err = e.meter.Float64Histogram(
		"db.client.operation.duration",
		metric.WithDescription("Database operation duration"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	e.queryCount, err = e.meter.Int64Counter(
		"db.client.operation.count",
		metric.WithDescription("Number of database operations"),
	)
	if err != nil {
		return nil, err
	}

	e.errorCount, err = e.meter.Int64Counter(
		"db.client.operation.error.count",
		metric.WithDescription("Number of database operation errors"),
	)
	if err != nil {
		return nil, err
	}

	e.activeQueries, err = e.meter.Int64UpDownCounter(
		"db.client.connections.active",
		metric.WithDescription("Number of active database operations"),
	)
	if err != nil {
		return nil, err
	}

	return e, nil
}

// Start starts the exporter.
func (e *Exporter) Start(ctx context.Context) error {
	e.wg.Add(1)
	go e.processLoop(ctx)
	return nil
}

// Stop stops the exporter.
func (e *Exporter) Stop() error {
	close(e.done)
	e.wg.Wait()
	return nil
}

// Export queues an event for export.
func (e *Exporter) Export(event *DatabaseEvent) {
	select {
	case e.eventQueue <- event:
	default:
		e.config.Logger.Warn("event queue full, dropping event")
	}
}

// processLoop processes events from the queue.
func (e *Exporter) processLoop(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.FlushInterval)
	defer ticker.Stop()

	batch := make([]*DatabaseEvent, 0, e.config.BatchSize)

	for {
		select {
		case <-e.done:
			// Flush remaining events
			if len(batch) > 0 {
				e.exportBatch(ctx, batch)
			}
			return

		case <-ticker.C:
			if len(batch) > 0 {
				e.exportBatch(ctx, batch)
				batch = batch[:0]
			}

		case event := <-e.eventQueue:
			batch = append(batch, event)
			if len(batch) >= e.config.BatchSize {
				e.exportBatch(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

// exportBatch exports a batch of events.
func (e *Exporter) exportBatch(ctx context.Context, batch []*DatabaseEvent) {
	for _, event := range batch {
		if e.config.EnableTraces {
			e.exportTrace(ctx, event)
		}
		if e.config.EnableMetrics {
			e.exportMetrics(ctx, event)
		}
	}
}

// exportTrace exports a single event as a trace span.
func (e *Exporter) exportTrace(ctx context.Context, event *DatabaseEvent) {
	attrs := []attribute.KeyValue{
		attribute.String("db.system", event.DatabaseType.String()),
		attribute.String("db.name", event.Database),
		attribute.String("db.user", event.User),
		attribute.String("db.operation.name", event.QueryType.String()),
	}

	// Add query if available (be careful with sensitive data)
	if event.NormalizedQuery != "" {
		attrs = append(attrs, attribute.String("db.statement", truncateQuery(event.NormalizedQuery, 2048)))
	}

	if event.Host != "" {
		attrs = append(attrs, attribute.String("server.address", event.Host))
	}
	if event.Port > 0 {
		attrs = append(attrs, attribute.Int("server.port", int(event.Port)))
	}
	if event.RowsAffected >= 0 {
		attrs = append(attrs, attribute.Int64("db.response.rows_affected", event.RowsAffected))
	}
	if event.ErrorCode != 0 {
		attrs = append(attrs, attribute.Int("db.response.status_code", int(event.ErrorCode)))
	}

	_, span := e.tracer.Start(ctx, event.QueryType.String(),
		trace.WithTimestamp(event.Timestamp),
		trace.WithAttributes(attrs...),
	)
	span.End(trace.WithTimestamp(event.Timestamp.Add(event.Latency)))
}

// exportMetrics exports metrics for an event.
func (e *Exporter) exportMetrics(ctx context.Context, event *DatabaseEvent) {
	attrs := []attribute.KeyValue{
		attribute.String("db.system", event.DatabaseType.String()),
		attribute.String("db.name", event.Database),
		attribute.String("db.operation.name", event.QueryType.String()),
	}

	// Record duration
	e.queryDuration.Record(ctx, event.Latency.Seconds(), metric.WithAttributes(attrs...))

	// Increment query count
	e.queryCount.Add(ctx, 1, metric.WithAttributes(attrs...))

	// Increment error count if applicable
	if event.ErrorCode != 0 {
		e.errorCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// ExportStats holds export statistics.
type ExportStats struct {
	TotalExported uint64
	TotalDropped  uint64
	QueueSize     int
	ByDatabase    map[DatabaseType]*DatabaseTypeMetrics
}

// DatabaseTypeMetrics holds metrics for a database type.
type DatabaseTypeMetrics struct {
	DatabaseType  DatabaseType
	ExportedCount uint64
	ErrorCount    uint64
	TotalDuration time.Duration
}

// GetStats returns export statistics.
func (e *Exporter) GetStats() *ExportStats {
	return &ExportStats{
		QueueSize:  len(e.eventQueue),
		ByDatabase: make(map[DatabaseType]*DatabaseTypeMetrics),
	}
}
