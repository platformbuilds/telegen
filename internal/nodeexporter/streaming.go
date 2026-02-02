// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package nodeexporter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// MetricsBatch represents a batch of collected metrics.
type MetricsBatch struct {
	// Metrics is the list of metric families
	Metrics []*dto.MetricFamily

	// Timestamp is when the metrics were collected
	Timestamp time.Time

	// Environment holds environment metadata
	Environment *DetectedEnvironment
}

// MetricsReceiver is an interface for receiving streamed metrics.
type MetricsReceiver interface {
	// ReceiveMetrics receives a batch of metrics for export.
	ReceiveMetrics(ctx context.Context, batch *MetricsBatch) error
}

// StreamingExporter handles periodic collection and streaming of metrics.
type StreamingExporter struct {
	config          *ExportConfig
	registry        *prometheus.Registry
	environment     *DetectedEnvironment
	logger          *slog.Logger
	receiver        MetricsReceiver
	cache           *MetricCache
	adaptiveBatcher *AdaptiveBatcher

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}

	// Performance stats
	collectCount    int64
	collectDuration time.Duration
	exportCount     int64
	exportDuration  time.Duration
}

// NewStreamingExporter creates a new streaming exporter.
func NewStreamingExporter(
	cfg *ExportConfig,
	registry *prometheus.Registry,
	env *DetectedEnvironment,
	logger *slog.Logger,
) *StreamingExporter {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1000
	}
	if cfg.FlushTimeout == 0 {
		cfg.FlushTimeout = 5 * time.Second
	}

	s := &StreamingExporter{
		config:      cfg,
		registry:    registry,
		environment: env,
		logger:      logger,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}

	// Initialize cache if enabled
	if cfg.Cache.Enabled {
		ttl := cfg.Cache.TTL
		if ttl == 0 {
			ttl = 5 * time.Second
		}
		s.cache = NewMetricCache(registry, ttl, logger)
		logger.Debug("metric caching enabled", "ttl", ttl)
	}

	// Initialize adaptive batcher if enabled
	if cfg.AdaptiveBatching {
		targetLatency := cfg.TargetLatency
		if targetLatency == 0 {
			targetLatency = 100 * time.Millisecond
		}
		s.adaptiveBatcher = NewAdaptiveBatcher(10, cfg.BatchSize, targetLatency, logger)
		logger.Debug("adaptive batching enabled", "target_latency", targetLatency)
	}

	return s
}

// SetReceiver sets the metrics receiver for streaming.
func (s *StreamingExporter) SetReceiver(receiver MetricsReceiver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receiver = receiver
}

// Start begins the periodic metrics collection and streaming.
func (s *StreamingExporter) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	s.mu.Unlock()

	go s.run(ctx)

	s.logger.Info("streaming exporter started",
		"interval", s.config.Interval,
		"use_otlp", s.config.UseOTLP,
		"environment", s.environment.Type)

	return nil
}

// Stop stops the streaming exporter.
func (s *StreamingExporter) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	// Wait for the run loop to finish
	<-s.doneCh
	s.logger.Info("streaming exporter stopped")
}

// run is the main loop for periodic metric collection.
func (s *StreamingExporter) run(ctx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	// Collect immediately on start
	s.collectAndSend(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.collectAndSend(ctx)
		}
	}
}

// collectAndSend collects metrics and sends them to the receiver.
func (s *StreamingExporter) collectAndSend(ctx context.Context) {
	s.mu.RLock()
	receiver := s.receiver
	s.mu.RUnlock()

	if receiver == nil {
		// No receiver configured, skip
		return
	}

	collectStart := time.Now()

	// Collect metrics - use cache if available
	var metricFamilies []*dto.MetricFamily
	var err error
	if s.cache != nil {
		metricFamilies, err = s.cache.Gather()
	} else {
		metricFamilies, err = s.registry.Gather()
	}

	collectDuration := time.Since(collectStart)
	s.collectCount++
	s.collectDuration += collectDuration

	if err != nil {
		s.logger.Error("failed to gather metrics", "error", err)
		return
	}

	if len(metricFamilies) == 0 {
		return
	}

	// Add environment labels to all metrics
	s.addEnvironmentLabels(metricFamilies)

	batch := &MetricsBatch{
		Metrics:     metricFamilies,
		Timestamp:   time.Now(),
		Environment: s.environment,
	}

	// Send to receiver with timeout
	sendCtx, cancel := context.WithTimeout(ctx, s.config.FlushTimeout)
	defer cancel()

	exportStart := time.Now()
	err = receiver.ReceiveMetrics(sendCtx, batch)
	exportDuration := time.Since(exportStart)

	s.exportCount++
	s.exportDuration += exportDuration

	// Record latency for adaptive batching
	if s.adaptiveBatcher != nil {
		s.adaptiveBatcher.RecordLatency(exportDuration)
	}

	if err != nil {
		s.logger.Error("failed to send metrics", "error", err)
	} else {
		s.logger.Debug("metrics exported",
			"families", len(metricFamilies),
			"collect_ms", collectDuration.Milliseconds(),
			"export_ms", exportDuration.Milliseconds())
	}
}

// addEnvironmentLabels adds environment-specific labels to all metrics.
func (s *StreamingExporter) addEnvironmentLabels(families []*dto.MetricFamily) {
	if len(s.environment.Labels) == 0 {
		return
	}

	for _, family := range families {
		for _, metric := range family.Metric {
			for name, value := range s.environment.Labels {
				labelName := name
				labelValue := value
				metric.Label = append(metric.Label, &dto.LabelPair{
					Name:  &labelName,
					Value: &labelValue,
				})
			}
		}
	}
}

// CollectNow triggers an immediate collection and returns the batch.
func (s *StreamingExporter) CollectNow() (*MetricsBatch, error) {
	var metricFamilies []*dto.MetricFamily
	var err error

	if s.cache != nil {
		metricFamilies, err = s.cache.Gather()
	} else {
		metricFamilies, err = s.registry.Gather()
	}
	if err != nil {
		return nil, err
	}

	s.addEnvironmentLabels(metricFamilies)

	return &MetricsBatch{
		Metrics:     metricFamilies,
		Timestamp:   time.Now(),
		Environment: s.environment,
	}, nil
}

// StreamingStats holds performance statistics for the streaming exporter.
type StreamingStats struct {
	CollectCount       int64
	CollectDuration    time.Duration
	AvgCollectDuration time.Duration
	ExportCount        int64
	ExportDuration     time.Duration
	AvgExportDuration  time.Duration
	CacheHitRate       float64
	CurrentBatchSize   int
}

// Stats returns performance statistics for the streaming exporter.
func (s *StreamingExporter) Stats() StreamingStats {
	stats := StreamingStats{
		CollectCount:    s.collectCount,
		CollectDuration: s.collectDuration,
		ExportCount:     s.exportCount,
		ExportDuration:  s.exportDuration,
	}

	if s.collectCount > 0 {
		stats.AvgCollectDuration = s.collectDuration / time.Duration(s.collectCount)
	}
	if s.exportCount > 0 {
		stats.AvgExportDuration = s.exportDuration / time.Duration(s.exportCount)
	}
	if s.cache != nil {
		stats.CacheHitRate = s.cache.HitRate()
	}
	if s.adaptiveBatcher != nil {
		stats.CurrentBatchSize = s.adaptiveBatcher.CurrentSize()
	} else {
		stats.CurrentBatchSize = s.config.BatchSize
	}

	return stats
}

// OTLPAdapter adapts node_exporter metrics to telegen's OTLP export pipeline.
// This is used when UseOTLP is enabled to integrate with telegen's main export path.
type OTLPAdapter struct {
	logger *slog.Logger
	sendFn func(context.Context, []*dto.MetricFamily) error
}

// NewOTLPAdapter creates a new OTLP adapter.
func NewOTLPAdapter(logger *slog.Logger, sendFn func(context.Context, []*dto.MetricFamily) error) *OTLPAdapter {
	return &OTLPAdapter{
		logger: logger,
		sendFn: sendFn,
	}
}

// ReceiveMetrics implements MetricsReceiver for OTLP export.
func (a *OTLPAdapter) ReceiveMetrics(ctx context.Context, batch *MetricsBatch) error {
	if a.sendFn == nil {
		return nil
	}
	return a.sendFn(ctx, batch.Metrics)
}

// LoggingReceiver is a MetricsReceiver that logs metrics for debugging.
type LoggingReceiver struct {
	logger *slog.Logger
}

// NewLoggingReceiver creates a logging receiver for debugging.
func NewLoggingReceiver(logger *slog.Logger) *LoggingReceiver {
	return &LoggingReceiver{logger: logger}
}

// ReceiveMetrics logs the received metrics.
func (r *LoggingReceiver) ReceiveMetrics(ctx context.Context, batch *MetricsBatch) error {
	totalMetrics := 0
	for _, family := range batch.Metrics {
		totalMetrics += len(family.Metric)
	}

	r.logger.Debug("received metrics batch",
		"families", len(batch.Metrics),
		"total_metrics", totalMetrics,
		"timestamp", batch.Timestamp,
		"environment", batch.Environment.Type)

	return nil
}
