// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/mirastacklabs-ai/telegen/internal/logs/parsers"
)

// Telemetry metrics for the Kafka receiver
var (
	kafkaRecordsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "records_total",
		Help:      "Total number of records received from Kafka",
	}, []string{"topic", "partition"})

	kafkaRecordsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "records_processed_total",
		Help:      "Total number of records successfully processed",
	}, []string{"topic", "partition"})

	kafkaRecordsFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "records_failed_total",
		Help:      "Total number of records that failed processing",
	}, []string{"topic", "partition", "error_type"})

	// TODO: Use this metric when offset lag tracking is implemented
	_ = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "offset_lag",
		Help:      "Current offset lag per partition (high watermark - committed offset)",
	}, []string{"topic", "partition"})

	kafkaRecordDelay = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "record_delay_seconds",
		Help:      "Time between record timestamp and processing time",
		Buckets:   []float64{0.001, 0.01, 0.1, 0.5, 1, 5, 10, 30, 60, 300},
	}, []string{"topic"})

	kafkaBrokerConnects = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "broker_connects_total",
		Help:      "Total number of successful broker connections",
	})

	kafkaBrokerDisconnects = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "broker_disconnects_total",
		Help:      "Total number of broker disconnections",
	})

	kafkaPartitionsAssigned = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "partitions_assigned",
		Help:      "Current number of assigned partitions",
	})

	kafkaUnmarshalFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "unmarshal_failed_total",
		Help:      "Total number of records that failed to parse/unmarshal",
	}, []string{"topic"})

	kafkaBrokerThrottleDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "broker_throttle_seconds",
		Help:      "Duration of broker throttling in seconds",
		Buckets:   []float64{0.001, 0.01, 0.1, 0.5, 1, 5, 10, 30, 60},
	}, []string{"broker"})

	kafkaBrokerReadLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "broker_read_latency_seconds",
		Help:      "Time to read from broker in seconds (readWait + timeToRead)",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"broker", "outcome"})

	kafkaFetchBatchRecords = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "fetch_batch_records_total",
		Help:      "Total number of records received per fetch batch",
	}, []string{"topic", "partition", "compression"})

	kafkaFetchBatchBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "fetch_batch_bytes_total",
		Help:      "Total bytes received per fetch batch (compressed)",
	}, []string{"topic", "partition"})

	kafkaFetchBatchBytesUncompressed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "telegen",
		Subsystem: "kafka_receiver",
		Name:      "fetch_batch_bytes_uncompressed_total",
		Help:      "Total bytes received per fetch batch (uncompressed)",
	}, []string{"topic", "partition"})
)

// ComponentStatus represents the lifecycle status of a Kafka receiver
type ComponentStatus string

const (
	StatusStarting ComponentStatus = "starting"
	StatusOK       ComponentStatus = "ok"
	StatusStopping ComponentStatus = "stopping"
	StatusStopped  ComponentStatus = "stopped"
	StatusError    ComponentStatus = "error"
)

// StatusReporter is an optional callback for reporting component status changes
type StatusReporter func(status ComponentStatus, err error)

// Receiver implements a Kafka consumer for logs using franz-go.
// It follows the OpenTelemetry Kafka receiver pattern adapted for telegen's architecture:
// - Uses franz-go for Kafka client (proven, high-performance)
// - Uses telegen's parser.Pipeline for format detection (Docker JSON, CRI-O, Spring Boot, Log4j, etc.)
// - Exports via OTEL SDK LoggerProvider (shared OTLP exporter)
// - Includes partition management and error handling
//
// Receiver implements kgo.Hook interface for telemetry hooks.
type Receiver struct {
	config           Config
	clusterName      string // Cluster identifier for multi-cluster support
	logger           *slog.Logger
	serviceName      string
	parserPipeline   *parsers.Pipeline
	loggerProvider   *sdklog.LoggerProvider

	mu          sync.RWMutex
	client      *kgo.Client
	started     chan struct{}
	closing     chan struct{}
	wg          sync.WaitGroup
	
	// Per-partition state management (following OTEL pattern)
	assignments map[topicPartition]*partitionConsumer
	
	// Topic exclusion patterns (compiled regexes)
	excludePatterns []*regexp.Regexp
	
	// Header keys to extract (empty = extract all when enabled)
	headerKeys map[string]struct{}
	
	// Metrics collection enabled flags
	metricsEnabled bool
	
	// Component status reporting
	status         ComponentStatus
	statusReporter StatusReporter

	// Stats tracking for periodic logging
	statsMessagesReceived  atomic.Int64
	statsMessagesProcessed atomic.Int64
	statsMessagesFailed    atomic.Int64
	statsMessagesExported  atomic.Int64
	statsBytesReceived     atomic.Int64
	statsLastLogTime       atomic.Int64 // Unix timestamp
	discoveredTopics       []string     // Topics discovered from broker metadata
	firstBatchLogged       atomic.Bool  // Whether we've logged the first batch receipt
}

// Compile-time check that Receiver implements kgo.Hook
var _ kgo.Hook = (*Receiver)(nil)

// OnBrokerConnect is called when a connection to a broker is established.
// Implements kgo.HookBrokerConnect.
func (r *Receiver) OnBrokerConnect(meta kgo.BrokerMetadata, _ time.Duration, _ net.Conn, err error) {
	if r.metricsEnabled && r.config.Telemetry.KafkaBrokerConnects {
		if err == nil {
			kafkaBrokerConnects.Inc()
		}
	}
}

// OnBrokerDisconnect is called when a connection to a broker is closed.
// Implements kgo.HookBrokerDisconnect.
func (r *Receiver) OnBrokerDisconnect(meta kgo.BrokerMetadata, _ net.Conn) {
	if r.metricsEnabled && r.config.Telemetry.KafkaBrokerDisconnects {
		kafkaBrokerDisconnects.Inc()
	}
}

// OnBrokerThrottle is called when a broker throttles the client.
// This is critical for detecting broker overload situations.
// Implements kgo.HookBrokerThrottle.
func (r *Receiver) OnBrokerThrottle(meta kgo.BrokerMetadata, throttleInterval time.Duration, _ bool) {
	if r.metricsEnabled {
		brokerName := fmt.Sprintf("%s:%d", meta.Host, meta.Port)
		kafkaBrokerThrottleDuration.WithLabelValues(brokerName).Observe(throttleInterval.Seconds())
		r.logger.Warn("broker throttling consumer",
			slog.String("broker", brokerName),
			slog.Duration("duration", throttleInterval),
		)
	}
}

// OnBrokerRead is called after a read from a broker completes.
// Tracks read latency for performance monitoring.
// Implements kgo.HookBrokerRead.
func (r *Receiver) OnBrokerRead(meta kgo.BrokerMetadata, _ int16, bytesRead int, readWait, timeToRead time.Duration, err error) {
	if r.metricsEnabled && r.config.Telemetry.KafkaBrokerReadLatency {
		brokerName := fmt.Sprintf("%s:%d", meta.Host, meta.Port)
		outcome := "success"
		if err != nil {
			outcome = "failure"
		}
		totalLatency := (readWait + timeToRead).Seconds()
		kafkaBrokerReadLatency.WithLabelValues(brokerName, outcome).Observe(totalLatency)
	}
}

// OnFetchBatchRead is called once per batch read from Kafka.
// Tracks batch-level metrics for throughput monitoring.
// Implements kgo.HookFetchBatchRead.
func (r *Receiver) OnFetchBatchRead(meta kgo.BrokerMetadata, topic string, partition int32, metrics kgo.FetchBatchMetrics) {
	if r.metricsEnabled && r.config.Telemetry.KafkaFetchBatchMetrics {
		partitionStr := fmt.Sprintf("%d", partition)
		compression := compressionCodecToString(metrics.CompressionType)
		
		kafkaFetchBatchRecords.WithLabelValues(topic, partitionStr, compression).Add(float64(metrics.NumRecords))
		kafkaFetchBatchBytes.WithLabelValues(topic, partitionStr).Add(float64(metrics.CompressedBytes))
		kafkaFetchBatchBytesUncompressed.WithLabelValues(topic, partitionStr).Add(float64(metrics.UncompressedBytes))
	}
}

// compressionCodecToString converts a compression codec byte to a string
func compressionCodecToString(c uint8) string {
	switch c {
	case 0:
		return "none"
	case 1:
		return "gzip"
	case 2:
		return "snappy"
	case 3:
		return "lz4"
	case 4:
		return "zstd"
	default:
		return "unknown"
	}
}

type topicPartition struct {
	topic     string
	partition int32
}

// partitionConsumer tracks per-partition state and in-flight message processing
type partitionConsumer struct {
	logger        *slog.Logger
	ctx           context.Context
	cancel        context.CancelCauseFunc
	mu            sync.RWMutex
	wg            sync.WaitGroup // Tracks in-flight message processing goroutines
	backoff       *backoff.ExponentialBackOff
	lastOffset    atomic.Int64   // Last successfully processed offset
}

// isPermanentError checks if an error should not be retried
func isPermanentError(err error) bool {
	if err == nil {
		return false
	}
	// Parsing errors are permanent - retrying won't help
	if errors.Is(err, ErrParseFailed) {
		return true
	}
	// Context cancellation is permanent
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

// ErrParseFailed indicates a log line could not be parsed
var ErrParseFailed = errors.New("failed to parse log")

// ReceiverOption is a functional option for configuring a Receiver
type ReceiverOption func(*Receiver)

// WithClusterName sets the cluster name for multi-cluster identification
func WithClusterName(name string) ReceiverOption {
	return func(r *Receiver) {
		r.clusterName = name
	}
}

// WithStatusReporter sets a callback for component status changes
func WithStatusReporter(reporter StatusReporter) ReceiverOption {
	return func(r *Receiver) {
		r.statusReporter = reporter
	}
}

// NewReceiver creates a new Kafka receiver
func NewReceiver(
	cfg Config,
	serviceName string,
	logger *slog.Logger,
	lp *sdklog.LoggerProvider,
	opts ...ReceiverOption,
) (*Receiver, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("no kafka brokers configured")
	}
	// Validate broker addresses are non-empty
	for i, broker := range cfg.Brokers {
		if broker == "" {
			return nil, fmt.Errorf("kafka broker at index %d is empty", i)
		}
	}
	if len(cfg.Topics) == 0 {
		return nil, errors.New("no kafka topics configured")
	}
	// Validate topics are non-empty
	for i, topic := range cfg.Topics {
		if topic == "" {
			return nil, fmt.Errorf("kafka topic at index %d is empty", i)
		}
	}
	if cfg.GroupID == "" {
		return nil, errors.New("kafka group_id is required")
	}
	// Validate SASL mechanism if auth is enabled
	if cfg.Auth.Enabled {
		switch cfg.Auth.Mechanism {
		case "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512":
			// Valid mechanisms
		case "":
			return nil, errors.New("SASL auth enabled but mechanism not specified")
		default:
			return nil, fmt.Errorf("unsupported SASL mechanism: %s (supported: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)", cfg.Auth.Mechanism)
		}
		if cfg.Auth.Username == "" {
			return nil, errors.New("SASL auth enabled but username is empty")
		}
	}

	// Validate exclude_topics patterns are valid regex and not empty
	if len(cfg.ExcludeTopics) > 0 {
		for _, pattern := range cfg.ExcludeTopics {
			if pattern == "" {
				return nil, errors.New("exclude_topics contains empty string, which would match all topics")
			}
		}
	}

	// Compile topic exclusion patterns
	var excludePatterns []*regexp.Regexp
	for _, pattern := range cfg.ExcludeTopics {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude topic pattern %q: %w", pattern, err)
		}
		excludePatterns = append(excludePatterns, re)
	}

	// Build header keys set for extraction
	var headerKeys map[string]struct{}
	if cfg.HeaderExtraction.ExtractHeaders {
		headerKeys = make(map[string]struct{})
		for _, key := range cfg.HeaderExtraction.Headers {
			headerKeys[key] = struct{}{}
		}
	}

	// Check if any metrics are enabled
	metricsEnabled := cfg.Telemetry.KafkaReceiverRecords ||
		cfg.Telemetry.KafkaReceiverOffsetLag ||
		cfg.Telemetry.KafkaReceiverRecordsDelay ||
		cfg.Telemetry.KafkaBrokerConnects ||
		cfg.Telemetry.KafkaBrokerDisconnects ||
		cfg.Telemetry.KafkaBrokerReadLatency ||
		cfg.Telemetry.KafkaFetchBatchMetrics

	// Create parser pipeline with configured settings
	parserPipeline := parsers.NewPipeline(cfg.Parser, logger)

	receiver := &Receiver{
		config:          cfg,
		clusterName:     "default", // Default cluster name
		logger:          logger,
		serviceName:     serviceName,
		parserPipeline:  parserPipeline,
		loggerProvider:  lp,
		started:         make(chan struct{}),
		closing:         make(chan struct{}),
		assignments:     make(map[topicPartition]*partitionConsumer),
		excludePatterns: excludePatterns,
		headerKeys:      headerKeys,
		metricsEnabled:  metricsEnabled,
		status:          StatusStopped,
	}
	
	// Apply functional options
	for _, opt := range opts {
		opt(receiver)
	}
	
	return receiver, nil
}

// Start initializes and starts the Kafka consumer
func (r *Receiver) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-r.closing:
		return errors.New("receiver is stopping or stopped")
	case <-r.started:
		return errors.New("receiver already started")
	default:
		close(r.started)
	}

	// Report starting status
	r.reportStatus(StatusStarting, nil)

	// Build client options (following OTEL reference pattern)
	opts := []kgo.Opt{
		kgo.SeedBrokers(r.config.Brokers...),
		kgo.ConsumerGroup(r.config.GroupID),
		// NOTE: We add ConsumeTopics() AFTER resolving patterns via metadata
		kgo.SessionTimeout(r.config.SessionTimeout),
		kgo.HeartbeatInterval(r.config.HeartbeatInterval),
		kgo.RebalanceTimeout(r.config.RebalanceTimeout),
		kgo.Balancers(r.getGroupBalancer()),
		// Partition lifecycle callbacks
		kgo.OnPartitionsAssigned(r.onPartitionsAssigned),
		kgo.OnPartitionsRevoked(func(ctx context.Context, client *kgo.Client, m map[string][]int32) {
			r.onPartitionsLost(ctx, client, m, false)
		}),
		kgo.OnPartitionsLost(func(ctx context.Context, client *kgo.Client, m map[string][]int32) {
			r.onPartitionsLost(ctx, client, m, true)
		}),
		// Disable auto-commit - we commit manually after processing
		kgo.DisableAutoCommit(),
		// Register hooks for broker telemetry (OnBrokerConnect, OnBrokerDisconnect, OnBrokerThrottle)
		kgo.WithHooks(r),
	}

	// Leader epoch toggle for Kafka version compatibility
	// Disable for older Kafka versions (< 2.1.0) that don't support leader epochs
	if !r.config.UseLeaderEpoch {
		opts = append(opts, kgo.AdjustFetchOffsetsFn(clearLeaderEpochAdjuster))
	}

	// Initial offset
	if r.config.InitialOffset == "earliest" {
		opts = append(opts, kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	} else {
		opts = append(opts, kgo.ConsumeResetOffset(kgo.NewOffset().AtEnd()))
	}

	// Batch settings
	opts = append(opts,
		kgo.MaxConcurrentFetches(10),
		kgo.BrokerMaxWriteBytes(int32(r.config.Batch.MaxPartitionBytes)),
	)

	// Client ID
	if r.config.ClientID != "" {
		opts = append(opts, kgo.ClientID(r.config.ClientID))
	}

	// TLS configuration
	if r.config.TLS.Enable {
		tlsCfg := &struct{
			Enable             bool
			CAFile             string
			CertFile           string
			KeyFile            string
			InsecureSkipVerify bool
		}{
			Enable:             r.config.TLS.Enable,
			CAFile:             r.config.TLS.CAFile,
			CertFile:           r.config.TLS.CertFile,
			KeyFile:            r.config.TLS.KeyFile,
			InsecureSkipVerify: r.config.TLS.InsecureSkipVerify,
		}
		cc, err := CreateTLSConfig(tlsCfg)
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		opts = append(opts, kgo.DialTLSConfig(cc))
	}

	// SASL authentication
	if r.config.Auth.Enabled {
		saslOpt, err := r.getSASLMechanism()
		if err != nil {
			return fmt.Errorf("failed to configure SASL: %w", err)
		}
		opts = append(opts, saslOpt)
	}

	// Create Franz-go client
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return fmt.Errorf("failed to create kafka client: %w", err)
	}

	// Test broker connectivity
	if err := client.Ping(ctx); err != nil {
		client.Close()
		return fmt.Errorf("failed to connect to kafka brokers: %w", err)
	}

	// Resolve topic patterns to actual topic names from broker metadata
	// This is critical: if topics contain wildcards (*) or regex (^...), we must
	// fetch actual topic names from the broker and match them
	resolvedTopics, err := r.resolveTopicPatterns(ctx, client, r.config.Topics)
	if err != nil {
		client.Close()
		return fmt.Errorf("failed to resolve topic patterns: %w", err)
	}

	if len(resolvedTopics) == 0 {
		client.Close()
		return fmt.Errorf("no topics matched configured patterns: %v", r.config.Topics)
	}

	// Apply exclude_topics filter to the RESOLVED topic names (not patterns)
	// This is the correct place to filter - after patterns are resolved to actual topic names
	filteredTopics := r.filterTopics(resolvedTopics)
	if len(filteredTopics) == 0 {
		client.Close()
		return errors.New("all resolved topics excluded by exclude_topics patterns")
	}

	excludedCount := len(resolvedTopics) - len(filteredTopics)
	if excludedCount > 0 {
		r.logger.Info("topics excluded by exclude_topics patterns",
			slog.String("cluster", r.clusterName),
			slog.Int("excluded_count", excludedCount),
			slog.Any("exclude_patterns", r.config.ExcludeTopics),
		)
	}

	r.discoveredTopics = filteredTopics

	// Close the initial client - we need to recreate with the resolved topics
	client.Close()

	// Now create the REAL consumer client with resolved literal topic names
	opts = append(opts, kgo.ConsumeTopics(filteredTopics...))

	client, err = kgo.NewClient(opts...)
	if err != nil {
		return fmt.Errorf("failed to create kafka consumer client: %w", err)
	}
	r.client = client

	r.logger.Info("kafka receiver started",
		slog.String("cluster", r.clusterName),
		slog.Any("brokers", r.config.Brokers),
		slog.String("group_id", r.config.GroupID),
		slog.Any("topic_patterns", r.config.Topics),
		slog.Any("exclude_patterns", r.config.ExcludeTopics),
		slog.Int("topics_resolved", len(resolvedTopics)),
		slog.Int("topics_excluded", len(resolvedTopics)-len(filteredTopics)),
		slog.Int("topics_subscribed", len(filteredTopics)),
		slog.Any("subscribed_topics", filteredTopics),
		slog.Bool("use_leader_epoch", r.config.UseLeaderEpoch),
		slog.Bool("header_extraction", r.config.HeaderExtraction.ExtractHeaders),
	)

	// Log each topic we're subscribing to for visibility
	for _, topic := range filteredTopics {
		r.logger.Info("subscribing to topic",
			slog.String("cluster", r.clusterName),
			slog.String("topic", topic),
		)
	}

	// Report OK status after successful start
	r.reportStatus(StatusOK, nil)

	// Start stats logging loop in background
	r.wg.Add(1)
	go r.statsLoop(ctx)

	// Start consume loop in background
	r.wg.Add(1)
	go r.consumeLoop(ctx)

	return nil
}

// Stop gracefully shuts down the receiver
func (r *Receiver) Stop(ctx context.Context) error {
	// Report stopping status
	r.reportStatus(StatusStopping, nil)
	
	r.mu.Lock()
	
	select {
	case <-r.closing:
		r.mu.Unlock()
		return errors.New("receiver already stopping")
	default:
		close(r.closing)
	}
	r.mu.Unlock()

	// Close Kafka client (stops consume loop)
	if r.client != nil {
		r.client.LeaveGroup()
		r.client.Close()
	}

	// Wait for consume loop to finish with timeout
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		r.logger.Info("kafka receiver stopped", slog.String("cluster", r.clusterName))
		r.reportStatus(StatusStopped, nil)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("shutdown timeout: %w", ctx.Err())
	}
}

// reportStatus updates the receiver status and notifies the status reporter if configured
func (r *Receiver) reportStatus(status ComponentStatus, err error) {
	r.status = status
	if r.statusReporter != nil {
		r.statusReporter(status, err)
	}
	
	// Also log status changes
	if err != nil {
		r.logger.Error("kafka receiver status change",
			slog.String("cluster", r.clusterName),
			slog.String("status", string(status)),
			slog.Any("error", err),
		)
	} else {
		r.logger.Debug("kafka receiver status change",
			slog.String("cluster", r.clusterName),
			slog.String("status", string(status)),
		)
	}
}

// Status returns the current component status
func (r *Receiver) Status() ComponentStatus {
	return r.status
}

// ClusterName returns the cluster name for this receiver
func (r *Receiver) ClusterName() string {
	return r.clusterName
}

// getGroupBalancer returns the configured rebalance strategy
func (r *Receiver) getGroupBalancer() kgo.GroupBalancer {
	switch r.config.GroupRebalanceStrategy {
	case "range":
		return kgo.RangeBalancer()
	case "roundrobin":
		return kgo.RoundRobinBalancer()
	case "sticky":
		return kgo.StickyBalancer()
	case "cooperative-sticky", "":
		fallthrough
	default:
		return kgo.CooperativeStickyBalancer()
	}
}

// onPartitionsAssigned is called when partitions are assigned to this consumer
func (r *Receiver) onPartitionsAssigned(ctx context.Context, client *kgo.Client, assigned map[string][]int32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	assignedCount := 0
	for topic, partitions := range assigned {
		for _, partition := range partitions {
			tp := topicPartition{topic: topic, partition: partition}
			if _, exists := r.assignments[tp]; !exists {
				pctx, cancel := context.WithCancelCause(ctx)
				r.assignments[tp] = &partitionConsumer{
					logger:  r.logger.With(slog.String("topic", topic), slog.Int64("partition", int64(partition))),
					ctx:     pctx,
					cancel:  cancel,
					backoff: backoff.NewExponentialBackOff(),
				}
				assignedCount++
				r.logger.Info("partition assigned", slog.String("topic", topic), slog.Int64("partition", int64(partition)))
			}
		}
	}

	// Update metrics
	if r.metricsEnabled {
		kafkaPartitionsAssigned.Set(float64(len(r.assignments)))
	}
}

// onPartitionsLost is called when partitions are revoked or lost
func (r *Receiver) onPartitionsLost(ctx context.Context, client *kgo.Client, lost map[string][]int32, isLost bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for topic, partitions := range lost {
		for _, partition := range partitions {
			tp := topicPartition{topic: topic, partition: partition}
			if pc, exists := r.assignments[tp]; exists {
				if isLost {
					pc.cancel(errors.New("partition lost"))
				} else {
					pc.cancel(errors.New("partition revoked"))
				}
				pc.wg.Wait() // Wait for in-flight messages to finish
				delete(r.assignments, tp)
				r.logger.Info("partition removed", slog.String("topic", topic), slog.Int64("partition", int64(partition)))
			}
		}
	}

	// Update metrics
	if r.metricsEnabled {
		kafkaPartitionsAssigned.Set(float64(len(r.assignments)))
		if r.config.Telemetry.KafkaBrokerDisconnects && isLost {
			kafkaBrokerDisconnects.Inc()
		}
	}
}

// consumeLoop polls Kafka and processes messages
func (r *Receiver) consumeLoop(ctx context.Context) {
	defer r.wg.Done()

	for {
		// Check if we're shutting down
		select {
		case <-r.closing:
			return
		default:
		}

		// Poll Kafka for records
		fetches := r.client.PollRecords(ctx, -1)

		if fetches.IsClientClosed() {
			r.logger.Info("kafka consumer stopped")
			return
		}

		// Skip if nothing to process
		if fetches.Empty() {
			continue
		}

		// Log first batch receipt for visibility
		if !r.firstBatchLogged.Load() {
			r.firstBatchLogged.Store(true)
			totalRecords := 0
			topicSet := make(map[string]int)
			fetches.EachPartition(func(p kgo.FetchTopicPartition) {
				totalRecords += len(p.Records)
				topicSet[p.Topic] += len(p.Records)
			})
			topics := make([]string, 0, len(topicSet))
			for t := range topicSet {
				topics = append(topics, t)
			}
			r.logger.Info("kafka receiver receiving messages",
				slog.String("cluster", r.clusterName),
				slog.Int("records_in_first_batch", totalRecords),
				slog.Int("topics_in_batch", len(topics)),
				slog.Any("topics", topics),
				slog.String("status", "consuming"),
			)
		}

		// Process fetch errors
		fetches.EachError(func(topic string, partition int32, err error) {
			r.logger.Error("kafka fetch error",
				slog.String("topic", topic),
				slog.Int64("partition", int64(partition)),
				slog.Any("error", err),
			)
		})

		// Copy assignments map to avoid holding lock during processing
		r.mu.RLock()
		assignments := make(map[topicPartition]*partitionConsumer, len(r.assignments))
		for tp, pc := range r.assignments {
			assignments[tp] = pc
		}
		r.mu.RUnlock()

		// Track offsets to commit after successful processing
		offsetsToCommit := make(map[string]map[int32]kgo.EpochOffset)

		// Process partitions concurrently
		var wg sync.WaitGroup
		var commitMu sync.Mutex

		fetches.EachPartition(func(p kgo.FetchTopicPartition) {
			if len(p.Records) == 0 {
				return
			}

			tp := topicPartition{topic: p.Topic, partition: p.Partition}
			pc, ok := assignments[tp]
			if !ok {
				r.logger.Warn("received records for unassigned partition",
					slog.String("topic", p.Topic),
					slog.Int64("partition", int64(p.Partition)),
				)
				return
			}

			// Track stats for periodic logging
			recordCount := int64(len(p.Records))
			r.statsMessagesReceived.Add(recordCount)
			for _, rec := range p.Records {
				r.statsBytesReceived.Add(int64(len(rec.Value)))
			}

			// Track records received metric
			if r.metricsEnabled && r.config.Telemetry.KafkaReceiverRecords {
				kafkaRecordsReceived.WithLabelValues(p.Topic, fmt.Sprintf("%d", p.Partition)).Add(float64(len(p.Records)))
			}

			// Try to add this message processing to partition consumer's wait group
			pc.mu.RLock()
			select {
			case <-pc.ctx.Done():
				pc.mu.RUnlock()
				return // Partition is being lost, skip
			default:
				pc.wg.Add(1)
				pc.mu.RUnlock()
			}

			wg.Add(1)
			go func(partition kgo.FetchTopicPartition, pc *partitionConsumer) {
				defer wg.Done()
				defer pc.wg.Done()

				var lastSuccessfulOffset int64 = -1
				var processedCount int64

				for _, record := range partition.Records {
					// Track record delay metric
					if r.metricsEnabled && r.config.Telemetry.KafkaReceiverRecordsDelay {
						delay := time.Since(record.Timestamp).Seconds()
						kafkaRecordDelay.WithLabelValues(partition.Topic).Observe(delay)
					}

					err := r.processMessage(pc.ctx, record)
					if err != nil {
						pc.logger.Error("failed to process message",
							slog.Int64("offset", record.Offset),
							slog.Any("error", err),
						)

						// Track failed stats
						r.statsMessagesFailed.Add(1)

						// Track failed records metric
						if r.metricsEnabled && r.config.Telemetry.KafkaReceiverRecords {
							errorType := "transient"
							if isPermanentError(err) {
								errorType = "permanent"
							}
							kafkaRecordsFailed.WithLabelValues(partition.Topic, fmt.Sprintf("%d", partition.Partition), errorType).Inc()
						}

						// Check if this is a permanent error
						if isPermanentError(err) {
							// For permanent errors, we can optionally still commit
							if r.config.MessageMarking.OnPermanentError {
								lastSuccessfulOffset = record.Offset
							}
							continue // Don't retry permanent errors
						}

						// Handle transient errors with optional commit and backoff
						if r.config.MessageMarking.OnError {
							lastSuccessfulOffset = record.Offset
						}

						if r.config.ErrorBackoff.Enabled {
							backoffDuration := r.getBackoffDuration(pc.backoff)
							select {
							case <-time.After(backoffDuration):
							case <-pc.ctx.Done():
								goto commitOffsets
							}
						}
					} else {
						// Success - track the offset
						lastSuccessfulOffset = record.Offset
						processedCount++
						pc.backoff.Reset() // Reset backoff on success

						// Track processed stats (includes OTLP export since processMessage exports)
						r.statsMessagesProcessed.Add(1)
						r.statsMessagesExported.Add(1)

						// Track processed records metric
						if r.metricsEnabled && r.config.Telemetry.KafkaReceiverRecords {
							kafkaRecordsProcessed.WithLabelValues(partition.Topic, fmt.Sprintf("%d", partition.Partition)).Inc()
						}
					}
				}

			commitOffsets:
				// Commit offset after successful processing (if enabled)
				if r.config.MessageMarking.After && lastSuccessfulOffset >= 0 {
					commitMu.Lock()
					if offsetsToCommit[partition.Topic] == nil {
						offsetsToCommit[partition.Topic] = make(map[int32]kgo.EpochOffset)
					}
					// Commit offset + 1 (next offset to fetch)
					offsetsToCommit[partition.Topic][partition.Partition] = kgo.EpochOffset{
						Offset: lastSuccessfulOffset + 1,
					}
					pc.lastOffset.Store(lastSuccessfulOffset)
					commitMu.Unlock()
				}
			}(p, pc)
		})

		wg.Wait()

		// Commit all offsets (fire-and-forget with logging callback)
		if len(offsetsToCommit) > 0 && r.config.MessageMarking.After {
			r.client.CommitOffsets(ctx, offsetsToCommit, func(_ *kgo.Client, _ *kmsg.OffsetCommitRequest, _ *kmsg.OffsetCommitResponse, err error) {
				if err != nil {
					r.logger.Error("failed to commit offsets", slog.Any("error", err))
				}
			})
		}
	}
}

// processMessage parses and exports a single Kafka message
func (r *Receiver) processMessage(ctx context.Context, record *kgo.Record) error {
	if record == nil {
		return nil // Nil records are not an error
	}
	// Parse the raw Kafka message using telegen's parser pipeline
	logLine := string(record.Value)
	if logLine == "" {
		return nil // Empty messages are not an error
	}

	parsedLog := r.parserPipeline.Parse(logLine, "")
	if parsedLog == nil {
		// Track unmarshal/parse failure metric
		if r.metricsEnabled {
			kafkaUnmarshalFailed.WithLabelValues(record.Topic).Inc()
		}
		return ErrParseFailed // Permanent error - won't succeed on retry
	}

	// Handle oversized messages
	if r.config.MaxBodySize > 0 && len(parsedLog.Body) > r.config.MaxBodySize {
		if r.config.SkipOversizedMessages {
			// Skip the message entirely
			r.logger.Warn("skipping oversized kafka message",
				"topic", record.Topic,
				"partition", record.Partition,
				"offset", record.Offset,
				"body_size", len(parsedLog.Body),
				"max_body_size", r.config.MaxBodySize)
			return nil // Not an error - intentionally skipped
		}
		// Truncate the body and mark as truncated
		originalSize := len(parsedLog.Body)
		parsedLog.Body = parsedLog.Body[:r.config.MaxBodySize] + "... [TRUNCATED]"
		if parsedLog.Attributes == nil {
			parsedLog.Attributes = make(map[string]string)
		}
		parsedLog.Attributes["log.truncated"] = "true"
		parsedLog.Attributes["log.original_size"] = fmt.Sprintf("%d", originalSize)
		r.logger.Debug("truncated oversized kafka message",
			"topic", record.Topic,
			"partition", record.Partition,
			"offset", record.Offset,
			"original_size", originalSize,
			"truncated_size", len(parsedLog.Body))
	}

	// Add Kafka metadata as attributes (queryable)
	if parsedLog.Attributes == nil {
		parsedLog.Attributes = make(map[string]string)
	}
	parsedLog.Attributes["kafka.topic"] = record.Topic
	parsedLog.Attributes["kafka.partition"] = fmt.Sprintf("%d", record.Partition)
	parsedLog.Attributes["kafka.offset"] = fmt.Sprintf("%d", record.Offset)
	parsedLog.Attributes["kafka.timestamp"] = record.Timestamp.Format(time.RFC3339Nano)
	if record.Key != nil {
		parsedLog.Attributes["kafka.key"] = string(record.Key)
	}
	parsedLog.Attributes["kafka.consumer_group"] = r.config.GroupID
	parsedLog.Attributes["kafka.message.format"] = parsedLog.Format

	// Add telegen metadata as resource attributes (structural)
	if parsedLog.ResourceAttributes == nil {
		parsedLog.ResourceAttributes = make(map[string]string)
	}
	parsedLog.ResourceAttributes["telegen.signal.category"] = "logs"
	parsedLog.ResourceAttributes["telegen.source.module"] = "kafka_receiver"
	parsedLog.ResourceAttributes["telegen.collector.type"] = "kafka"
	parsedLog.ResourceAttributes["service.name"] = r.serviceName

	// Extract headers as resource attributes if configured
	if r.config.HeaderExtraction.ExtractHeaders && len(record.Headers) > 0 {
		for _, h := range record.Headers {
			// If specific headers are configured, only extract those
			if len(r.headerKeys) > 0 {
				if _, ok := r.headerKeys[h.Key]; !ok {
					continue
				}
			}
			// Add header as resource attribute with kafka.header. prefix
			parsedLog.ResourceAttributes["kafka.header."+h.Key] = string(h.Value)
		}
	}

	// Propagate Kafka headers through context for downstream processors
	ctx = r.contextWithHeaders(ctx, record.Headers)

	// Convert to OTEL log record
	otlRecord := parsedLog.ToOTelRecord()

	// Get logger from provider and emit
	logger := r.loggerProvider.Logger("telegen.kafka")
	logger.Emit(ctx, otlRecord)

	return nil
}

// getBackoffDuration returns the next backoff duration with exponential increase
func (r *Receiver) getBackoffDuration(b *backoff.ExponentialBackOff) time.Duration {
	d := b.NextBackOff()
	if d == backoff.Stop {
		d = r.config.ErrorBackoff.MaxInterval
	}
	return d
}

// getSASLMechanism returns the configured SASL mechanism as a franz-go option
func (r *Receiver) getSASLMechanism() (kgo.Opt, error) {
	switch r.config.Auth.Mechanism {
	case "PLAIN":
		mechanism := plain.Auth{
			User: r.config.Auth.Username,
			Pass: r.config.Auth.Password,
		}.AsMechanism()
		return kgo.SASL(mechanism), nil

	case "SCRAM-SHA-256":
		mechanism := scram.Auth{
			User: r.config.Auth.Username,
			Pass: r.config.Auth.Password,
		}.AsSha256Mechanism()
		return kgo.SASL(mechanism), nil

	case "SCRAM-SHA-512":
		mechanism := scram.Auth{
			User: r.config.Auth.Username,
			Pass: r.config.Auth.Password,
		}.AsSha512Mechanism()
		return kgo.SASL(mechanism), nil

	default:
		return nil, fmt.Errorf("unsupported SASL mechanism: %s (supported: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)", r.config.Auth.Mechanism)
	}
}

// filterTopics returns topics that don't match any exclusion pattern
func (r *Receiver) filterTopics(topics []string) []string {
	if len(r.excludePatterns) == 0 {
		return topics
	}

	var filtered []string
	for _, topic := range topics {
		excluded := false
		for _, pattern := range r.excludePatterns {
			if pattern.MatchString(topic) {
				r.logger.Debug("excluding topic", slog.String("topic", topic), slog.String("pattern", pattern.String()))
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, topic)
		}
	}
	return filtered
}

// resolveTopicPatterns fetches all topics from broker metadata and matches them
// against configured patterns (wildcards, regex, or literal names).
// Returns a list of actual topic names to subscribe to.
func (r *Receiver) resolveTopicPatterns(ctx context.Context, client *kgo.Client, patterns []string) ([]string, error) {
	r.logger.Info("resolving topic patterns from broker metadata",
		slog.String("cluster", r.clusterName),
		slog.Any("patterns", patterns),
	)

	// Request metadata for all topics
	req := kmsg.NewMetadataRequest()
	req.Topics = nil // nil = all topics

	resp, err := req.RequestWith(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch broker metadata: %w", err)
	}

	// Collect all topic names from metadata
	allTopics := make([]string, 0, len(resp.Topics))
	for _, topic := range resp.Topics {
		if topic.ErrorCode == 0 && topic.Topic != nil && *topic.Topic != "" {
			allTopics = append(allTopics, *topic.Topic)
		}
	}

	r.logger.Info("fetched topics from broker",
		slog.String("cluster", r.clusterName),
		slog.Int("total_topics_on_broker", len(allTopics)),
	)

	// Separate patterns into categories and compile regexes
	var literalTopics []string
	var regexes []*regexp.Regexp
	hasWildcard := false

	for _, pattern := range patterns {
		if pattern == "*" {
			hasWildcard = true
			r.logger.Info("pattern: wildcard (*) - will match all non-internal topics",
				slog.String("cluster", r.clusterName),
			)
		} else if strings.HasPrefix(pattern, "^") {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
			}
			regexes = append(regexes, re)
			r.logger.Info("pattern: regex",
				slog.String("cluster", r.clusterName),
				slog.String("regex", pattern),
			)
		} else {
			literalTopics = append(literalTopics, pattern)
			r.logger.Info("pattern: literal topic",
				slog.String("cluster", r.clusterName),
				slog.String("topic", pattern),
			)
		}
	}

	// Build set of resolved topics (using map to dedupe)
	resolvedSet := make(map[string]struct{})

	// Add literal topics directly (verify they exist)
	for _, topic := range literalTopics {
		for _, brokerTopic := range allTopics {
			if brokerTopic == topic {
				resolvedSet[topic] = struct{}{}
				break
			}
		}
		// If literal topic doesn't exist on broker, still add it
		// (Kafka will return error when consuming, which is more informative)
		if _, exists := resolvedSet[topic]; !exists {
			r.logger.Warn("configured topic not found on broker",
				slog.String("cluster", r.clusterName),
				slog.String("topic", topic),
			)
			// Still add it - let Kafka handle the error
			resolvedSet[topic] = struct{}{}
		}
	}

	// Match broker topics against patterns
	for _, brokerTopic := range allTopics {
		// Skip Kafka internal topics (starting with __ like __consumer_offsets)
		// Single underscore topics like _myapp.logs are valid user topics
		if strings.HasPrefix(brokerTopic, "__") {
			continue
		}

		// Check wildcard
		if hasWildcard {
			resolvedSet[brokerTopic] = struct{}{}
			continue
		}

		// Check regex patterns
		for _, re := range regexes {
			if re.MatchString(brokerTopic) {
				resolvedSet[brokerTopic] = struct{}{}
				r.logger.Debug("topic matched regex",
					slog.String("cluster", r.clusterName),
					slog.String("topic", brokerTopic),
					slog.String("regex", re.String()),
				)
				break
			}
		}
	}

	// Convert set to slice
	resolved := make([]string, 0, len(resolvedSet))
	for topic := range resolvedSet {
		resolved = append(resolved, topic)
	}

	r.logger.Info("topic pattern resolution complete",
		slog.String("cluster", r.clusterName),
		slog.Int("patterns_configured", len(patterns)),
		slog.Int("topics_resolved", len(resolved)),
		slog.Any("resolved_topics", resolved),
	)

	return resolved, nil
}

// discoverTopics fetches available topics from broker metadata and logs discovery info.
// This is especially useful when using regex patterns (like "*") to show what topics matched.
// DEPRECATED: Use resolveTopicPatterns instead - kept for backward compatibility
func (r *Receiver) discoverTopics(ctx context.Context, configuredTopics []string) {
	// Request metadata for all topics to discover what's available on the broker
	req := kmsg.NewMetadataRequest()
	req.Topics = nil // nil = all topics

	resp, err := req.RequestWith(ctx, r.client)
	if err != nil {
		r.logger.Warn("failed to fetch broker metadata for topic discovery",
			slog.String("cluster", r.clusterName),
			slog.Any("error", err),
		)
		return
	}

	// Collect all topic names from metadata
	allTopics := make([]string, 0, len(resp.Topics))
	for _, topic := range resp.Topics {
		if topic.ErrorCode == 0 && topic.Topic != nil && *topic.Topic != "" {
			allTopics = append(allTopics, *topic.Topic)
		}
	}

	// If configured topics include regex patterns (like "*" or "^prefix.*"),
	// we need to show which actual topics will be consumed
	isRegexConfig := false
	for _, t := range configuredTopics {
		if t == "*" || strings.HasPrefix(t, "^") || strings.Contains(t, "*") {
			isRegexConfig = true
			break
		}
	}

	if isRegexConfig {
		// Filter topics that match the configured patterns
		r.discoveredTopics = r.matchTopicsToPatterns(allTopics, configuredTopics)
	} else {
		// Direct topic names - verify they exist
		r.discoveredTopics = configuredTopics
	}

	r.logger.Info("kafka topic discovery completed",
		slog.String("cluster", r.clusterName),
		slog.Int("broker_topics_total", len(allTopics)),
		slog.Int("matching_topics", len(r.discoveredTopics)),
		slog.Any("topics_to_consume", r.discoveredTopics),
	)

	// Log each discovered topic for visibility
	for _, topic := range r.discoveredTopics {
		r.logger.Info("subscribing to topic",
			slog.String("cluster", r.clusterName),
			slog.String("topic", topic),
		)
	}
}

// matchTopicsToPatterns returns topics that match any of the configured patterns
func (r *Receiver) matchTopicsToPatterns(allTopics []string, patterns []string) []string {
	matched := make([]string, 0)

	for _, topic := range allTopics {
		// Skip Kafka internal topics (starting with __)
		if strings.HasPrefix(topic, "__") {
			continue
		}

		for _, pattern := range patterns {
			if pattern == "*" {
				// Wildcard matches all non-internal topics
				matched = append(matched, topic)
				break
			} else if strings.HasPrefix(pattern, "^") {
				// Regex pattern
				re, err := regexp.Compile(pattern)
				if err == nil && re.MatchString(topic) {
					matched = append(matched, topic)
					break
				}
			} else if pattern == topic {
				// Exact match
				matched = append(matched, topic)
				break
			}
		}
	}

	return matched
}

// statsLoop periodically logs consumption statistics
func (r *Receiver) statsLoop(ctx context.Context) {
	defer r.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.closing:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.logStats()
		}
	}
}

// logStats logs current consumption statistics
func (r *Receiver) logStats() {
	received := r.statsMessagesReceived.Load()
	processed := r.statsMessagesProcessed.Load()
	failed := r.statsMessagesFailed.Load()
	exported := r.statsMessagesExported.Load()
	bytes := r.statsBytesReceived.Load()

	// Get current partition assignments
	r.mu.RLock()
	partitionCount := len(r.assignments)
	topicSet := make(map[string]struct{})
	for tp := range r.assignments {
		topicSet[tp.topic] = struct{}{}
	}
	r.mu.RUnlock()

	topics := make([]string, 0, len(topicSet))
	for t := range topicSet {
		topics = append(topics, t)
	}

	// Only log if there's activity or first time
	lastLog := r.statsLastLogTime.Load()
	now := time.Now().Unix()
	r.statsLastLogTime.Store(now)

	// Always log stats for visibility (even if 0)
	r.logger.Info("kafka receiver stats",
		slog.String("cluster", r.clusterName),
		slog.Int64("messages_received", received),
		slog.Int64("messages_processed", processed),
		slog.Int64("messages_failed", failed),
		slog.Int64("messages_exported_to_otlp", exported),
		slog.Int64("bytes_received", bytes),
		slog.Int("partitions_assigned", partitionCount),
		slog.Int("topics_consuming", len(topics)),
		slog.Any("active_topics", topics),
		slog.Int64("stats_interval_seconds", now-lastLog),
	)
}

// contextWithHeaders creates a new context with Kafka headers as metadata.
// This allows downstream processors to access header values through the context.
func (r *Receiver) contextWithHeaders(ctx context.Context, headers []kgo.RecordHeader) context.Context {
	if len(headers) == 0 {
		return ctx
	}
	// Store headers in context as a map for downstream access
	headerMap := make(map[string][]string)
	for _, h := range headers {
		headerMap[h.Key] = append(headerMap[h.Key], string(h.Value))
	}
	return context.WithValue(ctx, kafkaHeadersKey, headerMap)
}

// kafkaHeadersKey is the context key for Kafka headers
type kafkaHeadersContextKey struct{}

var kafkaHeadersKey = kafkaHeadersContextKey{}

// GetKafkaHeadersFromContext retrieves Kafka headers from a context.
// Returns nil if no headers are present.
func GetKafkaHeadersFromContext(ctx context.Context) map[string][]string {
	if headers, ok := ctx.Value(kafkaHeadersKey).(map[string][]string); ok {
		return headers
	}
	return nil
}

// clearLeaderEpochAdjuster clears the leader epoch from offsets.
// This is needed for compatibility with Kafka versions < 2.1.0 that don't support leader epochs.
func clearLeaderEpochAdjuster(_ context.Context, topics map[string]map[int32]kgo.Offset) (map[string]map[int32]kgo.Offset, error) {
	for _, partitions := range topics {
		for p, off := range partitions {
			partitions[p] = off.WithEpoch(-1)
		}
	}
	return topics, nil
}

// ============================================================================
// Multi-Cluster Support
// ============================================================================

// MultiReceiver manages multiple Kafka cluster receivers for multi-cluster support.
// Each cluster operates independently with its own config, consumer group, and partitions.
type MultiReceiver struct {
	receivers      []*Receiver
	logger         *slog.Logger
	mu             sync.RWMutex
	started        bool
	statusReporter StatusReporter
	// Fields needed for dynamic receiver creation
	serviceName    string
	lp             *sdklog.LoggerProvider
}

// MultiReceiverConfig holds configs for multiple Kafka clusters
type MultiReceiverConfig struct {
	// Clusters is a list of per-cluster configurations
	Clusters []ClusterConfig `yaml:"clusters"`
}

// ClusterConfig wraps a cluster-specific Kafka configuration with a name
type ClusterConfig struct {
	// Name is a unique identifier for this cluster
	Name string `yaml:"name"`

	// Config is the Kafka receiver configuration for this cluster
	Config
}

// NewMultiReceiver creates a new multi-cluster Kafka receiver
func NewMultiReceiver(
	configs []ClusterConfig,
	serviceName string,
	logger *slog.Logger,
	lp *sdklog.LoggerProvider,
	opts ...ReceiverOption,
) (*MultiReceiver, error) {
	if len(configs) == 0 {
		return nil, errors.New("no kafka clusters configured")
	}

	mr := &MultiReceiver{
		receivers:   make([]*Receiver, 0, len(configs)),
		logger:      logger,
		serviceName: serviceName,
		lp:          lp,
	}

	// Extract status reporter if provided
	var statusReporter StatusReporter
	for _, opt := range opts {
		// Create a temp receiver to extract options
		tempR := &Receiver{}
		opt(tempR)
		if tempR.statusReporter != nil {
			statusReporter = tempR.statusReporter
			mr.statusReporter = statusReporter
		}
	}

	// Create a receiver for each cluster
	for _, clusterCfg := range configs {
		if clusterCfg.Name == "" {
			return nil, errors.New("cluster name is required for each cluster configuration")
		}

		// Create cluster-specific logger
		clusterLogger := logger.With(slog.String("cluster", clusterCfg.Name))

		// Build options for this receiver
		receiverOpts := []ReceiverOption{
			WithClusterName(clusterCfg.Name),
		}
		if statusReporter != nil {
			receiverOpts = append(receiverOpts, WithStatusReporter(statusReporter))
		}

		receiver, err := NewReceiver(clusterCfg.Config, serviceName, clusterLogger, lp, receiverOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create receiver for cluster %q: %w", clusterCfg.Name, err)
		}

		mr.receivers = append(mr.receivers, receiver)
	}

	return mr, nil
}

// Start starts all cluster receivers
func (mr *MultiReceiver) Start(ctx context.Context) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if mr.started {
		return errors.New("multi-receiver already started")
	}

	var startedReceivers []*Receiver
	var startErrors []error

	for _, receiver := range mr.receivers {
		if err := receiver.Start(ctx); err != nil {
			mr.logger.Warn("failed to start kafka receiver",
				slog.String("cluster", receiver.ClusterName()),
				slog.Any("error", err),
			)
			startErrors = append(startErrors, fmt.Errorf("cluster %s: %w", receiver.ClusterName(), err))
		} else {
			startedReceivers = append(startedReceivers, receiver)
			mr.logger.Info("kafka receiver started",
				slog.String("cluster", receiver.ClusterName()),
			)
		}
	}

	// If no receivers started, return combined error
	if len(startedReceivers) == 0 && len(startErrors) > 0 {
		return fmt.Errorf("failed to start any kafka receivers: %v", startErrors)
	}

	mr.started = true

	// Log summary
	mr.logger.Info("multi-cluster kafka receiver started",
		slog.Int("clusters_started", len(startedReceivers)),
		slog.Int("clusters_failed", len(startErrors)),
		slog.Int("clusters_total", len(mr.receivers)),
	)

	return nil
}

// Stop stops all cluster receivers
func (mr *MultiReceiver) Stop(ctx context.Context) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if !mr.started {
		return nil
	}

	var stopErrors []error

	for _, receiver := range mr.receivers {
		if err := receiver.Stop(ctx); err != nil {
			mr.logger.Warn("failed to stop kafka receiver",
				slog.String("cluster", receiver.ClusterName()),
				slog.Any("error", err),
			)
			stopErrors = append(stopErrors, fmt.Errorf("cluster %s: %w", receiver.ClusterName(), err))
		} else {
			mr.logger.Info("kafka receiver stopped",
				slog.String("cluster", receiver.ClusterName()),
			)
		}
	}

	mr.started = false

	if len(stopErrors) > 0 {
		return fmt.Errorf("errors stopping kafka receivers: %v", stopErrors)
	}

	return nil
}

// Receivers returns all managed receivers (for testing/inspection)
func (mr *MultiReceiver) Receivers() []*Receiver {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	// Return a copy to prevent external modification
	result := make([]*Receiver, len(mr.receivers))
	copy(result, mr.receivers)
	return result
}

// ClusterNames returns the names of all configured clusters
func (mr *MultiReceiver) ClusterNames() []string {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	names := make([]string, len(mr.receivers))
	for i, r := range mr.receivers {
		names[i] = r.ClusterName()
	}
	return names
}

// GetReceiver returns the receiver for a specific cluster name
func (mr *MultiReceiver) GetReceiver(clusterName string) *Receiver {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	for _, r := range mr.receivers {
		if r.ClusterName() == clusterName {
			return r
		}
	}
	return nil
}

// AddReceiver dynamically adds a new cluster receiver.
// If the MultiReceiver is already started, the new receiver will be started immediately.
// This is used by the discovery system to add newly discovered Kafka clusters.
func (mr *MultiReceiver) AddReceiver(ctx context.Context, clusterCfg ClusterConfig) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	// Check if cluster already exists
	for _, r := range mr.receivers {
		if r.ClusterName() == clusterCfg.Name {
			return fmt.Errorf("cluster %q already exists", clusterCfg.Name)
		}
	}

	clusterLogger := mr.logger.With(slog.String("cluster", clusterCfg.Name))

	// Build options for this receiver
	receiverOpts := []ReceiverOption{
		WithClusterName(clusterCfg.Name),
	}
	if mr.statusReporter != nil {
		receiverOpts = append(receiverOpts, WithStatusReporter(mr.statusReporter))
	}

	receiver, err := NewReceiver(clusterCfg.Config, mr.serviceName, clusterLogger, mr.lp, receiverOpts...)
	if err != nil {
		return fmt.Errorf("failed to create receiver for cluster %q: %w", clusterCfg.Name, err)
	}

	// If already running, start the new receiver
	if mr.started {
		if err := receiver.Start(ctx); err != nil {
			return fmt.Errorf("failed to start receiver for cluster %q: %w", clusterCfg.Name, err)
		}
		mr.logger.Info("dynamically added and started kafka receiver",
			slog.String("cluster", clusterCfg.Name),
		)
	} else {
		mr.logger.Info("dynamically added kafka receiver (not started yet)",
			slog.String("cluster", clusterCfg.Name),
		)
	}

	mr.receivers = append(mr.receivers, receiver)
	return nil
}

// RemoveReceiver dynamically removes a cluster receiver by name.
// The receiver will be stopped before removal.
// This is used by the discovery system to remove deleted Kafka clusters.
func (mr *MultiReceiver) RemoveReceiver(ctx context.Context, clusterName string) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	var foundIdx = -1
	for i, r := range mr.receivers {
		if r.ClusterName() == clusterName {
			foundIdx = i
			break
		}
	}

	if foundIdx < 0 {
		return fmt.Errorf("cluster %q not found", clusterName)
	}

	receiver := mr.receivers[foundIdx]

	// Stop the receiver if we're running
	if mr.started {
		if err := receiver.Stop(ctx); err != nil {
			mr.logger.Warn("error stopping receiver during removal",
				slog.String("cluster", clusterName),
				slog.Any("error", err),
			)
		}
	}

	// Remove from slice
	mr.receivers = append(mr.receivers[:foundIdx], mr.receivers[foundIdx+1:]...)

	mr.logger.Info("dynamically removed kafka receiver",
		slog.String("cluster", clusterName),
	)

	return nil
}

// UpdateReceiver updates an existing receiver's configuration.
// The receiver will be stopped, recreated with new config, and restarted if running.
func (mr *MultiReceiver) UpdateReceiver(ctx context.Context, clusterCfg ClusterConfig) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	var foundIdx = -1
	for i, r := range mr.receivers {
		if r.ClusterName() == clusterCfg.Name {
			foundIdx = i
			break
		}
	}

	if foundIdx < 0 {
		return fmt.Errorf("cluster %q not found", clusterCfg.Name)
	}

	oldReceiver := mr.receivers[foundIdx]
	wasRunning := mr.started

	// Stop the old receiver
	if wasRunning {
		if err := oldReceiver.Stop(ctx); err != nil {
			mr.logger.Warn("error stopping receiver during update",
				slog.String("cluster", clusterCfg.Name),
				slog.Any("error", err),
			)
		}
	}

	// Create new receiver
	clusterLogger := mr.logger.With(slog.String("cluster", clusterCfg.Name))
	receiverOpts := []ReceiverOption{
		WithClusterName(clusterCfg.Name),
	}
	if mr.statusReporter != nil {
		receiverOpts = append(receiverOpts, WithStatusReporter(mr.statusReporter))
	}

	newReceiver, err := NewReceiver(clusterCfg.Config, mr.serviceName, clusterLogger, mr.lp, receiverOpts...)
	if err != nil {
		return fmt.Errorf("failed to create updated receiver for cluster %q: %w", clusterCfg.Name, err)
	}

	// Start new receiver if we were running
	if wasRunning {
		if err := newReceiver.Start(ctx); err != nil {
			return fmt.Errorf("failed to start updated receiver for cluster %q: %w", clusterCfg.Name, err)
		}
	}

	// Replace in slice
	mr.receivers[foundIdx] = newReceiver

	mr.logger.Info("dynamically updated kafka receiver",
		slog.String("cluster", clusterCfg.Name),
	)

	return nil
}
