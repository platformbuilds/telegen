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

	"github.com/platformbuilds/telegen/internal/logs/parsers"
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

	kafkaOffsetLag = promauto.NewGaugeVec(prometheus.GaugeOpts{
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
)

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
	recordsCount  atomic.Int64   // Records processed in current batch
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

// NewReceiver creates a new Kafka receiver
func NewReceiver(
	cfg Config,
	serviceName string,
	logger *slog.Logger,
	lp *sdklog.LoggerProvider,
) (*Receiver, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("no kafka brokers configured")
	}
	if len(cfg.Topics) == 0 {
		return nil, errors.New("no kafka topics configured")
	}

	// Validate topic pattern configuration:
	// exclude_topics is only valid when at least one topic uses regex pattern (starts with "^")
	if len(cfg.ExcludeTopics) > 0 {
		hasRegexTopic := false
		for _, topic := range cfg.Topics {
			if strings.HasPrefix(topic, "^") {
				hasRegexTopic = true
				break
			}
		}
		if !hasRegexTopic {
			return nil, errors.New("exclude_topics is configured but none of the configured topics use regex pattern (must start with '^')")
		}
		// Validate exclude patterns are not empty
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
		cfg.Telemetry.KafkaBrokerDisconnects

	// Create parser pipeline with configured settings
	parserPipeline := parsers.NewPipeline(cfg.Parser, logger)

	return &Receiver{
		config:          cfg,
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
	}, nil
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

	// Filter topics based on exclusion patterns
	filteredTopics := r.filterTopics(r.config.Topics)
	if len(filteredTopics) == 0 {
		return errors.New("all topics excluded by filter patterns")
	}

	// Build client options (following OTEL reference pattern)
	opts := []kgo.Opt{
		kgo.SeedBrokers(r.config.Brokers...),
		kgo.ConsumerGroup(r.config.GroupID),
		kgo.ConsumeTopics(filteredTopics...),
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
	r.client = client

	// Test broker connectivity
	if err := r.client.Ping(ctx); err != nil {
		r.client.Close()
		return fmt.Errorf("failed to connect to kafka brokers: %w", err)
	}

	r.logger.Info("kafka receiver started",
		slog.Any("brokers", r.config.Brokers),
		slog.String("group_id", r.config.GroupID),
		slog.Any("topics", filteredTopics),
		slog.Int("excluded_topics", len(r.config.Topics)-len(filteredTopics)),
		slog.Bool("use_leader_epoch", r.config.UseLeaderEpoch),
		slog.Bool("header_extraction", r.config.HeaderExtraction.ExtractHeaders),
	)

	// Start consume loop in background
	r.wg.Add(1)
	go r.consumeLoop(ctx)

	return nil
}

// Stop gracefully shuts down the receiver
func (r *Receiver) Stop(ctx context.Context) error {
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
		r.logger.Info("kafka receiver stopped")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("shutdown timeout: %w", ctx.Err())
	}
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
