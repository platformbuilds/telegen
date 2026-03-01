// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/mirastacklabs-ai/telegen/internal/logs/parsers"
	"github.com/mirastacklabs-ai/telegen/internal/version"
)

// LogEnricher adds Kafka metadata and Telegen metadata to parsed logs
type LogEnricher struct {
	serviceName string
	logger      *slog.Logger
	config      Config
}

// NewLogEnricher creates a new log enricher
func NewLogEnricher(serviceName string, config Config, logger *slog.Logger) *LogEnricher {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogEnricher{
		serviceName: serviceName,
		logger:      logger,
		config:      config,
	}
}

// Enrich adds Kafka and Telegen metadata to the parsed log
func (e *LogEnricher) Enrich(parsed *parsers.ParsedLog, kafkaMsg *kgo.Record) *parsers.ParsedLog {
	if parsed == nil || kafkaMsg == nil {
		return parsed
	}

	// Ensure attributes map is initialized
	if parsed.Attributes == nil {
		parsed.Attributes = make(map[string]string)
	}

	// Ensure resource attributes map is initialized
	if parsed.ResourceAttributes == nil {
		parsed.ResourceAttributes = make(map[string]string)
	}

	// Add Kafka source metadata as regular attributes
	e.addKafkaMetadata(parsed, kafkaMsg)

	// Add Telegen enrichments as resource attributes
	e.addTelegenMetadata(parsed, kafkaMsg)

	return parsed
}

// addKafkaMetadata adds Kafka-specific metadata as log attributes
func (e *LogEnricher) addKafkaMetadata(parsed *parsers.ParsedLog, kafkaMsg *kgo.Record) {
	// Topic and partition information
	parsed.Attributes["kafka.topic"] = kafkaMsg.Topic
	parsed.Attributes["kafka.partition"] = fmt.Sprintf("%d", kafkaMsg.Partition)
	parsed.Attributes["kafka.offset"] = fmt.Sprintf("%d", kafkaMsg.Offset)

	// Message timestamp
	if !kafkaMsg.Timestamp.IsZero() {
		parsed.Attributes["kafka.timestamp"] = kafkaMsg.Timestamp.Format(time.RFC3339Nano)
	}

	// Consumer group
	parsed.Attributes["kafka.consumer_group"] = e.config.GroupID

	// Message key if present
	if len(kafkaMsg.Key) > 0 {
		parsed.Attributes["kafka.key"] = string(kafkaMsg.Key)
	}

	// Message size
	parsed.Attributes["kafka.message_size"] = fmt.Sprintf("%d", len(kafkaMsg.Value))
}

// addTelegenMetadata adds Telegen-specific metadata as resource attributes
func (e *LogEnricher) addTelegenMetadata(parsed *parsers.ParsedLog, kafkaMsg *kgo.Record) {
	// Signal classification
	parsed.ResourceAttributes["telegen.signal.category"] = "Logs"
	parsed.ResourceAttributes["telegen.signal.subcategory"] = "Kafka"
	parsed.ResourceAttributes["telegen.source.module"] = "internal/kafka"

	// Collector type
	parsed.ResourceAttributes["telegen.collector.type"] = "kafka_receiver"

	// Service identification
	if e.serviceName != "" {
		parsed.ResourceAttributes["service.name"] = e.serviceName
	}

	// Telegen version
	parsed.ResourceAttributes["telegen.version"] = version.Version()

	// Log ingestion metadata
	parsed.ResourceAttributes["telegen.broker_count"] = fmt.Sprintf("%d", len(e.config.Brokers))
	parsed.ResourceAttributes["telegen.group_rebalance_strategy"] = e.config.GroupRebalanceStrategy

	// Parser format information
	if parsed.Format != "" {
		parsed.ResourceAttributes["telegen.parser.format"] = parsed.Format
	}

	// Current timestamp (when log was ingested)
	parsed.ResourceAttributes["telegen.ingestion_timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
}
