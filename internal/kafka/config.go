// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"time"

	"github.com/platformbuilds/telegen/internal/logs/parsers"
)

// Config defines the Kafka receiver configuration
type Config struct {
	// Enabled enables the Kafka logs receiver
	Enabled bool `yaml:"enabled"`

	// Brokers is a list of Kafka broker addresses
	Brokers []string `yaml:"brokers"`

	// GroupID is the consumer group identifier
	GroupID string `yaml:"group_id"`

	// ClientID is the unique client identifier (defaults to hostname-<random>)
	ClientID string `yaml:"client_id"`

	// Topics is a list of Kafka topics to consume from.
	// If any topic starts with "^" it is treated as a regex pattern.
	Topics []string `yaml:"topics"`

	// ExcludeTopics is a list of regex patterns for topics to exclude.
	// Only valid when at least one entry in Topics uses a regex pattern (starts with "^").
	ExcludeTopics []string `yaml:"exclude_topics"`

	// UseLeaderEpoch enables leader epoch for offset validation (requires Kafka >= 2.1.0).
	// Disable for compatibility with older Kafka versions.
	UseLeaderEpoch bool `yaml:"use_leader_epoch"`

	// InitialOffset is the initial offset position: "latest" or "earliest"
	InitialOffset string `yaml:"initial_offset"`

	// SessionTimeout is the maximum time broker waits for heartbeat before removing consumer
	SessionTimeout time.Duration `yaml:"session_timeout"`

	// HeartbeatInterval is the frequency of heartbeats to broker
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`

	// RebalanceTimeout is the maximum time allowed for rebalance to complete
	RebalanceTimeout time.Duration `yaml:"rebalance_timeout"`

	// GroupRebalanceStrategy is the partition assignment strategy
	// Valid values: "range", "roundrobin", "sticky", "cooperative-sticky"
	GroupRebalanceStrategy string `yaml:"group_rebalance_strategy"`

	// MessageMarking controls offset commit behavior
	MessageMarking MessageMarking `yaml:"message_marking"`

	// Batch settings for message consumption
	Batch BatchConfig `yaml:"batch"`

	// Parser configuration for log parsing
	Parser parsers.PipelineConfig `yaml:"parser"`

	// Telemetry metrics enabled for this receiver
	Telemetry TelemetryConfig `yaml:"telemetry"`

	// Authentication configuration
	Auth AuthConfig `yaml:"auth"`

	// TLS configuration
	TLS struct {
		Enable             bool   `yaml:"enable"`
		CAFile             string `yaml:"ca_file"`
		CertFile           string `yaml:"cert_file"`
		KeyFile            string `yaml:"key_file"`
		InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	} `yaml:"tls"`

	// ErrorBackoff configures retry behavior for transient errors
	ErrorBackoff ErrorBackoffConfig `yaml:"error_backoff"`

	// HeaderExtraction controls extraction of Kafka message headers as resource attributes
	HeaderExtraction HeaderExtractionConfig `yaml:"header_extraction"`
}

// HeaderExtractionConfig controls extraction of headers from Kafka records
type HeaderExtractionConfig struct {
	// ExtractHeaders enables extracting Kafka headers as resource attributes
	ExtractHeaders bool `yaml:"extract_headers"`

	// Headers is a list of header keys to extract. If empty and ExtractHeaders is true, extracts all headers.
	Headers []string `yaml:"headers"`
}

// MessageMarking controls how messages are marked as consumed
type MessageMarking struct {
	// After commits offset after successful processing
	After bool `yaml:"after"`

	// OnError commits offset even if consumer returns error
	OnError bool `yaml:"on_error"`

	// OnPermanentError commits offset on permanent errors
	OnPermanentError bool `yaml:"on_permanent_error"`
}

// BatchConfig controls message batching
type BatchConfig struct {
	// Size is the maximum number of messages to batch
	Size int `yaml:"size"`

	// Timeout is the maximum time to wait before flushing batch
	Timeout time.Duration `yaml:"timeout"`

	// MaxPartitionBytes is the maximum bytes per partition to fetch
	MaxPartitionBytes int64 `yaml:"max_partition_bytes"`
}

// AuthConfig configures SASL authentication
type AuthConfig struct {
	// Enabled enables SASL authentication
	Enabled bool `yaml:"enabled"`

	// Mechanism is the SASL mechanism: "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"
	Mechanism string `yaml:"mechanism"`

	// Username for SASL authentication
	Username string `yaml:"username"`

	// Password for SASL authentication
	Password string `yaml:"password"`
}

// ErrorBackoffConfig configures exponential backoff for errors
type ErrorBackoffConfig struct {
	// Enabled enables error backoff retry logic
	Enabled bool `yaml:"enabled"`

	// InitialInterval is the initial backoff interval
	InitialInterval time.Duration `yaml:"initial_interval"`

	// MaxInterval is the maximum backoff interval
	MaxInterval time.Duration `yaml:"max_interval"`

	// Multiplier is the backoff multiplier (1.0 = no backoff)
	Multiplier float64 `yaml:"multiplier"`

	// Jitter adds randomness to backoff
	Jitter float64 `yaml:"jitter"`
}

// TelemetryConfig controls which metrics to emit
type TelemetryConfig struct {
	// Metrics::KafkaReceiverRecords counts records received
	KafkaReceiverRecords bool `yaml:"kafka_receiver_records"`

	// Metrics::KafkaReceiverOffsetLag tracks consumer lag per partition
	KafkaReceiverOffsetLag bool `yaml:"kafka_receiver_offset_lag"`

	// Metrics::KafkaReceiverRecordsDelay tracks message age from kafka timestamp
	KafkaReceiverRecordsDelay bool `yaml:"kafka_receiver_records_delay"`

	// Metrics::KafkaBrokerConnects tracks broker connection attempts
	KafkaBrokerConnects bool `yaml:"kafka_broker_connects"`

	// Metrics::KafkaBrokerDisconnects tracks broker disconnections
	KafkaBrokerDisconnects bool `yaml:"kafka_broker_disconnects"`

	// Metrics::KafkaBrokerReadLatency tracks broker read latency (OnBrokerRead hook)
	KafkaBrokerReadLatency bool `yaml:"kafka_broker_read_latency"`

	// Metrics::KafkaFetchBatchMetrics tracks per-batch metrics (OnFetchBatchRead hook)
	KafkaFetchBatchMetrics bool `yaml:"kafka_fetch_batch_metrics"`
}

// DefaultConfig returns sensible defaults for Kafka receiver configuration
func DefaultConfig() Config {
	return Config{
		Enabled:                false,
		Brokers:                []string{"localhost:9092"},
		GroupID:                "telegen-logs",
		ClientID:               "",
		Topics:                 []string{"application-logs"},
		ExcludeTopics:          []string{},
		InitialOffset:          "latest",
		SessionTimeout:         30 * time.Second,
		HeartbeatInterval:      10 * time.Second,
		RebalanceTimeout:       2 * time.Minute,
		GroupRebalanceStrategy: "cooperative-sticky",
		UseLeaderEpoch:         true, // Default enabled (Kafka 2.1.0+)
		MessageMarking: MessageMarking{
			After:            true,
			OnError:          false,
			OnPermanentError: true,
		},
		Batch: BatchConfig{
			Size:                100,
			Timeout:             5 * time.Second,
			MaxPartitionBytes:   1024 * 1024,
		},
		Parser: parsers.DefaultPipelineConfig(),
		Telemetry: TelemetryConfig{
			KafkaReceiverRecords:      true,
			KafkaReceiverOffsetLag:    true,
			KafkaReceiverRecordsDelay: false,
			KafkaBrokerConnects:       true,
			KafkaBrokerDisconnects:    true,
			KafkaBrokerReadLatency:    true,
			KafkaFetchBatchMetrics:    true,
		},
		Auth: AuthConfig{
			Enabled: false,
		},
		ErrorBackoff: ErrorBackoffConfig{
			Enabled:         false,
			InitialInterval: 500 * time.Millisecond,
			MaxInterval:     30 * time.Second,
			Multiplier:      2.0,
			Jitter:          0.2,
		},
		HeaderExtraction: HeaderExtractionConfig{
			ExtractHeaders: false,
			Headers:        []string{},
		},
	}
}
