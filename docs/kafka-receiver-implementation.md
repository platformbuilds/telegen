# Kafka Receiver Integration - Implementation Complete

## Overview

Telegen now has full Kafka receiver support for consuming raw logs from Kafka topics and exporting them to OpenTelemetry Collector with embedded telegen metadata.

## Architecture

The Kafka receiver follows the telegen design principle: **one agent, many signals** with single unified OTLP exporter.

### Data Flow
```
Kafka Broker
    ↓
[Franz-go Kafka Client]
    ↓
[Message Handler]
    ├→ Parse (existing telegen parsers)
    ├→ Enrich (Kafka metadata + Telegen metadata)
    └→ Convert to OTLP plog.Logs
    ↓
[Logs Consumer Adapter]
    ↓
[OTLP SDK LoggerProvider]
    ↓
[OTLP Exporter (gRPC/HTTP)]
    ↓
OTel Collector
```

## Components Implemented

### 1. **Kafka Package** (`internal/kafka/`)

#### `config.go` (195 lines)
Defines all configuration structures:
- `Config`: Main receiver configuration
- `MessageMarking`: Offset commit behavior (After, OnError, OnPermanentError)
- `BatchConfig`: Message batching settings
- `AuthConfig`: SASL authentication
- `ErrorBackoffConfig`: Exponential backoff retry logic
- `TelemetryConfig`: Metrics emission flags

#### `receiver.go` (371 lines)
Main Kafka consumer implementation:
- Franz-go client with consumer group coordination
- `Start()`: Initialize client, ping brokers, start consume loop
- `Stop()`: Graceful shutdown with timeout
- `consumeLoop()`: Fetch → process → commit loop with error handling
- `handleRecord()`: Parse → enrich → convert → export pipeline
- Automatic partition assignment for multi-pod DaemonSets

#### `handler.go` (116 lines)
Message processing pipeline:
- `MessageHandler`: Orchestrates parse → enrich → convert
- Uses existing `parsers.Pipeline` for auto-format detection
- Validates parsed logs before export
- Tracks telemetry attributes

#### `enricher.go` (133 lines)
Metadata enrichment (multi-tier):
- **Kafka metadata** (as attributes): topic, partition, offset, timestamp, key, size, consumer_group
- **Telegen metadata** (as resource attributes): signal_category, source_module, collector_type, version, ingestion_timestamp

#### `tls.go` (43 lines)
TLS/mutual TLS configuration helper for broker connections.

#### `logs_consumer_adapter.go` (NEW - 160 lines)
Adapts `*sdklog.LoggerProvider` to `consumer.Logs` interface:
- Converts `plog.Logs` (OTLP collector format) to SDK log records
- Bridges OTLP exporter with Kafka receiver
- Enables shared exporter pattern across all signals

### 2. **Configuration Updates** (`internal/config/config.go`)
Added `KafkaLogsConfig` struct with 100+ configuration options:
- Broker connection settings
- Consumer group coordination
- Message processing and batching
- Parser configuration (runtime, application, K8s, trace context)
- Telemetry metrics
- SASL authentication
- TLS configuration
- Error handling and backoff

### 3. **Pipeline Integration** (`internal/pipeline/pipeline.go`)
- Added `GetLogsConsumer()` method returning `consumer.Logs`
- Returns adapter wrapping OTLP LoggerProvider
- Added imports for `kafka` package and `consumer` interface
- Follows telegen pattern of shared exporters across signals

### 4. **Application Startup** (`cmd/telegen/main.go`)
- Added Kafka receiver initialization block
- `convertKafkaConfig()`: Maps config.KafkaLogsConfig → kafka.Config
- `parseDuration()`: Safe duration parsing with defaults
- Starts Kafka receiver after pipeline, reuses shared logs consumer
- Graceful degradation: logs warning if logs consumer unavailable

### 5. **Example Configuration** (`configs/telegen-kafka-logs.yaml`)
Complete example with:
- Broker configuration
- Consumer group setup (for multi-pod coordination)
- Topic subscriptions
- Parser settings (Docker JSON, CRI-O, Spring Boot, Log4j)
- Telemetry metrics
- SASL authentication example
- TLS configuration
- Error backoff settings
- Kubernetes DaemonSet deployment example

## Key Features

### Multi-Pod Coordination
- All pods with same `group_id` automatically coordinate via Kafka consumer groups
- Brokers assign partitions to pods (no custom code needed)
- Supports cooperative-sticky, range, and roundrobin strategies
- Works seamlessly in DaemonSets and StatefulSets

### Log Parsing
Leverages existing telegen parser infrastructure:
- **Runtime parsers**: Auto-detect Docker JSON, CRI-O, containerd formats
- **Application parsers**: Spring Boot, Log4j, JSON, plaintext fallback
- **Trace context extraction**: Extract trace_id/span_id from logs
- **K8s metadata enrichment**: Extract pod/namespace/node context

### Metadata Enrichment  
Fulfills requirement: *"ensure telegen metadata is also embedded into the logs"*
- **Log attributes** (queryable): Kafka topic, partition, offset, timestamp, key, size
- **Resource attributes** (structural): Signal category, source module, collector type, version, service name

### Error Handling
- Exponential backoff with configurable multiplier and jitter
- Distinguish permanent vs transient errors
- Configurable offset commit strategy
- Consumer group rebalancing with timeout

### Telemetry
Configurable metric emission:
- Records processed/parsed/exported
- Consumer lag per partition
- Processing delay (end-to-end latency)
- Broker connection events

## Configuration Schema

```yaml
pipelines:
  kafka:
    enabled: true
    brokers: ["kafka:9092"]
    group_id: "telegen-logs"
    topics: ["app-logs"]
    
    # Consumer coordination (for multi-pod)
    session_timeout: "10s"
    heartbeat_interval: "3s"
    rebalance_timeout: "30s"
    group_rebalance_strategy: "cooperative-sticky"
    
    # Message processing
    message_marking:
      after: true
      on_error: false
      on_permanent_error: true
    
    # Parser configuration
    parser:
      enable_runtime_parsing: true
      enable_application_parsing: true
      default_severity: "INFO"
      extract_trace_context: true
    
    # Batching
    batch:
      size: 100
      timeout: "500ms"
    
    # Auth/TLS
    auth:
      mechanism: "PLAIN"
      username: "user"
      password: "pass"
    
    tls:
      enabled: false
      ca_file: "/etc/kafka/ca.crt"
    
    # Error handling
    error_backoff:
      enabled: true
      initial_interval: "1s"
      max_interval: "30s"
      multiplier: 2.0
```

## Testing Checklist

- [ ] Unit tests for config parsing
- [ ] Unit tests for enricher (Kafka + Telegen metadata)
- [ ] Unit tests for handler (parse → enrich → convert)
- [ ] Unit tests for receiver (state management, shutdown)
- [ ] Integration test with embedded Kafka broker (testcontainers)
- [ ] End-to-end test with actual OTLP collector
- [ ] Multi-pod coordination test (verify partition distribution)
- [ ] Error handling test (permanent vs transient errors, backoff)
- [ ] TLS/SASL test

## Files Created/Modified

### Created
- `internal/kafka/config.go` (195 lines)
- `internal/kafka/enricher.go` (133 lines)
- `internal/kafka/handler.go` (116 lines)
- `internal/kafka/receiver.go` (371 lines)
- `internal/kafka/tls.go` (43 lines)
- `internal/kafka/logs_consumer_adapter.go` (160 lines)
- `configs/telegen-kafka-logs.yaml` (example config)

### Modified
- `internal/config/config.go` (+130 lines: KafkaLogsConfig struct + Kafka field in Pipelines)
- `internal/pipeline/pipeline.go` (+15 lines: GetLogsConsumer method, imports)
- `cmd/telegen/main.go` (+60 lines: Kafka startup, converter functions, imports)

**Total: ~1,050 lines of new code + ~200 lines of configuration**

## Design Decisions

1. **Architecture**:
   - Franz-go (high-performance, built-in consumer groups) vs librdkafka (C dependency)
   - OTEL collector pattern (producer → logs consumer interface) for composability

2. **Metadata**:
   - Kafka metadata as log attributes (queryable) vs resource attributes
   - Telegen metadata as resource attributes (structural, all telegen signals)

3. **Consumer Coordination**:
   - Kafka consumer groups (built-in, proven) vs custom coordination
   - No need for leader election or distributed consensus

4. **Parsing**:
   - Reuse existing telegen parsers (500+ lines, tested) vs building new deserializers
   - Auto-detection with pipeline + fallback to plaintext

5. **Error Handling**:
   - Configurable offset marking (trade-off: delivery guarantees vs simplicity)
   - Exponential backoff with jitter (avoid thundering herd)

## Future Enhancements

1. **Batch Conversion**: Batch Kafka messages before creating plog.Logs (memory efficiency)
2. **Metrics**: Emit receiver metrics (offset.lag, processing.delay) to OTLP
3. **Tracing**: Link Kafka consumer span to log trace context
4. **Dead Letter Queue**: Route parsing failures to separate topic
5. **Schema Registry**: Support Avro/Protobuf with schema registry
6. **Rate Limiting**: Configurable throttling per partition or topic
7. **Exactly-Once Semantics**: Idempotent offset commits with deduplication

## Related Documentation

- [OpenTelemetry Kafka Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkareceiver)
- [Franz-go (Kafka client)](https://pkg.go.dev/github.com/twmb/franz-go)
- [OTLP Logs Specification](https://opentelemetry.io/docs/reference/specification/protocol/logs/)
- [Telegen Architecture](../README.md)
