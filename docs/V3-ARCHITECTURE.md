# Telegen V3 Pipeline Architecture

This document describes the V3 unified observability pipeline architecture for Telegen.

## Overview

The V3 architecture introduces a unified pipeline that handles metrics, traces, and logs through a common data path while maintaining signal-specific optimizations. The design follows OpenTelemetry conventions and uses `pdata` (Protocol Data) types for all signal processing.

## Key Components

### 1. Signal Interface (`internal/pipeline/signal.go`)

The foundation of the V3 architecture is the `Signal` interface, which provides a unified abstraction for all signal types:

```go
type Signal interface {
    Type() SignalType
    Name() string
    Validate() error
    Start() error
    Stop() error
    EmitMetrics(ctx context.Context, md pmetric.Metrics) error
    EmitTraces(ctx context.Context, td ptrace.Traces) error
    EmitLogs(ctx context.Context, ld plog.Logs) error
}
```

Signal types:
- `SignalMetrics` - Metric data (gauges, counters, histograms)
- `SignalTraces` - Distributed traces and spans
- `SignalLogs` - Log records
- `SignalProfiles` - Profiling data (eBPF, JFR)
- `SignalEvents` - Events and notifications

### 2. Unified Exporter (`internal/pipeline/unified_exporter.go`)

The `UnifiedExporter` provides a single export interface for all signals:

```go
type UnifiedExporter struct {
    config     UnifiedExporterConfig
    metrics    ExporterBackend
    traces     ExporterBackend
    logs       ExporterBackend
}
```

Features:
- Batching with configurable size and timeout
- Retry logic with exponential backoff
- Queue-based buffering
- Health monitoring

### 3. Collector Adapters (`internal/pipeline/collector/`)

Flexible adapters for different data sources:

| Adapter | Purpose | Location |
|---------|---------|----------|
| `SNMPAdapter` | SNMP polling | `snmp_adapter.go` |
| `StorageAdapter` | Storage metrics | `storage_adapter.go` |
| `NetInfraAdapter` | Network infrastructure | `netinfra_adapter.go` |
| `RESTAPIAdapter` | HTTP API scraping | `restapi_adapter.go` |
| `PrometheusAdapter` | Prometheus scraping | `prometheus_adapter.go` |
| `ServiceDiscovery` | Dynamic target discovery | `discovery.go` |

### 4. Data Quality & Limits (`internal/pipeline/limits/`)

Protect the pipeline from data quality issues:

#### Cardinality Limiter
```go
limiter := NewCardinalityLimiter(CardinalityConfig{
    Enabled:           true,
    DefaultMaxSeries:  10000,
    GlobalMaxSeries:   100000,
    SeriesTTL:         time.Hour,
})
```

#### Rate Limiter
```go
limiter := NewRateLimiter(RateLimiterConfig{
    Enabled:             true,
    MetricsPerSecond:    10000,
    PauseOnLimitReached: true,
})
```

#### Attribute Limiter
```go
limiter := NewAttributeLimiter(AttributeLimiterConfig{
    MaxResourceAttributes: 128,
    MaxAttributeValueSize: 4096,
    ProtectedAttributes:   []string{"service.name"},
})
```

### 5. Signal Transformation (`internal/pipeline/transform/`)

Rule-based transformation with PII redaction:

#### Transformation Engine
```go
engine := NewTransformEngine(TransformConfig{
    Rules: []TransformRule{
        {
            Name:    "add-environment",
            Match:   RuleMatch{SignalTypes: []string{"metrics", "traces", "logs"}},
            Actions: []RuleAction{{Type: ActionSetAttribute, SetAttribute: &SetAttributeAction{Key: "environment", Value: "production"}}},
        },
    },
})
```

Action types:
- `set_attribute` - Add or update an attribute
- `delete_attribute` - Remove an attribute
- `rename_attribute` - Rename an attribute key
- `hash_attribute` - Hash an attribute value
- `filter` - Drop matching data
- `transform` - Apply regex transformation

#### PII Redaction
```go
matcher := NewPIIMatcher(PIIRedactionConfig{
    Enabled:         true,
    Rules:           defaultPIIRules(), // email, phone, ssn, credit_card, jwt, api_key
    RedactionString: "[REDACTED]",
    ScanLogBodies:   true,
})
```

### 6. Operations (`internal/pipeline/operations/`)

Production-ready operational features:

#### Hot Reload
```go
manager := NewHotReloadManager(HotReloadConfig{
    ConfigPath:      "/etc/telegen/config.yaml",
    CheckInterval:   30 * time.Second,
    EnableSIGHUP:    true,
    RollbackOnError: true,
})
```

Features:
- File-based config change detection
- SIGHUP signal handling
- Validation before apply
- Automatic rollback on error

#### Graceful Shutdown
```go
handler := NewShutdownHandler(ShutdownConfig{
    Timeout:      30 * time.Second,
    DrainTimeout: 10 * time.Second,
})

// Register components with priorities
handler.RegisterWithPriority(ingester, ShutdownPriorityFirst)   // Stop accepting data
handler.RegisterWithPriority(processor, ShutdownPriorityNormal) // Process remaining
handler.RegisterWithPriority(exporter, ShutdownPriorityLast)    // Flush and close
```

## Data Flow

```
                                    ┌─────────────────┐
                                    │   Collectors    │
                                    │  ┌───────────┐  │
                                    │  │ Prometheus│  │
                                    │  │ REST API  │  │
                                    │  │ SNMP      │  │
                                    │  │ eBPF      │  │
                                    │  └───────────┘  │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   Adapters      │
                                    │  Convert to     │
                                    │  pdata format   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │    Limits       │
                                    │  - Cardinality  │
                                    │  - Rate         │
                                    │  - Attributes   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │  Transformation │
                                    │  - Rules Engine │
                                    │  - PII Redact   │
                                    │  - Enrichment   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │ Unified Exporter│
                                    │  - Batching     │
                                    │  - Retry        │
                                    │  - Queue        │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   Backends      │
                                    │  ┌───────────┐  │
                                    │  │ OTLP      │  │
                                    │  │ Prometheus│  │
                                    │  │ Loki      │  │
                                    │  │ Kafka     │  │
                                    │  └───────────┘  │
                                    └─────────────────┘
```

## Configuration Example

```yaml
pipeline:
  # Collector configuration
  collectors:
    prometheus:
      enabled: true
      scrape_interval: 30s
      targets:
        - name: node-exporter
          address: localhost:9100
    
    restapi:
      enabled: true
      endpoints:
        - name: api-health
          url: http://localhost:8080/health
          method: GET
          interval: 60s

  # Data quality limits
  limits:
    cardinality:
      enabled: true
      default_max_series: 10000
      global_max_series: 100000
    
    rate:
      enabled: true
      metrics_per_second: 10000
      traces_per_second: 5000
      logs_per_second: 20000
    
    attributes:
      max_resource_attributes: 128
      max_attribute_value_size: 4096

  # Transformation rules
  transform:
    enabled: true
    rules:
      - name: add-cluster-info
        match:
          signal_types: [metrics, traces, logs]
        actions:
          - type: set_attribute
            set_attribute:
              key: k8s.cluster.name
              value: production-us-east-1
    
    pii_redaction:
      enabled: true
      scan_log_bodies: true
      redaction_string: "[REDACTED]"

  # Export configuration
  export:
    otlp:
      endpoint: otel-collector:4317
      insecure: true
    
    batch:
      size: 1000
      timeout: 5s
    
    retry:
      enabled: true
      max_attempts: 3

  # Operations
  operations:
    hot_reload:
      enabled: true
      check_interval: 30s
      enable_sighup: true
    
    shutdown:
      timeout: 30s
      drain_timeout: 10s
```

## Test Coverage

All components include comprehensive tests:

| Package | Tests | Status |
|---------|-------|--------|
| `internal/pipeline` | 10 | ✅ Pass |
| `internal/pipeline/collector` | 19 | ✅ Pass |
| `internal/pipeline/limits` | 12 | ✅ Pass |
| `internal/pipeline/transform` | 17 | ✅ Pass |
| `internal/pipeline/operations` | 18 | ✅ Pass |
| **Total** | **76** | ✅ Pass |

## Migration from V2

The V3 architecture is designed to coexist with V2 collectors. Existing V2 collectors are wrapped with adapters:

```go
// V2 to V3 adapter
type EBPFTracesAdapter struct {
    v2Collector *ebpf.Collector
}

func (a *EBPFTracesAdapter) EmitTraces(ctx context.Context, td ptrace.Traces) error {
    // Forward to V3 pipeline
    return a.pipeline.ProcessTraces(ctx, td)
}
```

See `internal/pipeline/adapters/` for all V2-to-V3 adapter implementations.

## Performance Considerations

1. **Batching**: Configure batch sizes based on your throughput requirements
2. **Cardinality**: Set appropriate limits to prevent memory issues
3. **Rate Limiting**: Use rate limits to protect downstream systems
4. **Attribute Filtering**: Reduce payload sizes by removing unnecessary attributes
5. **PII Scanning**: Disable log body scanning if not needed for performance

## Health & Monitoring

The pipeline exposes health endpoints:

- `/healthz` - Liveness check
- `/readyz` - Readiness check (respects shutdown state)
- `/metrics` - Prometheus metrics about pipeline operation

Self-telemetry metrics:
- `telegen_pipeline_processed_total{signal="metrics|traces|logs"}` - Total signals processed
- `telegen_pipeline_dropped_total{reason="cardinality|rate|filter"}` - Dropped signals
- `telegen_pipeline_export_latency_seconds` - Export latency histogram
- `telegen_pipeline_queue_size` - Current queue sizes
