# Unified Pipeline Architecture

Telegen runs a single production pipeline implementation: the V3 `UnifiedPipeline`. Legacy pipeline code is retired from the runtime path. The unified pipeline processes all signal types (traces, metrics, logs, profiles) through a common architecture with per-signal adapters, converters, and exporters.

---

## High-Level Architecture

```
Signal Sources (eBPF / Polling / File)
        ↓
Ring Buffers + Large Buffers
        ↓
Protocol Parsers (frame decode → request.Span / pdata)
        ↓
Unified Pipeline
  ├── Adapter Registry (per-collector signal adapters)
  ├── Converting Pipeline (format transformation)
  ├── Integration Layer (limits, transforms, PII redaction)
  ├── Persistent WAL Queues (per-signal, with replay)
  └── Multi-Endpoint Exporter (failover/fanout + circuit breaker)
        ↓
Shared OTLP Clients (gRPC-primary, HTTP fallback)
        ↓
Backend (OTel Collector, Prometheus Remote Write, etc.)
```

---

## Signal Sources

The unified pipeline ingests signals from multiple source types:

| Source | Signal Types | Mechanism |
|--------|-------------|-----------|
| **eBPF Tracers** | Traces, Profiles | Ring buffer events (generic tracer, Go tracer, GPU event tracer, LLM tracer, log enricher) |
| **JFR Pipeline** | Profiles (logs) | File watching → JFR-to-JSON conversion |
| **File Log Tailer** | Logs | glob-based file watching with Docker/CRI-O/Spring Boot parsers |
| **Host Metrics** | Metrics | procfs reading (CPU, memory, disk, network) |
| **K8s Metrics** | Metrics | kube-state-metrics + cadvisor streaming to OTLP |
| **K8s Events** | Logs | K8s Event API → OTLP logs |
| **SNMP** | Metrics | Polling via SNMP v1/v2c/v3 |
| **Storage Adapters** | Metrics, Logs | Polling via vendor REST APIs (Dell, HPE, Pure, NetApp) |
| **Network Infra** | Metrics | Polling via REST/SOAP APIs (Arista, Cisco ACI, Palo Alto, FortiGate) |
| **VMware vSphere** | Metrics, Logs | govmomi PropertyCollector + EventManager |
| **Kafka Logs** | Logs | Kafka topic consumption with multi-format parsing |
| **Security Monitors** | Logs | eBPF syscall audit, file integrity, container escape |

---

## Adapter Registry

The adapter registry provides pluggable per-collector adapters that normalize diverse signal formats into the unified `PipelineSignal` interface.

| Adapter | Source | Signal Type | Description |
|---------|--------|-------------|-------------|
| **eBPF** | Traces, Profiles | `TraceSignal`, `ProfileSignal` | Converts eBPF ring buffer events to OTLP pdata |
| **JFR** | Profiles | `ProfileSignal` | Converts JFR events to OTLP profile data |
| **File Log** | Logs | `LogSignal` | Converts tailed log lines to OTLP log records |
| **Host Metrics** | Metrics | `MetricSignal` | Converts procfs readings to OTLP metric data |
| **Kube Metrics** | Metrics | `MetricSignal` | Converts K8s API objects to OTLP metrics |
| **Kafka Logs** | Logs | `LogSignal` | Converts Kafka messages to OTLP log records |
| **SNMP** | Metrics | `MetricSignal` | Converts SNMP poll results to OTLP metrics |
| **Storage** | Metrics, Logs | `MetricSignal`, `LogSignal` | Converts vendor API responses to OTLP |
| **Network Infra** | Metrics | `MetricSignal` | Converts firewall/SDN API responses to OTLP metrics |
| **VMware** | Metrics, Logs | `MetricSignal`, `LogSignal` | Converts vCenter metrics/events to OTLP |
| **Security** | Logs | `LogSignal` | Converts eBPF security events to OTLP log records |
| **GPU** | Metrics, Traces | `MetricSignal`, `TraceSignal` | Converts NVML readings and CUDA events to OTLP |
| **DB Tracing** | Traces | `TraceSignal` | Converts database wire protocol to OTLP spans |
| **Log-Trace Correlation** | Logs | `LogSignal` | Injects trace_id/span_id into log records |

---

## Converting Pipeline

The converting pipeline transforms signals from source-native formats to OTLP pdata:

| Converter | Input | Output | Description |
|-----------|-------|--------|-------------|
| `ebpf_profile_to_otlp` | eBPF profile events | OTLP Profiles | CPU, off-CPU, memory, mutex profiles |
| `security_to_otlp` | eBPF security events | OTLP Logs | Syscall audit, file integrity, container escape |
| `prometheus_to_otlp` | Prometheus metrics | OTLP Metrics | Node exporter, kube-state-metrics |
| `jfr_to_otlp` | JFR events | OTLP Logs | Java Flight Recorder events as log records |
| `gpu_to_otlp` | NVML readings | OTLP Metrics | GPU utilization, memory, power, etc. |

---

## Integration Layer

The integration layer processes signals before export:

### Limits

Configurable signal limits prevent overload:

- **Max samples per trace** — truncate very large traces
- **Max log record size** — drop oversized log records
- **Max metric data points** — batch size limits

### Transforms

Signal transforms modify signal content before export:

- **PII Redaction** — `transform/pii_redaction.go` — redacts emails, IPs, credit cards from log bodies and span attributes
- **Attribute filtering** — include/exclude specific attributes
- **Resource enrichment** — add cloud, K8s, process metadata

### Signal Metadata

All signals are enriched with `telegen.*` metadata attributes (configurable via `exports.metadata_fields`):

| Field | Config Key | Description |
|-------|-----------|-------------|
| `telegen.signal.category` | `enable_category` | Top-level category (e.g., "Database Traces") |
| `telegen.signal.subcategory` | `enable_subcategory` | Sub-category (e.g., "PostgreSQL") |
| `telegen.source.module` | `enable_source_module` | Go source module path |
| `telegen.bpf.component` | `enable_bpf_component` | eBPF component file path |
| `telegen.signal.description` | `enable_description` | Human-readable description (verbose) |
| `telegen.collector.type` | `enable_collector_type` | Collector type (ebpf, jfr, snmp, api, procfs, nvml) |

---

## Persistent WAL Queues

The unified pipeline uses per-signal-type persistent queues (Write-Ahead Log) for reliability:

### Queue Structure

| Signal Type | Queue | Replay Worker |
|------------|-------|---------------|
| Traces | `queue.PersistentQueue` (subdirectory `traces/`) | `traceQueueWorker` |
| Logs | `queue.PersistentQueue` (subdirectory `logs/`) | `logQueueWorker` |
| Metrics | `queue.PersistentQueue` (subdirectory `metrics/`) | `metricQueueWorker` |

### Queue Operations

- **Push** — Enqueue signal data with size estimation
- **Pop** — Replay queued data on startup or after connection failure
- **Drain** — Continuous drain workers for each signal type
- **Back-pressure** — When queue is full, block signal ingestion (configurable)

### Legacy Remote-Write Path

For prompb producers not yet ported to pmetric:

- `queue.Ring[*prompb.WriteRequest]` + `remoteWriteWorker()`
- `EnqueueMetrics(wr)` injects AWS labels before queueing
- Preserved for backward compatibility with Prometheus Remote Write endpoints

---

## Multi-Endpoint Exporter

The multi-endpoint exporter supports **failover** and **fanout** export strategies with circuit-breaker semantics.

### Export Modes

| Mode | Description |
|------|-------------|
| `failover` | Try first endpoint; on failure, try next (default) |
| `fanout` | Send to all endpoints simultaneously |

### Circuit Breaker

Each endpoint has an independent circuit breaker:

- **Closed** — Normal operation, all requests sent
- **Open** — Requests fail fast (after threshold failures)
- **Half-Open** — Probe with single request to test recovery

Circuit breaker configuration:

```yaml
exports:
  otlp:
    multi_endpoint:
      circuit_breaker:
        enabled: true
        failure_threshold: 5      # Failures before open
        success_threshold: 2      # Successes to close
        timeout: "30s"            # Open → half-open wait
```

### Shared OTLP Clients

The unified pipeline initializes shared OTLP clients at startup:

- **gRPC-primary** — `GetMetricsExporter()`, `GetTracesExporter()`
- **HTTP fallback** — When the endpoint is a URL (not host:port), HTTP exporter is used automatically
- **Logger Provider** — `GetLogsLoggerProvider()` for OTLP logs

Shared clients are exposed via `initSharedOTLPClients` and used by all signal adapters.

---

## OBI Span Bridge

Telegen integrates with the upstream `go.opentelemetry.io/obi` project for Go application tracing:

- `forwardOBISpanBatch` ingests upstream OBI span batches
- Converts through `tracesgen.GroupSpans` / `GenerateTracesWithAttributes`
- Routes into V3 via `SendTraces`
- Preserves `service.name` and `service.namespace` via explicit field mapping (not JSON round-trip)

---

## Runtime Sources

The unified pipeline starts runtime sources based on configuration:

| Source | Config | Description |
|--------|--------|-------------|
| **AWS Metadata** | `cloud.aws.enabled` | IMDSv2 enrichment for traces, logs, metrics |
| **Node Exporter** | `node_exporter.enabled` | OTLP streaming of node_exporter-compatible metrics |
| **Host Metrics** | Always (agent mode) | procfs-based host metrics |
| **File Log Tailer** | `pipelines.logs.filelog.include` | Glob-based log file tailing |
| **JFR Pipeline** | `pipelines.jfr.enabled` | JFR file watching and conversion |
| **eBPF Pipeline** | `profiling.enabled` | eBPF profilers (CPU, off-CPU, memory, mutex) |
| **K8s Metrics** | `kube_metrics.enabled` | kube-state-metrics + cadvisor streaming |
| **K8s Events** | `kube_metrics.logs_streaming.enabled` | K8s events → OTLP logs |

---

## Multi-Worker Export

Configurable `worker_count` goroutines per signal type:

```yaml
exports:
  otlp:
    worker_count:
      traces: 4
      logs: 2
      metrics: 2
```

Batch channels with back-pressure to persistent queues when full.

---

## Configuration

### Minimal (Zero-Config)

```yaml
otlp:
  endpoint: "otel-collector:4317"
```

### Full Pipeline Configuration

```yaml
exports:
  include_signal_metadata: true
  metadata_fields:
    enable_category: true
    enable_subcategory: true
    enable_source_module: true
    enable_bpf_component: true
    enable_description: false
    enable_collector_type: true

  remoteWrite:
    mode: "active"
    endpoints:
      - url: "http://otel-collector:19291/api/v1/push"
        compression: "snappy"

  otlp:
    send_mode: "failover"
    grpc:
      enabled: true
      endpoint: "otel-collector:4317"
      insecure: true
    http:
      enabled: false
      endpoint: "otel-collector:4318"

queues:
  traces:  { mem_limit: "256Mi", max_age: "6h" }
  logs:    { mem_limit: "256Mi", max_age: "24h" }
  metrics: { mem_limit: "128Mi", max_age: "5m" }

backoff:
  initial: "500ms"
  max: "30s"
  multiplier: 2.0
  jitter: 0.2
```

---

## Migration from Legacy Pipeline

The legacy pipeline (`internal/pipeline/pipeline.go`) is retired. If you are upgrading from a version that used the legacy pipeline:

1. Remove any `pipeline.legacy` configuration blocks
2. Ensure `exports.otlp` is configured (the unified pipeline uses shared OTLP clients)
3. Update signal metadata configuration to use `exports.metadata_fields` (new location)
4. Verify `queues` configuration uses the new signal-type keys (`traces`, `logs`, `metrics`)

The unified pipeline is **backward compatible** with all signal types — no signal data format changes are required.
