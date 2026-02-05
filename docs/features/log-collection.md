# Log Collection & Trace Enrichment

Telegen provides native log collection with automatic trace correlation, delivering 100% OTLP-compliant logs.

## Overview

Telegen's log pipeline offers:

- **Native container runtime parsers** - Docker JSON, containerd, CRI-O
- **Automatic K8s metadata extraction** - Pod, namespace, container from log paths
- **eBPF-based trace injection** - Link logs to distributed traces
- **Application-aware parsing** - Spring Boot, Log4j, Logback patterns
- **Non-Kubernetes support** - File path-based correlation for VMs

No sidecar containers. No separate log shippers. One unified agent.

:::{tip}
For full-stack observability, enable both `log_enricher` and `filelog` to correlate application logs with distributed traces automatically.
:::

---

## How It Works

```{mermaid}
flowchart TB
    subgraph Sources["Log Sources"]
        A["Container Logs\n/var/log/containers/"]
        B["Application Logs\n/var/log/myapp/"]
        C["System Logs\n/var/log/syslog"]
    end
    
    subgraph Telegen["Telegen Agent"]
        subgraph eBPF["eBPF Layer"]
            E["Log Enricher\n(write syscall intercept)"]
            T["Trace Context Cache"]
        end
        
        subgraph Pipeline["Log Pipeline"]
            F["Filelog Reader"]
            P["Runtime Parsers"]
            TE["Trace Enricher"]
            K["K8s Metadata"]
        end
    end
    
    A --> F
    B --> F
    C --> F
    F --> P
    P --> TE
    E --> T
    T --> TE
    TE --> K
    K --> O["OTLP Exporter"]
    O --> C1["OTel Collector\nor Backend"]
```

### The Correlation Bridge

Telegen uses a unique approach to correlate plain-text logs with distributed traces:

1. **eBPF captures trace context** - When an application writes a log line, the `log_enricher` intercepts the `write()` syscall and captures the current trace context
2. **Time-windowed cache** - Trace context is stored in a correlation cache keyed by container ID (K8s) or file path (non-K8s) + timestamp
3. **Filelog enrichment** - When the log pipeline reads the log file, it queries the cache using timestamp matching (±100ms tolerance)
4. **OTLP emission** - The enriched log record includes `trace_id`, `span_id`, and `trace_flags`

This approach works for **any log format**, including plain-text logs without native trace context.

---

## Configuration

### Basic Log Collection

```yaml
logs:
  enabled: true
  
  filelog:
    enabled: true
    # Container logs (Kubernetes)
    include:
      - /var/log/containers/*.log
      - /var/log/pods/*/*/*/*.log
    # Application logs (non-K8s)
    include:
      - /var/log/myapp/*.log
    
    # Automatic runtime detection
    auto_detect_runtime: true
    
    # K8s metadata from log paths
    k8s_metadata_from_path: true
```

### Full Configuration with Trace Enrichment

```yaml
logs:
  enabled: true
  
  # eBPF log enricher - captures trace context at write time
  log_enricher:
    enabled: true
    # Target files to track (supports glob patterns)
    target_paths:
      - /var/log/containers/*.log
      - /var/log/pods/*/*/*/*.log
      - /var/log/myapp/*.log
    # JSON injection (only works for JSON logs)
    json_injection: true
    # Record trace context for filelog correlation (works for all formats)
    filelog_correlation: true
  
  filelog:
    enabled: true
    include:
      - /var/log/containers/*.log
      - /var/log/pods/*/*/*/*.log
      - /var/log/myapp/*.log
    
    auto_detect_runtime: true
    k8s_metadata_from_path: true
    
    # Trace context enrichment from eBPF correlation
    trace_context_enrichment:
      enabled: true
      # Time window for matching log timestamps to trace context
      tolerance: 100ms
    
    # Application-specific parsers
    application_parsers:
      enabled: true
      patterns:
        - spring_boot
        - log4j
        - logback
        - python_logging
```

---

## Log Enricher (eBPF)

The `log_enricher` uses eBPF to capture trace context at the moment of log emission.

### How It Works

```{mermaid}
sequenceDiagram
    participant App as Application
    participant Kernel as Linux Kernel
    participant eBPF as Log Enricher
    participant Cache as Correlation Cache
    participant Filelog as Filelog Reader
    
    App->>Kernel: write(fd, "User login failed", 17)
    Kernel->>eBPF: kprobe:vfs_write
    eBPF->>eBPF: Extract trace context from goroutine/thread
    eBPF->>Cache: Store(key=cid:abc123, ts=1706745600, trace=...)
    Kernel->>App: bytes written
    
    Note over Filelog: 50ms later...
    
    Filelog->>Filelog: Read line from file
    Filelog->>Cache: Lookup(key=cid:abc123, ts=1706745600, tolerance=100ms)
    Cache->>Filelog: TraceContext{traceID, spanID, flags}
    Filelog->>Filelog: Enrich OTLP record
```

### Supported Log Formats

| Format | JSON Injection | Filelog Correlation |
|--------|---------------|---------------------|
| JSON (structured) | ✅ Direct injection | ✅ Via cache |
| Plain text | ❌ Not possible | ✅ Via cache |
| Log4j pattern | ❌ Not possible | ✅ Via cache |
| Spring Boot default | ❌ Not possible | ✅ Via cache |

### JSON Injection Example

When `json_injection: true`, the log enricher directly modifies JSON logs:

**Before:**
```json
{"timestamp":"2024-01-31T10:30:00Z","level":"INFO","message":"User login successful","user_id":"12345"}
```

**After:**
```json
{"timestamp":"2024-01-31T10:30:00Z","level":"INFO","message":"User login successful","user_id":"12345","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7","trace_flags":"01"}
```

---

## Container Runtime Parsers

Telegen includes native parsers for all major container runtimes.

### Docker JSON

```json
{"log":"2024-01-31T10:30:00.000Z INFO  Starting application\n","stream":"stdout","time":"2024-01-31T10:30:00.123456789Z"}
```

Extracted fields:
- `body`: `2024-01-31T10:30:00.000Z INFO  Starting application`
- `timestamp`: `2024-01-31T10:30:00.123456789Z`
- `stream`: `stdout`

### containerd / CRI-O

```
2024-01-31T10:30:00.123456789Z stdout F 2024-01-31T10:30:00.000Z INFO  Starting application
```

Extracted fields:
- `body`: `2024-01-31T10:30:00.000Z INFO  Starting application`
- `timestamp`: `2024-01-31T10:30:00.123456789Z`
- `stream`: `stdout`
- `partial`: `false` (F = full line)

---

## Kubernetes Metadata

Telegen extracts Kubernetes metadata from log file paths.

### Path Format

```
/var/log/containers/nginx-7b5f8d4c9b-x2kpq_default_nginx-abc123def456.log
                    ↓           ↓       ↓       ↓
                    pod_name    pod_uid namespace container_name
```

### Extracted Resource Attributes

```yaml
resource:
  attributes:
    k8s.pod.name: nginx-7b5f8d4c9b-x2kpq
    k8s.pod.uid: 7b5f8d4c9b
    k8s.namespace.name: default
    k8s.container.name: nginx
    container.id: abc123def456
    k8s.node.name: worker-01  # From agent metadata
```

---

## Application Parsers

Telegen includes parsers for common application log formats.

### Spring Boot

```
2024-01-31 10:30:00.123  INFO 1234 --- [main] c.e.MyApplication : Application started
```

Extracted:
```yaml
timestamp: "2024-01-31T10:30:00.123Z"
severity_number: 9  # INFO
severity_text: "INFO"
attributes:
  process.pid: 1234
  thread.name: "main"
  code.namespace: "c.e.MyApplication"
body: "Application started"
```

### Log4j / Logback

```
2024-01-31 10:30:00,123 [main] INFO  com.example.Service - Processing request id=12345
```

Extracted:
```yaml
timestamp: "2024-01-31T10:30:00.123Z"
severity_number: 9
severity_text: "INFO"
attributes:
  thread.name: "main"
  code.namespace: "com.example.Service"
body: "Processing request id=12345"
```

---

## Non-Kubernetes Environments

Telegen supports trace correlation in non-Kubernetes environments using file path-based correlation.

### How It Works

In non-K8s environments (VMs, bare metal):

1. **eBPF identifies log file** - Uses the file path as correlation key (`path:/var/log/myapp/application.log`)
2. **Same key at read time** - Filelog uses the same file path for lookup
3. **Correlation matches** - Trace context retrieved and attached

### Configuration

```yaml
logs:
  log_enricher:
    enabled: true
    target_paths:
      - /var/log/myapp/*.log
      - /opt/app/logs/*.log
    filelog_correlation: true
  
  filelog:
    enabled: true
    include:
      - /var/log/myapp/*.log
      - /opt/app/logs/*.log
    
    trace_context_enrichment:
      enabled: true
      tolerance: 100ms
```

### Correlation Keys

| Environment | Key Format | Example |
|-------------|------------|---------|
| Kubernetes | `cid:<container_id>` | `cid:abc123def456` |
| Non-K8s | `path:<file_path>` | `path:/var/log/myapp/app.log` |

---

## OTLP Compliance

All logs are emitted as fully OTLP-compliant log records.

### Log Record Structure

```yaml
# Full OTLP LogRecord
resource:
  attributes:
    service.name: "my-service"
    k8s.pod.name: "my-service-7b5f8d4c9b-x2kpq"
    k8s.namespace.name: "production"
    k8s.node.name: "worker-01"
    host.name: "worker-01"

scope:
  name: "telegen.logs"
  version: "2.10.1"

log_record:
  time_unix_nano: 1706695800123456789
  observed_time_unix_nano: 1706695800200000000
  severity_number: 9
  severity_text: "INFO"
  body:
    string_value: "User login successful"
  attributes:
    - key: "user_id"
      value: { string_value: "12345" }
    - key: "log.file.path"
      value: { string_value: "/var/log/containers/my-service_default_app-abc123.log" }
  trace_id: "4bf92f3577b34da6a3ce929d0e0e4736"
  span_id: "00f067aa0ba902b7"
  flags: 1
```

### Semantic Conventions

Telegen follows OpenTelemetry semantic conventions:

| Attribute | Description |
|-----------|-------------|
| `log.file.path` | Source file path |
| `log.iostream` | `stdout` or `stderr` |
| `container.runtime` | `docker`, `containerd`, `cri-o` |
| `exception.type` | Exception class name |
| `exception.message` | Exception message |
| `exception.stacktrace` | Full stack trace |

---

## Troubleshooting

### Trace Context Not Appearing

1. **Check log_enricher is enabled**:
   ```bash
   telegen config validate | grep log_enricher
   ```

2. **Verify eBPF programs loaded**:
   ```bash
   telegen status | grep -A5 "Log Enricher"
   ```

3. **Check tolerance window**:
   - Default 100ms should work for most cases
   - Increase if logs have high latency to disk

### Missing Kubernetes Metadata

1. **Verify log path format**:
   ```bash
   ls -la /var/log/containers/
   ```

2. **Check symlink resolution**:
   - `/var/log/containers/*.log` should symlink to `/var/log/pods/`

### Performance Tuning

```yaml
logs:
  filelog:
    # Batch size for OTLP export
    batch_size: 1000
    
    # Flush interval
    flush_interval: 1s
    
    # Max concurrent files
    max_concurrent_files: 100
    
  log_enricher:
    # Correlation cache settings
    cache_ttl: 30s
    cache_max_entries: 100000
    cache_bucket_size: 100ms
```

---

## Metrics

Telegen exposes self-monitoring metrics for the log pipeline:

```prometheus
# Log lines processed
telegen_logs_records_total{source="filelog", k8s_namespace="default"} 1234567

# Trace enrichment success rate
telegen_logs_trace_enriched_total{method="cache"} 98765
telegen_logs_trace_enriched_total{method="json"} 45678

# Cache hit rate
telegen_correlation_cache_hits_total 98765
telegen_correlation_cache_misses_total 1234

# Parse errors
telegen_logs_parse_errors_total{parser="docker_json"} 12
```
