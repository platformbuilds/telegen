# Monitoring Telegen

How to monitor Telegen itself for health and performance.

## Self-Telemetry

Telegen exposes metrics about its own operation via a Prometheus endpoint.

### Metrics Endpoint

By default, Telegen exposes metrics at `:19090/metrics`:

```bash
curl http://localhost:19090/metrics
```

### Configuration

```yaml
self_telemetry:
  enabled: true
  listen: ":19090"
  path: "/metrics"
  prometheus_namespace: "telegen"
```

---

## Key Metrics

### Collection Metrics

| Metric | Description |
|--------|-------------|
| `telegen_spans_collected_total` | Total spans collected |
| `telegen_spans_exported_total` | Spans exported successfully |
| `telegen_spans_dropped_total` | Spans dropped (queue full, errors) |
| `telegen_metrics_collected_total` | Metrics collected |
| `telegen_metrics_exported_total` | Metrics exported |
| `telegen_logs_collected_total` | Logs collected |
| `telegen_logs_exported_total` | Logs exported |
| `telegen_profiles_collected_total` | Profiles collected |

### eBPF Metrics

| Metric | Description |
|--------|-------------|
| `telegen_ebpf_programs_loaded` | Number of eBPF programs |
| `telegen_ebpf_map_entries` | Entries in eBPF maps |
| `telegen_ebpf_ringbuf_events_total` | Ring buffer events received |
| `telegen_ebpf_ringbuf_lost_total` | Ring buffer events lost |
| `telegen_ebpf_perf_events_total` | Perf buffer events |
| `telegen_ebpf_perf_lost_total` | Perf buffer events lost |

### Export Metrics

| Metric | Description |
|--------|-------------|
| `telegen_export_requests_total` | Export requests to backend |
| `telegen_export_errors_total` | Export errors |
| `telegen_export_latency_seconds` | Export latency histogram |
| `telegen_export_batch_size` | Batch sizes |
| `telegen_export_queue_size` | Current queue depth |

### Resource Metrics

| Metric | Description |
|--------|-------------|
| `telegen_process_cpu_seconds_total` | CPU time used |
| `telegen_process_resident_memory_bytes` | Memory usage |
| `telegen_process_open_fds` | Open file descriptors |
| `telegen_go_goroutines` | Number of goroutines |

---

## Health Checks

### Liveness Probe

```bash
curl http://localhost:19090/healthz
```

Response:
```json
{
  "status": "ok"
}
```

### Readiness Probe

```bash
curl http://localhost:19090/ready
```

Response:
```json
{
  "status": "ready",
  "checks": {
    "ebpf": "ok",
    "otlp": "ok",
    "discovery": "ok"
  }
}
```

### Kubernetes Probes

```yaml
spec:
  containers:
    - name: telegen
      livenessProbe:
        httpGet:
          path: /healthz
          port: 19090
        initialDelaySeconds: 10
        periodSeconds: 10
      readinessProbe:
        httpGet:
          path: /ready
          port: 19090
        initialDelaySeconds: 5
        periodSeconds: 5
```

---

## Prometheus Scraping

### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'telegen'
    static_configs:
      - targets: ['localhost:19090']
```

### Kubernetes ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: telegen
spec:
  selector:
    matchLabels:
      app: telegen
  endpoints:
    - port: metrics
      interval: 30s
```

---

## Dashboard

### Key Panels

**Collection Overview:**
```promql
# Spans per second
rate(telegen_spans_collected_total[5m])

# Drop rate
rate(telegen_spans_dropped_total[5m]) / rate(telegen_spans_collected_total[5m])
```

**eBPF Health:**
```promql
# Ring buffer loss rate
rate(telegen_ebpf_ringbuf_lost_total[5m]) / rate(telegen_ebpf_ringbuf_events_total[5m])

# Programs loaded
telegen_ebpf_programs_loaded
```

**Export Health:**
```promql
# Export error rate
rate(telegen_export_errors_total[5m]) / rate(telegen_export_requests_total[5m])

# Export latency P99
histogram_quantile(0.99, rate(telegen_export_latency_seconds_bucket[5m]))

# Queue backlog
telegen_export_queue_size
```

**Resource Usage:**
```promql
# CPU usage
rate(telegen_process_cpu_seconds_total[5m])

# Memory
telegen_process_resident_memory_bytes

# Goroutines
telegen_go_goroutines
```

---

## Alerting

### Recommended Alerts

```yaml
groups:
  - name: telegen
    rules:
      # High drop rate
      - alert: TelegenHighDropRate
        expr: rate(telegen_spans_dropped_total[5m]) / rate(telegen_spans_collected_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Telegen dropping spans ({{ $value | humanizePercentage }})"
      
      # eBPF event loss
      - alert: TelegenEbpfEventLoss
        expr: rate(telegen_ebpf_ringbuf_lost_total[5m]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Telegen losing eBPF events ({{ $value }}/s)"
      
      # Export errors
      - alert: TelegenExportErrors
        expr: rate(telegen_export_errors_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Telegen export errors detected"
      
      # High memory usage
      - alert: TelegenHighMemory
        expr: telegen_process_resident_memory_bytes > 1e9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Telegen using {{ $value | humanizeBytes }} memory"
      
      # Queue backup
      - alert: TelegenQueueBackup
        expr: telegen_export_queue_size > 10000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Telegen export queue backing up ({{ $value }} items)"
```

---

## Logging

### Log Levels

```yaml
telegen:
  log_level: info  # debug, info, warn, error
  log_format: json  # json or text
```

### Log Output

```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "level": "info",
  "msg": "Exported batch",
  "spans": 512,
  "latency_ms": 45,
  "endpoint": "otel-collector:4317"
}
```

### Debug Logging

Enable for troubleshooting:

```yaml
telegen:
  log_level: debug
```

Or via environment:

```bash
TELEGEN_LOG_LEVEL=debug telegen
```

---

## Status Commands

### Check Status

```bash
# Via API
curl http://localhost:19090/status

# Response
{
  "version": "3.0.0",
  "uptime": "24h15m30s",
  "mode": "agent",
  "ebpf": {
    "programs_loaded": 15,
    "maps_created": 25
  },
  "export": {
    "endpoint": "otel-collector:4317",
    "connected": true,
    "last_export": "2024-01-15T10:30:00Z"
  }
}
```

### List eBPF Programs

```bash
# Using bpftool
bpftool prog list | grep telegen

# Expected output
123: tracepoint  name trace_http  tag abc123  gpl
124: kprobe  name trace_tcp  tag def456  gpl
...
```

---

## Tracing Telegen

Enable self-tracing for deep debugging:

```yaml
self_telemetry:
  tracing:
    enabled: true
    sample_rate: 0.01  # 1% of internal operations
```

This creates traces for Telegen's internal operations, useful for debugging performance issues.

---

## Next Steps

- {doc}`troubleshooting` - Common issues and solutions
- {doc}`performance-tuning` - Optimize resource usage
