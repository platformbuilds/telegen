# Performance Tuning

Optimize Telegen for your environment and workload.

## Resource Guidelines

### Default Resource Requirements

| Component | CPU | Memory |
|-----------|-----|--------|
| **Agent (minimal)** | 0.1 cores | 128MB |
| **Agent (full features)** | 0.5 cores | 512MB |
| **Agent (high volume)** | 1.0 cores | 1GB |
| **Collector (SNMP)** | 0.2 cores | 256MB |
| **Collector (storage)** | 0.3 cores | 384MB |

### Kubernetes Resources

```yaml
resources:
  requests:
    cpu: "100m"
    memory: "256Mi"
  limits:
    cpu: "1000m"
    memory: "1Gi"
```

---

## Ring Buffer Tuning

The ring buffer is the primary channel for eBPF events.

### Sizing

| Buffer Size | Use Case | Event Capacity |
|-------------|----------|----------------|
| 4MB | Low traffic, testing | ~40K events |
| 16MB | Default, balanced | ~160K events |
| 64MB | High traffic | ~640K events |
| 256MB | Very high volume | ~2.5M events |

### Configuration

```yaml
agent:
  ebpf:
    ringbuf_size: 16777216  # 16MB (default)
```

### Signs You Need Larger Buffer

```promql
# High loss rate
rate(telegen_ebpf_ringbuf_lost_total[5m]) > 100
```

If events are being lost, increase buffer size:

```yaml
agent:
  ebpf:
    ringbuf_size: 67108864  # 64MB
```

---

## CPU Optimization

### Reduce Collection Overhead

1. **Limit traced ports**
   ```yaml
   agent:
     ebpf:
       network:
         include_ports:
           - 80
           - 443
           - 8080
         exclude_ports:
           - 22
           - 2379
   ```

2. **Reduce syscall tracing**
   ```yaml
   agent:
     ebpf:
       syscalls:
         enabled: false  # Disable if not needed
   ```

3. **Limit profiling frequency**
   ```yaml
   agent:
     profiling:
       sample_rate: 49  # Lower than default 99 Hz
   ```

### Parallel Processing

```yaml
agent:
  processing:
    workers: 4  # Match available CPU cores
```

---

## Memory Optimization

### Queue Limits

```yaml
queues:
  traces:
    mem_limit: "128Mi"
    max_age: "1h"
    batch_size: 256
  
  metrics:
    mem_limit: "64Mi"
    max_age: "5m"
    batch_size: 500
  
  logs:
    mem_limit: "128Mi"
    max_age: "6h"
    batch_size: 500
```

### Reduce Cardinality

High cardinality labels increase memory:

```yaml
agent:
  kubernetes:
    # Only essential labels
    label_allowlist:
      - "app"
      - "version"
    # NOT: "*"
```

### Limit Active Connections Tracked

```yaml
agent:
  ebpf:
    network:
      # Limit tracked connections
      max_connections: 50000  # Default: 100000
```

---

## Network/Export Optimization

### Compression

```yaml
otlp:
  compression: gzip  # Reduce bandwidth
```

### Batching

```yaml
queues:
  traces:
    batch_size: 512     # Larger batches = fewer requests
    flush_interval: 5s  # Don't wait too long
```

### Connection Pooling

```yaml
otlp:
  max_connections: 10  # Connection pool size
  idle_timeout: 60s
```

---

## Sampling

### Head-Based Sampling

Sample at collection time:

```yaml
otlp:
  traces:
    sample_rate: 0.1  # 10% of traces
```

### Tail-Based Sampling

For more intelligent sampling, configure your OTel Collector:

```yaml
# OTel Collector config
processors:
  tail_sampling:
    policies:
      - name: errors
        type: status_code
        status_code: { status_codes: [ERROR] }
      - name: slow
        type: latency
        latency: { threshold_ms: 1000 }
      - name: sample
        type: probabilistic
        probabilistic: { sampling_percentage: 10 }
```

---

## Per-Feature Tuning

### Profiling

```yaml
agent:
  profiling:
    # Lower sample rate for less overhead
    sample_rate: 49  # Hz
    
    # Longer upload interval
    upload_interval: 120s
    
    # Disable unused profile types
    mutex: false
    block: false
    goroutine: false
```

### Security Monitoring

```yaml
agent:
  security:
    # Focus on critical syscalls only
    syscall_audit:
      syscalls:
        - execve
        - setuid
        - ptrace
      # NOT all syscalls
    
    # Limit file paths
    file_integrity:
      paths:
        - /etc/passwd
        - /etc/shadow
      # NOT: /var/**
```

### Network Monitoring

```yaml
agent:
  network:
    # Use sampling for high-volume
    tcp:
      sample_rate: 10  # 1 in 10 connections
    
    # XDP sampling
    xdp:
      sample_rate: 1000  # 0.1% of packets
```

---

## High-Volume Environments

### Recommended Configuration

For environments with >10K requests/second:

```yaml
telegen:
  log_level: warn  # Reduce logging

agent:
  ebpf:
    ringbuf_size: 134217728  # 128MB
    perf_buffer_size: 32768  # 32KB per CPU
    
    network:
      exclude_paths:
        - "/health*"
        - "/ready*"
        - "/metrics"
      exclude_ports:
        - 22
        - 2379
        - 2380
        - 10250
  
  resources:
    cpu_limit: 2.0
    memory_limit: "2Gi"
    rate_limit:
      spans_per_second: 100000
      metrics_per_second: 200000

otlp:
  compression: gzip
  
queues:
  traces:
    mem_limit: "512Mi"
    batch_size: 1024
```

---

## Low-Resource Environments

### Minimal Configuration

For resource-constrained environments:

```yaml
telegen:
  log_level: error

agent:
  ebpf:
    ringbuf_size: 4194304  # 4MB
    
    network:
      enabled: true
      http: true
      grpc: false
      dns: false
    
    syscalls:
      enabled: false
  
  profiling:
    enabled: false
  
  security:
    enabled: false

queues:
  traces:
    mem_limit: "64Mi"
    batch_size: 128
```

### Kubernetes Resources

```yaml
resources:
  requests:
    cpu: "50m"
    memory: "128Mi"
  limits:
    cpu: "200m"
    memory: "256Mi"
```

---

## Monitoring Performance

### Key Metrics to Watch

```promql
# CPU usage
rate(telegen_process_cpu_seconds_total[5m])

# Memory usage
telegen_process_resident_memory_bytes

# Event loss rate
rate(telegen_ebpf_ringbuf_lost_total[5m]) / rate(telegen_ebpf_ringbuf_events_total[5m])

# Export latency
histogram_quantile(0.99, rate(telegen_export_latency_seconds_bucket[5m]))

# Queue depth
telegen_export_queue_size
```

### Performance Alerts

```yaml
groups:
  - name: telegen-performance
    rules:
      - alert: TelegenHighCPU
        expr: rate(telegen_process_cpu_seconds_total[5m]) > 0.8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Telegen using high CPU"
      
      - alert: TelegenHighMemory
        expr: telegen_process_resident_memory_bytes > 1.5e9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Telegen memory above 1.5GB"
      
      - alert: TelegenExportSlow
        expr: histogram_quantile(0.99, rate(telegen_export_latency_seconds_bucket[5m])) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Telegen export P99 latency high"
```

---

## Benchmarking

### Test Configuration

Before deploying changes, benchmark:

```bash
# Generate test load
hey -n 10000 -c 100 http://your-app:8080/api/test

# Monitor Telegen metrics
watch -n 1 'curl -s http://localhost:19090/metrics | grep -E "cpu|memory|lost"'
```

### Compare Before/After

1. Baseline current configuration
2. Apply changes
3. Run same load test
4. Compare metrics

---

## Best Practices Summary

1. **Start conservative** - Begin with defaults, tune based on actual needs
2. **Monitor loss rates** - If losing events, increase buffers
3. **Use sampling** - For high-volume, sample rather than drop
4. **Filter noise** - Exclude health checks, internal traffic
5. **Batch efficiently** - Larger batches reduce export overhead
6. **Set limits** - Protect against runaway memory usage
7. **Test changes** - Benchmark before and after tuning

---

## Next Steps

- {doc}`monitoring` - Set up performance monitoring
- {doc}`troubleshooting` - Diagnose performance issues
- {doc}`../configuration/full-reference` - All configuration options
