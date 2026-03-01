# Minimal Configuration

Get started with the absolute minimum configuration.

## Zero-Config Approach

Telegen is designed to work out of the box. Deploy with just an OTLP endpoint and Telegen handles everything else:

```yaml
otlp:
  endpoint: "otel-collector:4317"
```

That's it. Telegen will:

- ✅ Auto-detect cloud provider (AWS, GCP, Azure, etc.)
- ✅ Auto-detect Kubernetes metadata
- ✅ Auto-discover running processes and runtimes
- ✅ Enable distributed tracing
- ✅ Enable host metrics collection
- ✅ Enable log collection
- ✅ Correlate all signals automatically

---

## Environment Variable Only

You can run Telegen with zero config files using environment variables:

```bash
# Docker
docker run -d --name telegen \
  --privileged --pid=host --network=host \
  -v /sys:/sys:ro \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e TELEGEN_OTLP_ENDPOINT=otel-collector:4317 \
  ghcr.io/mirastacklabs-ai/telegen:latest
```

```bash
# Linux
TELEGEN_OTLP_ENDPOINT=otel-collector:4317 telegen
```

---

## Minimal Config File Examples

### Basic Agent Mode

```yaml
# /etc/telegen/config.yaml
otlp:
  endpoint: "otel-collector:4317"
```

### With Authentication

```yaml
otlp:
  endpoint: "otel-collector:4317"
  headers:
    Authorization: "Bearer ${OTEL_TOKEN}"
```

### With TLS

```yaml
otlp:
  endpoint: "otel-collector:4317"
  tls:
    enabled: true
    ca_file: "/etc/ssl/certs/ca.crt"
```

### Collector Mode (Remote Monitoring)

```yaml
telegen:
  mode: collector

otlp:
  endpoint: "otel-collector:4317"

collector:
  snmp:
    enabled: true
    targets:
      - address: "10.0.1.1:161"
        community: "public"
```

---

## What Gets Enabled by Default

| Feature | Default | Notes |
|---------|---------|-------|
| **Distributed Tracing** | ✅ Enabled | HTTP, gRPC, database protocols |
| **Host Metrics** | ✅ Enabled | CPU, memory, disk, network |
| **Process Discovery** | ✅ Enabled | Runtime detection |
| **Cloud Detection** | ✅ Enabled | AWS, GCP, Azure, etc. |
| **Kubernetes Enrichment** | ✅ Enabled | When running in K8s |
| **Continuous Profiling** | ❌ Disabled | Enable with `agent.profiling.enabled: true` |
| **Security Monitoring** | ❌ Disabled | Enable with `agent.security.enabled: true` |
| **SNMP Collection** | ❌ Disabled | Collector mode only |

---

## Targeted Instrumentation

By default, Telegen instruments all processes. To target specific services, use port-based discovery:

### Instrument Specific Ports

```yaml
otlp:
  endpoint: "otel-collector:4317"

discovery:
  instrument:
    - open_ports: "8080-8089"
    - open_ports: "3000,5000"
```

### Kubernetes-Aware Targeting

```yaml
otlp:
  endpoint: "otel-collector:4317"

discovery:
  instrument:
    - k8s_namespace: "production"
      open_ports: "8080"
```

---

## Enabling Additional Features

### Enable Profiling

```yaml
otlp:
  endpoint: "otel-collector:4317"

agent:
  profiling:
    enabled: true
```

### Enable Security Monitoring

```yaml
otlp:
  endpoint: "otel-collector:4317"

agent:
  security:
    enabled: true
```

### Enable All Features

```yaml
otlp:
  endpoint: "otel-collector:4317"

agent:
  profiling:
    enabled: true
    cpu: true
    memory: true
    off_cpu: true
  
  security:
    enabled: true
    syscall_audit: true
    file_integrity: true
  
  network:
    enabled: true
    dns: true
    tcp_metrics: true
```

---

## Next Steps

- {doc}`full-reference` - Complete configuration reference
- {doc}`agent-mode` - Agent mode options
- {doc}`collector-mode` - Collector mode options
