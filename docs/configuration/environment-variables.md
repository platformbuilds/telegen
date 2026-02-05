# Environment Variables

Complete reference for Telegen environment variables.

## Overview

Environment variables provide the highest-priority configuration method. They override all config file settings and are ideal for:

- Container deployments
- Secrets management
- CI/CD pipelines
- Per-environment overrides

## Naming Convention

Environment variables follow this pattern:

```
TELEGEN_<SECTION>_<SUBSECTION>_<KEY>
```

Examples:
- `TELEGEN_OTLP_ENDPOINT` → `otlp.endpoint`
- `TELEGEN_AGENT_PROFILING_ENABLED` → `agent.profiling.enabled`

---

## Core Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_MODE` | `agent` | Operating mode: `agent` or `collector` |
| `TELEGEN_SERVICE_NAME` | `telegen` | Service name for telemetry |
| `TELEGEN_INSTANCE_ID` | hostname | Unique instance identifier |
| `TELEGEN_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `TELEGEN_LOG_FORMAT` | `json` | Log format: `json` or `text` |
| `TELEGEN_CONFIG_FILE` | `/etc/telegen/config.yaml` | Config file path |

---

## OTLP Export Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_OTLP_ENDPOINT` | - | **Required.** OTLP endpoint (e.g., `otel-collector:4317`) |
| `TELEGEN_OTLP_PROTOCOL` | `grpc` | Protocol: `grpc` or `http` |
| `TELEGEN_OTLP_COMPRESSION` | `gzip` | Compression: `gzip` or `none` |
| `TELEGEN_OTLP_TIMEOUT` | `10s` | Connection timeout |
| `TELEGEN_OTLP_INSECURE` | `false` | Skip TLS verification |
| `TELEGEN_OTLP_HEADERS` | - | Headers as `key=value,key2=value2` |

### TLS Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_OTLP_TLS_ENABLED` | `false` | Enable TLS |
| `TELEGEN_OTLP_TLS_CA_FILE` | - | CA certificate path |
| `TELEGEN_OTLP_TLS_CERT_FILE` | - | Client certificate path |
| `TELEGEN_OTLP_TLS_KEY_FILE` | - | Client key path |
| `TELEGEN_OTLP_TLS_INSECURE_SKIP_VERIFY` | `false` | Skip certificate verification |

### Per-Signal Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_OTLP_TRACES_ENABLED` | `true` | Enable trace export |
| `TELEGEN_OTLP_TRACES_ENDPOINT` | - | Override traces endpoint |
| `TELEGEN_OTLP_TRACES_SAMPLE_RATE` | `1.0` | Trace sampling rate (0.0-1.0) |
| `TELEGEN_OTLP_METRICS_ENABLED` | `true` | Enable metrics export |
| `TELEGEN_OTLP_METRICS_ENDPOINT` | - | Override metrics endpoint |
| `TELEGEN_OTLP_LOGS_ENABLED` | `true` | Enable logs export |
| `TELEGEN_OTLP_LOGS_ENDPOINT` | - | Override logs endpoint |
| `TELEGEN_OTLP_PROFILES_ENABLED` | `true` | Enable profiles export |
| `TELEGEN_OTLP_PROFILES_ENDPOINT` | - | Override profiles endpoint |

---

## Agent Variables

### eBPF Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_AGENT_EBPF_ENABLED` | `true` | Enable eBPF |
| `TELEGEN_AGENT_EBPF_RINGBUF_SIZE` | `16777216` | Ring buffer size (bytes) |
| `TELEGEN_AGENT_EBPF_PERF_BUFFER_SIZE` | `8192` | Per-CPU perf buffer size |

### Network Tracing

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_AGENT_EBPF_NETWORK_ENABLED` | `true` | Enable network tracing |
| `TELEGEN_AGENT_EBPF_NETWORK_HTTP` | `true` | Trace HTTP |
| `TELEGEN_AGENT_EBPF_NETWORK_GRPC` | `true` | Trace gRPC |
| `TELEGEN_AGENT_EBPF_NETWORK_DNS` | `true` | Trace DNS |
| `TELEGEN_AGENT_EBPF_NETWORK_TCP_METRICS` | `true` | Collect TCP metrics |

### Discovery

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_AGENT_DISCOVERY_ENABLED` | `true` | Enable auto-discovery |
| `TELEGEN_AGENT_DISCOVERY_INTERVAL` | `30s` | Discovery interval |
| `TELEGEN_AGENT_DISCOVERY_DETECT_CLOUD` | `true` | Detect cloud provider |
| `TELEGEN_AGENT_DISCOVERY_DETECT_KUBERNETES` | `true` | Detect Kubernetes |
| `TELEGEN_AGENT_DISCOVERY_DETECT_RUNTIMES` | `true` | Detect application runtimes |

### Profiling

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_AGENT_PROFILING_ENABLED` | `false` | Enable profiling |
| `TELEGEN_AGENT_PROFILING_SAMPLE_RATE` | `99` | Sample rate (Hz) |
| `TELEGEN_AGENT_PROFILING_CPU` | `true` | CPU profiling |
| `TELEGEN_AGENT_PROFILING_OFF_CPU` | `true` | Off-CPU profiling |
| `TELEGEN_AGENT_PROFILING_MEMORY` | `true` | Memory profiling |
| `TELEGEN_AGENT_PROFILING_DURATION` | `10s` | Profile duration |
| `TELEGEN_AGENT_PROFILING_UPLOAD_INTERVAL` | `60s` | Upload interval |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_AGENT_SECURITY_ENABLED` | `false` | Enable security monitoring |
| `TELEGEN_AGENT_SECURITY_SYSCALL_AUDIT_ENABLED` | `true` | Syscall auditing |
| `TELEGEN_AGENT_SECURITY_FILE_INTEGRITY_ENABLED` | `true` | File integrity monitoring |
| `TELEGEN_AGENT_SECURITY_CONTAINER_ESCAPE_ENABLED` | `true` | Container escape detection |

### GPU

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_AGENT_GPU_ENABLED` | `true` | Enable GPU monitoring |
| `TELEGEN_AGENT_GPU_NVIDIA` | `true` | NVIDIA GPU support |
| `TELEGEN_AGENT_GPU_POLL_INTERVAL` | `10s` | GPU polling interval |

---

## Collector Variables

### SNMP

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_COLLECTOR_SNMP_ENABLED` | `false` | Enable SNMP collection |
| `TELEGEN_COLLECTOR_SNMP_POLL_INTERVAL` | `60s` | Polling interval |
| `TELEGEN_COLLECTOR_SNMP_TIMEOUT` | `10s` | SNMP timeout |
| `TELEGEN_COLLECTOR_SNMP_RETRIES` | `3` | Retry count |

### SNMP Trap Receiver

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_COLLECTOR_SNMP_TRAP_RECEIVER_ENABLED` | `false` | Enable trap receiver |
| `TELEGEN_COLLECTOR_SNMP_TRAP_RECEIVER_LISTEN` | `:162` | Listen address |

---

## Cloud Variables

### AWS

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_CLOUD_AWS_ENABLED` | `true` | Enable AWS detection |
| `TELEGEN_CLOUD_AWS_TIMEOUT` | `200ms` | Metadata timeout |
| `TELEGEN_CLOUD_AWS_REFRESH_INTERVAL` | `15m` | Refresh interval |
| `TELEGEN_CLOUD_AWS_COLLECT_TAGS` | `false` | Collect EC2 tags |

### GCP

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_CLOUD_GCP_ENABLED` | `true` | Enable GCP detection |
| `TELEGEN_CLOUD_GCP_TIMEOUT` | `200ms` | Metadata timeout |
| `TELEGEN_CLOUD_GCP_REFRESH_INTERVAL` | `15m` | Refresh interval |

### Azure

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_CLOUD_AZURE_ENABLED` | `true` | Enable Azure detection |
| `TELEGEN_CLOUD_AZURE_TIMEOUT` | `200ms` | Metadata timeout |
| `TELEGEN_CLOUD_AZURE_REFRESH_INTERVAL` | `15m` | Refresh interval |

---

## Self-Telemetry Variables

The self-telemetry endpoint serves health probes (`/healthz`, `/readyz`) and Prometheus metrics (`/metrics`).

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_SELF_TELEMETRY_LISTEN` | `:19090` | HTTP listen address for health probes and metrics |
| `TELEGEN_SELF_TELEMETRY_PROMETHEUS_NAMESPACE` | `telegen` | Prometheus metrics namespace prefix |

---

## Queue Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_QUEUES_TRACES_MEM_LIMIT` | `256Mi` | Trace queue memory limit |
| `TELEGEN_QUEUES_TRACES_MAX_AGE` | `6h` | Max trace age |
| `TELEGEN_QUEUES_TRACES_BATCH_SIZE` | `512` | Trace batch size |
| `TELEGEN_QUEUES_METRICS_MEM_LIMIT` | `128Mi` | Metrics queue memory limit |
| `TELEGEN_QUEUES_METRICS_MAX_AGE` | `5m` | Max metrics age |
| `TELEGEN_QUEUES_METRICS_BATCH_SIZE` | `1000` | Metrics batch size |
| `TELEGEN_QUEUES_LOGS_MEM_LIMIT` | `256Mi` | Logs queue memory limit |
| `TELEGEN_QUEUES_LOGS_MAX_AGE` | `24h` | Max logs age |
| `TELEGEN_QUEUES_LOGS_BATCH_SIZE` | `1000` | Logs batch size |

---

## Backoff Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGEN_BACKOFF_INITIAL` | `500ms` | Initial backoff |
| `TELEGEN_BACKOFF_MAX` | `30s` | Maximum backoff |
| `TELEGEN_BACKOFF_MULTIPLIER` | `2.0` | Backoff multiplier |
| `TELEGEN_BACKOFF_JITTER` | `0.2` | Jitter factor |
| `TELEGEN_BACKOFF_MAX_RETRIES` | `5` | Max retry attempts |

---

## Usage Examples

### Docker

```bash
docker run -d --name telegen \
  --privileged --pid=host --network=host \
  -v /sys:/sys:ro \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e TELEGEN_OTLP_ENDPOINT=otel-collector:4317 \
  -e TELEGEN_AGENT_PROFILING_ENABLED=true \
  -e TELEGEN_AGENT_SECURITY_ENABLED=true \
  ghcr.io/platformbuilds/telegen:latest
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: telegen-config
data:
  TELEGEN_OTLP_ENDPOINT: "otel-collector.monitoring:4317"
  TELEGEN_AGENT_PROFILING_ENABLED: "true"
  TELEGEN_AGENT_SECURITY_ENABLED: "true"
  TELEGEN_LOG_LEVEL: "info"
```

### Kubernetes Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: telegen-secrets
type: Opaque
stringData:
  TELEGEN_OTLP_HEADERS: "Authorization=Bearer your-token"
```

### Shell Script

```bash
#!/bin/bash
export TELEGEN_OTLP_ENDPOINT="otel-collector:4317"
export TELEGEN_AGENT_PROFILING_ENABLED=true
export TELEGEN_AGENT_SECURITY_ENABLED=true
export TELEGEN_LOG_LEVEL=debug

telegen
```

---

## Precedence

Configuration values are resolved in this order (highest to lowest):

1. **Environment variables** - Always win
2. **Config file** - Merged with defaults
3. **Built-in defaults** - Fallback values

Example:

```yaml
# config.yaml
otlp:
  endpoint: "from-config:4317"
```

```bash
# Environment
export TELEGEN_OTLP_ENDPOINT="from-env:4317"
```

Result: `otlp.endpoint` = `from-env:4317`

---

## Secret Substitution

Config files support environment variable substitution using `${VAR}` syntax:

```yaml
otlp:
  endpoint: "${OTEL_ENDPOINT}"
  headers:
    Authorization: "Bearer ${OTEL_TOKEN}"

collector:
  snmp:
    targets:
      - address: "10.0.1.1:161"
        security:
          auth_password: "${SNMP_AUTH_PASSWORD}"
          priv_password: "${SNMP_PRIV_PASSWORD}"
```

---

## Next Steps

- {doc}`minimal-config` - Getting started with minimal config
- {doc}`full-reference` - Complete configuration reference
