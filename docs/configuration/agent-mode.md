# Agent Mode Configuration

Detailed configuration guide for Telegen Agent mode.

## Overview

**Agent Mode** is the default operating mode for Telegen. In this mode, Telegen runs directly on hosts, collects telemetry using eBPF, and exports data to your OTLP backend.

```{mermaid}
flowchart LR
    subgraph Host["Host System"]
        K["Kernel"]
        A["Applications"]
        TG["Telegen Agent"]
    end
    
    K -->|eBPF| TG
    A -->|Auto-instrumented| TG
    TG -->|OTLP| OC["OTel Collector"]
```

---

## When to Use Agent Mode

Use Agent Mode when you want to:

- **Collect host-level telemetry** - CPU, memory, disk, network
- **Auto-instrument applications** - No code changes required
- **Enable distributed tracing** - HTTP, gRPC, database calls
- **Enable continuous profiling** - CPU, memory, off-CPU
- **Monitor security events** - Syscalls, file integrity

---

## Minimal Agent Configuration

```yaml
agent:
  mode: agent

exports:
  otlp:
    grpc:
      enabled: true
      endpoint: "otel-collector:4317"
      insecure: true
```

---

## eBPF Configuration

All eBPF tuning lives under `ebpf.tracer`. `ebpf` itself is a top-level section — it is not nested under `agent`.

### BPF Map Sizing

BPF map capacity is scaled as a whole rather than tuned per buffer. `global_scale_factor` moves every map in powers of two: `1` doubles them, `-1` halves them, `0` leaves the defaults.

```yaml
ebpf:
  tracer:
    maps_config:
      global_scale_factor: 0
```

| Value | Use Case |
|-------|----------|
| -1 | Low-throughput environments, tight memory budgets |
| 0 | Default, balanced |
| 1 | High-throughput, many connections |
| 2 | Very high volume, latency-sensitive |

Individual protocol ring buffers can be overridden when a single protocol dominates. `0` means "use the built-in default".

```yaml
ebpf:
  tracer:
    buffer_sizes:
      http: 0
      mysql: 0
      postgres: 0
      kafka: 0
      tcp: 0
```

### Event Batching

Batching controls how often the tracer drains events to userspace:

```yaml
ebpf:
  tracer:
    batch_length: 100
    batch_timeout: 1s
```

---

## Network Tracing

Network flow observability is an on/off switch. Protocol selection is driven by
`ebpf.otel_traces_export.instrumentations`, not by per-protocol network flags.

```yaml
ebpf:
  network:
    enabled: true
```

---

## Process Discovery

Telegen discovers which processes to instrument using **port-based** and/or **path-based** selection.

### Basic Discovery

```yaml
ebpf:
  discovery:
    # Skip services already instrumented with OTel SDKs
    exclude_otel_instrumented_services: true
    
    # Process discovery timing
    min_process_age: 5s
    poll_interval: 5s
```

### Port-Based Discovery (Recommended)

Port-based discovery is more reliable in containerized environments:

```yaml
ebpf:
  discovery:
    instrument:
      # Single port
      - open_ports: "8080"
      
      # Port range
      - open_ports: "8000-8999"
      
      # Multiple ports and ranges
      - open_ports: "80,443,3000,8080-8089"
```

### Path-Based Discovery

Discover by executable path pattern (glob syntax):

```yaml
ebpf:
  discovery:
    instrument:
      # All Java processes
      - exe_path: "*java*"
      
      # Specific application
      - exe_path: "/usr/bin/myapp"
      
      # Node.js
      - exe_path: "*node*"
```

### Kubernetes-Aware Discovery

```yaml
ebpf:
  discovery:
    instrument:
      # By namespace
      - k8s_namespace: "production"
      
      # By namespace + port
      - k8s_namespace: "production"
        open_ports: "8080"
      
      # By pod labels
      - k8s_pod_labels:
          app: "frontend*"
          version: "v2*"
      
      # By annotations
      - k8s_pod_annotations:
          telegen.io/instrument: "true"
```

### Excluding Services

```yaml
ebpf:
  discovery:
    instrument:
      - open_ports: "8080-8089"
    
    exclude_instrument:
      # Test namespaces
      - k8s_namespace: "*-test"
      
      # Prometheus metrics port
      - open_ports: "9090"
      
      # Health check services
      - exe_path: "*health*"
    
    # Default exclusions (observability tools)
    default_exclude_instrument:
      - exe_path: "*telegen*"
      - exe_path: "*otelcol*"
      - k8s_namespace: "kube-system"
```

### Full Discovery Example

```yaml
ebpf:
  discovery:
    exclude_otel_instrumented_services: true
    skip_go_specific_tracers: false
    
    instrument:
      # Common app ports
      - open_ports: "8080-8089"
      - open_ports: "3000,5000"
      
      # Java in production
      - exe_path: "*java*"
        k8s_namespace: "production"
      
      # Opt-in via annotation
      - k8s_pod_annotations:
          telegen.io/instrument: "true"
    
    exclude_instrument:
      - k8s_namespace: "kube-system"
      - open_ports: "9090"
    
    min_process_age: 5s
    poll_interval: 5s
```

### Metadata Discovery

Cloud environment detection is configured under the top-level `cloud` section. Runtime, database, and message-queue detection is automatic and has no configuration surface.

```yaml
cloud:
  auto_detect: true
  detection_timeout: 5s
  detection_interval: 5m
  discover_resources: true
  resource_interval: 5m
```

Kubernetes metadata decoration is configured separately:

```yaml
kubernetes:
  enable: true
```

### Runtime Detection

Telegen automatically detects and instruments:

| Runtime | Detection Method | Tracing Support |
|---------|-----------------|-----------------|
| **Go** | Binary analysis, goroutine patterns | ✅ Full |
| **Java** | JVM process, JFR integration | ✅ Full |
| **Python** | Interpreter process, frame analysis | ✅ Full |
| **Node.js** | V8 process detection | ✅ Full |
| **.NET** | CoreCLR detection | ✅ Full |
| **Ruby** | Interpreter detection | ⚠️ Partial |
| **Rust** | Binary analysis | ✅ Full |

---

## Continuous Profiling

Enable CPU, memory, and off-CPU profiling:

```yaml
profiling:
  enabled: true

  # How often a profile is collected, and how often profiles are shipped
  collection_interval: 10s
  upload_interval: 60s

  # Profile types. Each is configured independently.
  cpu:
    enabled: true
    sample_rate: 99       # 99 Hz avoids aliasing with periodic workloads
    max_stack_depth: 127
  off_cpu:
    enabled: true
    min_block_time_ns: 1000000
  memory:
    enabled: true
    min_alloc_size: 1024
  mutex:
    enabled: true
    contention_threshold_ns: 1000000

  # Symbol resolution
  symbols:
    demangling_enabled: true
    go_symbols: true
    kernel_symbols: true
```

---

## Security Monitoring

```{warning}
Runtime security monitoring has **no configuration surface** today. There is no
`security` section in the agent config; adding one stops the agent from starting,
because unknown keys are rejected.
```

---

## Log Collection

File tailing lives under `pipelines.logs.filelog`. Include and exclude are glob lists; container logs are picked up by including their path.

```yaml
pipelines:
  logs:
    enabled: true
    filelog:
      include:
        - /var/log/syslog
        - /var/log/auth.log
        - /var/log/*.log
        - /var/log/**/*.log
      exclude:
        - "*.gz"
        - "*.zip"
        - "*.old"
        - "**/lastlog"
        - "**/wtmp"
        - "**/btmp"
      position_file: /var/lib/telegen/logs.pos
      poll_interval: "5s"
      ship_historical_events: false
```

```{note}
Multiline assembly and per-format parsing are applied automatically by the log
parsers. They are not configurable from the agent config today.
```

---

## GPU Monitoring

GPU metrics are collected by the host metrics collector when a supported device is present. There is no `gpu` configuration section; NVML-backed collection is automatic.

---

## Resource Limits

The agent bounds its own memory through the Go runtime memory limit. CPU and per-signal rate limiting are not configurable from the agent config today.

```yaml
selfTelemetry:
  # Soft memory ceiling for the agent process, in bytes
  memory_limit_bytes: 536870912
```

---

## Kubernetes-Specific

When running in Kubernetes, metadata decoration is available:

```yaml
kubernetes:
  enable: true
  cluster_name: "prod-us-east-1"
  informers_sync_timeout: "30s"
  informers_resync_period: "30m"

  # Which pod/node labels are copied onto resources
  resource_labels:
    - "app.kubernetes.io/name"
    - "app.kubernetes.io/version"
    - "app"
    - "version"
```

---

## Example: Mutual TLS to the Collector

```yaml
agent:
  mode: agent
  log_level: INFO

exports:
  otlp:
    tls:
      enable: true
      ca_file: "/etc/ssl/certs/ca.crt"
      cert_file: "/etc/ssl/certs/client.crt"
      key_file: "/etc/ssl/certs/client.key"
    grpc:
      enabled: true
      endpoint: "otel-collector:4317"
      insecure: false

ebpf:
  enabled: true
  network:
    enabled: true

profiling:
  enabled: true
  cpu:
    enabled: true
  memory:
    enabled: true
```

---

## Example: Performance-Optimized

```yaml
agent:
  mode: agent
  log_level: WARN

exports:
  otlp:
    grpc:
      enabled: true
      endpoint: "otel-collector:4317"
      insecure: true
      compression: "gzip"

ebpf:
  enabled: true
  network:
    enabled: true
  tracer:
    # Grow every BPF map one power of two for high event volume
    maps_config:
      global_scale_factor: 1
    # Drain larger batches less often
    batch_length: 500
    batch_timeout: 5s

selfTelemetry:
  memory_limit_bytes: 1073741824
```

---

## Next Steps

- {doc}`collector-mode` - Remote collection without eBPF
- {doc}`environment-variables` - Environment variable reference
