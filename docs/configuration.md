# Telegen Configuration Reference

Complete reference for all Telegen configuration options.

## Table of Contents

- [Configuration File](#configuration-file)
- [Core Configuration](#core-configuration)
- [eBPF Configuration](#ebpf-configuration)
- [Discovery Configuration](#discovery-configuration)
- [Profiling Configuration](#profiling-configuration)
- [Security Configuration](#security-configuration)
- [Network Configuration](#network-configuration)
- [Logs Configuration](#logs-configuration)
- [Export Configuration](#export-configuration)
- [Self-Telemetry Configuration](#self-telemetry-configuration)
- [Environment Variables](#environment-variables)
- [Example Configurations](#example-configurations)

## Configuration File

Telegen uses YAML configuration. Default locations:

1. `/etc/telegen/config.yaml`
2. `./config.yaml`
3. Path specified via `--config` flag

## Core Configuration

```yaml
telegen:
  # Operation mode: "agent" (eBPF instrumentation) or "collector" (remote polling)
  mode: agent
  
  # Service name for identification
  service_name: "telegen"
  
  # Instance ID (defaults to hostname)
  instance_id: ""
  
  # Log level: debug, info, warn, error
  log_level: info
  
  # Log format: json or text
  log_format: json
```

## eBPF Configuration

```yaml
ebpf:
  # Enable eBPF instrumentation
  enabled: true
  
  # Network tracing
  network:
    enabled: true
    # Enable HTTP/gRPC parsing
    http:
      enabled: true
      # Maximum buffer size for HTTP body capture
      max_body_size: 1048576
    # Enable database query parsing
    database:
      enabled: true
      # Supported: mysql, postgres, redis, mongodb
      protocols:
        - mysql
        - postgres
        - redis
  
  # Syscall tracing
  syscalls:
    enabled: true
    # Trace specific syscalls (empty = all)
    include: []
    # Exclude syscalls from tracing
    exclude:
      - futex
      - nanosleep
  
  # Process tracking
  process:
    enabled: true
    # Track process lifecycle events
    lifecycle: true
    # Track file operations
    file_ops: true
  
  # Memory allocation tracking
  memory:
    enabled: false
    # Track allocations larger than this size
    min_size: 1024
  
  # eBPF ring buffer size (must be power of 2)
  ringbuf_size: 16777216  # 16MB
  
  # Per-CPU buffer size for perf events
  perf_buffer_size: 8192
  
  # Maximum number of concurrent tracked connections
  max_connections: 100000
  
  # BPF filesystem mount point
  bpf_fs: "/sys/fs/bpf"
  
  # Pin BPF objects for persistence
  pin_objects: false
```

## Discovery Configuration

```yaml
discovery:
  # Enable service discovery
  enabled: true
  
  # Kubernetes discovery
  kubernetes:
    enabled: true
    # Namespace to watch (empty = all namespaces)
    namespace: ""
    # Include pod labels as span attributes
    include_labels: true
    # Include pod annotations as span attributes
    include_annotations: false
    # Label selector for pods to instrument
    label_selector: ""
    # Exclude system namespaces
    exclude_namespaces:
      - kube-system
      - kube-public
  
  # AWS discovery
  aws:
    enabled: false
    # EC2 instance metadata
    ec2:
      enabled: true
    # ECS task metadata
    ecs:
      enabled: true
    # EKS cluster metadata
    eks:
      enabled: true
  
  # Azure discovery
  azure:
    enabled: false
    # Azure Instance Metadata Service
    imds:
      enabled: true
    # AKS cluster metadata
    aks:
      enabled: true
  
  # GCP discovery
  gcp:
    enabled: false
    # GCE metadata
    gce:
      enabled: true
    # GKE cluster metadata
    gke:
      enabled: true
  
  # Static discovery
  static:
    enabled: false
    # Static service definitions
    services: []
```

## Profiling Configuration

```yaml
profiling:
  # Enable continuous profiling
  enabled: true
  
  # CPU profiling
  cpu:
    enabled: true
    # Sample rate (samples per second)
    sample_rate: 99
    # Stack depth limit
    stack_depth: 128
  
  # Memory profiling
  memory:
    enabled: true
    # Profile allocations
    allocations: true
    # Profile live objects
    live_objects: true
    # Minimum allocation size to track
    min_size: 1024
  
  # Goroutine profiling (Go applications)
  goroutine:
    enabled: true
    # Profile interval
    interval: 10s
  
  # Block profiling (Go applications)
  block:
    enabled: false
    # Block profile rate
    rate: 1
  
  # Mutex profiling (Go applications)
  mutex:
    enabled: false
    # Mutex profile fraction
    fraction: 1
  
  # Off-CPU profiling
  off_cpu:
    enabled: true
    # Minimum off-CPU time to record
    min_duration: 1ms
  
  # Symbol resolution
  symbols:
    # Use DWARF debug info
    dwarf: true
    # Use Go symbol table
    go_symbols: true
    # Use kernel symbols
    kernel_symbols: true
    # Cache size for symbol resolution
    cache_size: 10000
  
  # Profile aggregation interval
  aggregation_interval: 10s
  
  # Profile upload interval
  upload_interval: 60s
```

## Security Configuration

```yaml
security:
  # Enable security monitoring
  enabled: true
  
  # Syscall auditing
  syscall_audit:
    enabled: true
    # Log all syscalls (verbose)
    log_all: false
    # Syscalls to monitor specifically
    monitored_syscalls:
      - execve
      - execveat
      - ptrace
      - process_vm_readv
      - process_vm_writev
  
  # File integrity monitoring
  file_integrity:
    enabled: true
    # Paths to monitor
    paths:
      - /etc/passwd
      - /etc/shadow
      - /etc/sudoers
      - /etc/ssh/sshd_config
      - /usr/bin
      - /usr/sbin
    # Events to track: create, modify, delete, chmod
    events:
      - modify
      - delete
      - chmod
  
  # Container escape detection
  container_escape:
    enabled: true
    # Detection methods
    methods:
      - namespace_escape
      - cgroup_escape
      - privileged_operation
  
  # Process injection detection
  process_injection:
    enabled: true
    # Detection methods
    methods:
      - ptrace_attach
      - process_vm_write
      - ld_preload
  
  # Network security
  network:
    enabled: true
    # Detect DNS tunneling
    dns_tunneling: true
    # Detect port scanning
    port_scanning: true
    # Detect suspicious connections
    suspicious_connections: true
  
  # Runtime behavior baseline
  baseline:
    enabled: true
    # Learning period duration
    learning_period: 24h
    # Alert on deviation
    alert_on_deviation: true
```

## Network Configuration

```yaml
network:
  # Enable network flow tracking
  enabled: true
  
  # Traffic capture
  capture:
    enabled: true
    # Interfaces to monitor (empty = all)
    interfaces: []
    # Exclude loopback
    exclude_loopback: true
  
  # DNS tracking
  dns:
    enabled: true
    # Capture DNS queries
    queries: true
    # Capture DNS responses
    responses: true
    # Maximum query cache size
    cache_size: 10000
  
  # Layer 7 protocol parsing
  protocols:
    http:
      enabled: true
      # Parse request/response headers
      headers: true
      # Parse request/response body (expensive)
      body: false
      # Maximum body size to parse
      max_body_size: 65536
    grpc:
      enabled: true
    mysql:
      enabled: true
      # Capture query text
      capture_query: true
    postgres:
      enabled: true
      capture_query: true
    redis:
      enabled: true
      capture_command: true
    mongodb:
      enabled: true
      capture_query: true
    kafka:
      enabled: true
    rabbitmq:
      enabled: true
  
  # TCP tracking
  tcp:
    enabled: true
    # Track TCP state changes
    state_tracking: true
    # Track retransmissions
    retransmissions: true
    # Track RTT
    rtt: true
  
  # Flow aggregation
  aggregation:
    # Aggregation interval
    interval: 30s
    # Maximum flows per interval
    max_flows: 100000
```

## Logs Configuration

```yaml
logs:
  # Enable log collection
  enabled: true
  
  # File log sources
  filelog:
    # Include patterns
    include:
      - /var/log/*.log
      - /var/log/**/*.log
    # Exclude patterns
    exclude:
      - /var/log/telegen/*.log
    # Position file for resuming
    position_file: /var/lib/telegen/positions.json
    # Poll interval
    poll_interval: 500ms
  
  # Journal logs (systemd)
  journal:
    enabled: true
    # Units to include
    include_units: []
    # Units to exclude
    exclude_units:
      - systemd-networkd.service
  
  # Container logs
  containers:
    enabled: true
    # Container runtime: docker, containerd, cri-o
    runtime: auto
    # Include container metadata
    include_metadata: true
  
  # Log parsing
  parsing:
    # Parse JSON logs
    json: true
    # Parse multiline logs
    multiline:
      enabled: true
      # First line pattern
      first_line_pattern: '^\d{4}-\d{2}-\d{2}'
  
  # Log enrichment
  enrichment:
    # Add hostname
    hostname: true
    # Add Kubernetes metadata
    kubernetes: true
    # Add custom attributes
    attributes: {}
```

## Export Configuration

Telegen uses a **Common Exporter Pipeline** architecture where all signals share
a unified OTLP export configuration.

### Common Exporter Pipeline Architecture

All telegen signals (kube_metrics, node_exporter, ebpf, jfr, logs) flow through
a shared OTLP exporter, ensuring consistent behavior and simplified management:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TELEGEN AGENT                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  ┌─────┐  │
│   │kube_metrics │  │node_exporter│  │    ebpf     │  │   jfr   │  │logs │  │
│   │ (kubestate  │  │   (host     │  │  (traces +  │  │(to JSON │  │     │  │
│   │ + cadvisor) │  │   metrics)  │  │   metrics)  │  │  logs)  │  │     │  │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────┬────┘  └──┬──┘  │
│          │                │                │              │          │     │
│          └────────────────┴────────────────┴──────────────┴──────────┘     │
│                                    │                                        │
│                       ┌────────────▼────────────┐                          │
│                       │  COMMON OTLP EXPORTER   │                          │
│                       │    (exports.otlp)       │                          │
│                       │                         │                          │
│                       │  grpc: :4317            │                          │
│                       │  http: :4318            │                          │
│                       └────────────┬────────────┘                          │
│                                    │                                        │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │        OTEL COLLECTOR          │
                    └────────────────────────────────┘
```

### Benefits

- **Connection pooling** - Single gRPC/HTTP connection to collector
- **Consistent configuration** - TLS, compression, timeouts configured once
- **Simplified management** - Change endpoint once, affects all signals
- **Reduced resource usage** - No per-signal connection overhead

### Signal-to-Exporter Mapping

| Signal | Configuration | Export Path |
|--------|--------------|-------------|
| kube_metrics | `kube_metrics.streaming.use_otlp: true` | `exports.otlp.grpc` |
| node_exporter | `node_exporter.export.use_otlp: true` | `exports.otlp.grpc` |
| ebpf traces | `ebpf.otel_traces_export.protocol: grpc` | `exports.otlp.grpc` |
| ebpf metrics | `ebpf.otel_metrics_export.protocol: grpc` | `exports.otlp.grpc` |
| jfr logs | `pipelines.jfr.direct_export.log_export.otlp_enabled: true` | `exports.otlp.http` |
| app logs | `pipelines.logs.enabled: true` | `exports.otlp.http` |

### OTLP Configuration

```yaml
exports:
  # OTLP export
  otlp:
    # gRPC endpoint
    grpc:
      enabled: true
      endpoint: "localhost:4317"
      # Use TLS
      tls:
        enabled: false
        # CA certificate file
        ca_file: ""
        # Client certificate file
        cert_file: ""
        # Client key file
        key_file: ""
        # Skip server verification (insecure)
        insecure_skip_verify: false
      # Connection timeout
      timeout: 30s
      # Retry settings
      retry:
        enabled: true
        initial_interval: 1s
        max_interval: 30s
        max_elapsed_time: 5m
      # Headers
      headers: {}
      # Compression: none, gzip
      compression: gzip
    
    # HTTP endpoint
    http:
      enabled: false
      endpoint: "http://localhost:4318"
      # Same TLS options as gRPC
  
  # Prometheus remote write
  prometheus:
    enabled: false
    endpoint: "http://prometheus:9090/api/v1/write"
    # Basic auth
    basic_auth:
      username: ""
      password: ""
  
  # Pyroscope export for profiles
  pyroscope:
    enabled: false
    endpoint: "http://pyroscope:4040"
    # Tenant ID for multi-tenancy
    tenant_id: ""
  
  # Loki export for logs
  loki:
    enabled: false
    endpoint: "http://loki:3100/loki/api/v1/push"
    # Batch size
    batch_size: 1000
    # Batch wait time
    batch_wait: 1s
  
  # Batch settings (global)
  batch:
    # Maximum batch size
    max_size: 8192
    # Maximum batch wait time
    timeout: 5s
  
  # Queue settings (global)
  queue:
    # Queue size
    size: 5000
    # Number of consumers
    num_consumers: 10
```

## Self-Telemetry Configuration

The `selfTelemetry` section configures the agent's health endpoints and internal metrics.

```yaml
selfTelemetry:
  # HTTP endpoint for health probes and Prometheus metrics
  # Serves: /healthz, /readyz, /metrics
  listen: ":8080"
  
  # Prometheus metrics namespace prefix
  prometheus_namespace: "telegen"
```

### Endpoints

| Path | Description |
|------|-------------|
| `/healthz` | Liveness probe - returns 200 if agent is alive |
| `/readyz` | Readiness probe - returns 200 when pipeline is ready |
| `/metrics` | Prometheus metrics for agent internals |

### Health Probes for Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  periodSeconds: 20

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  periodSeconds: 10

startupProbe:
  httpGet:
    path: /healthz
    port: 8080
  failureThreshold: 30
  periodSeconds: 10
```

## Environment Variables

All configuration options can be set via environment variables:

| Environment Variable | Description |
|---------------------|-------------|
| `TELEGEN_MODE` | Operation mode (agent/collector) |
| `TELEGEN_LOG_LEVEL` | Log level (debug/info/warn/error) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint URL |
| `OTEL_EXPORTER_OTLP_HEADERS` | OTLP headers (comma-separated) |
| `OTEL_EXPORTER_OTLP_INSECURE` | Disable TLS (true/false) |
| `TELEGEN_TRACING_ENABLED` | Enable tracing (true/false) |
| `TELEGEN_PROFILING_ENABLED` | Enable profiling (true/false) |
| `TELEGEN_SECURITY_ENABLED` | Enable security (true/false) |
| `TELEGEN_NETWORK_ENABLED` | Enable network (true/false) |
| `TELEGEN_LOGS_ENABLED` | Enable logs (true/false) |
| `TELEGEN_CPU_SAMPLE_RATE` | CPU profiling sample rate |
| `TELEGEN_DISCOVERY_KUBERNETES` | Enable K8s discovery (true/false) |

## Example Configurations

### Minimal Agent Configuration

```yaml
telegen:
  mode: agent

ebpf:
  enabled: true

exports:
  otlp:
    grpc:
      enabled: true
      endpoint: "otel-collector:4317"
      insecure: true
```

### Full-Featured Agent

```yaml
telegen:
  mode: agent
  service_name: "my-app"
  log_level: info

ebpf:
  enabled: true
  network:
    enabled: true
    http:
      enabled: true
    database:
      enabled: true
      protocols:
        - mysql
        - postgres
        - redis

discovery:
  enabled: true
  kubernetes:
    enabled: true

profiling:
  enabled: true
  cpu:
    enabled: true
    sample_rate: 99
  memory:
    enabled: true
  off_cpu:
    enabled: true

security:
  enabled: true
  syscall_audit:
    enabled: true
  file_integrity:
    enabled: true
  container_escape:
    enabled: true

logs:
  enabled: true
  containers:
    enabled: true

exports:
  otlp:
    grpc:
      enabled: true
      endpoint: "otel-collector:4317"
      tls:
        enabled: true
        ca_file: "/etc/telegen/certs/ca.crt"
```

### Collector Mode (SNMP)

```yaml
telegen:
  mode: collector
  service_name: "telegen-collector"

snmp:
  enabled: true
  receivers:
    - targets:
        - "192.168.1.1:161"
        - "192.168.1.2:161"
      community: "public"
      version: "2c"
      interval: 60s
      modules:
        - if_mib
        - system
    - targets:
        - "10.0.0.1:161"
      version: "3"
      security_level: authPriv
      username: "admin"
      auth_protocol: SHA
      auth_password: "${SNMP_AUTH_PASSWORD}"
      priv_protocol: AES
      priv_password: "${SNMP_PRIV_PASSWORD}"
      interval: 30s
      modules:
        - entity_mib
        - power_mib

storage:
  enabled: true
  targets:
    - type: netapp
      endpoint: "https://netapp.local"
      username: "admin"
      password: "${NETAPP_PASSWORD}"
    - type: purestorage
      endpoint: "https://pure.local"
      api_token: "${PURE_API_TOKEN}"

exports:
  otlp:
    grpc:
      enabled: true
      endpoint: "otel-collector:4317"
```

### Development Configuration

```yaml
telegen:
  mode: agent
  log_level: debug
  log_format: text

ebpf:
  enabled: true
  network:
    enabled: true

selfTelemetry:
  listen: ":19090"
  health_listen: ":8080"
  pprof: true

exports:
  otlp:
    grpc:
      enabled: true
      endpoint: "localhost:4317"
      insecure: true
```

## Next Steps

- [Installation Guide](installation.md) - Install Telegen on your platform
- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions
