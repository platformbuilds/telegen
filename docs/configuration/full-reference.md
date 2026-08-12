# Full Configuration Reference

Complete reference for all Telegen configuration options.

> Current runtime uses top-level keys such as `exports`, `pipelines`, `vmware`, and `netinfra`.
> Some legacy examples in this page still use older grouped layouts; prefer
> `api/config.example.yaml` and `configs/netinfra-firewalls.yaml` for active examples.

## Configuration File Locations

Telegen searches for configuration in this order:

1. Path specified via `--config` flag
2. `./config.yaml` (current directory)
3. `/etc/telegen/config.yaml`

---

## Core Configuration

```yaml
telegen:
  # Operation mode: "agent" or "collector"
  mode: agent
  
  # Service identification
  service_name: "telegen"
  instance_id: "${HOSTNAME}"  # Defaults to hostname
  
  # Logging
  log_level: info    # debug, info, warn, error
  log_format: json   # json or text
  
  # Graceful shutdown timeout
  shutdown_timeout: 10s
```

---

## Common Exporter Pipeline

Telegen uses a **Common Exporter Pipeline** architecture where all signals share
a unified OTLP export configuration.

### Architecture

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

---

## OTLP Export Configuration

```yaml
otlp:
  # Primary endpoint (required)
  endpoint: "otel-collector:4317"
  
  # Protocol: grpc or http
  protocol: grpc
  
  # Compression: gzip, none
  compression: gzip
  
  # Connection timeout
  timeout: 10s
  
  # Skip TLS verification (not recommended for production)
  insecure: false
  
  # Custom headers
  headers:
    Authorization: "Bearer ${OTEL_TOKEN}"
    X-Custom-Header: "value"
  
  # TLS configuration
  tls:
    enabled: false
    ca_file: "/etc/ssl/certs/ca.crt"
    cert_file: "/etc/ssl/certs/client.crt"
    key_file: "/etc/ssl/certs/client.key"
    insecure_skip_verify: false
  
  # Per-signal configuration (optional overrides)
  traces:
    enabled: true
    endpoint: ""  # Use main endpoint if empty
    sample_rate: 1.0
  
  metrics:
    enabled: true
    endpoint: ""
  
  logs:
    enabled: true
    endpoint: ""
  
  profiles:
    enabled: true
    endpoint: ""
```

---

## Agent Configuration

```{tip}
`configs/telegen-full.yaml` in the repository is the exhaustive, machine-verified
reference. Every key below is checked against the config struct in CI.
```

```yaml
agent:
  # Service name for telemetry
  service_name: "telegen"

ebpf:
  enabled: true

  # Network flow observability. Protocol parsers (HTTP, gRPC, DNS, SQL,
  # messaging) are always active when this is on.
  network:
    enabled: true

  tracer:
    # BPF map sizing. Each step of the scale factor doubles every map.
    maps_config:
      global_scale_factor: 0

    # Per-protocol capture buffer budgets, in bytes. 0 uses the built-in default.
    buffer_sizes:
      http: 0
      mysql: 0
      postgres: 0
      mssql: 0
      kafka: 0
      mq: 0
      tcp: 0

    # Event draining
    batch_length: 100
    batch_timeout: 1s

  # Auto-discovery (process selection)
  discovery:
    # Skip services already instrumented with OpenTelemetry SDKs
    exclude_otel_instrumented_services: true
    exclude_otel_instrumented_services_span_metrics: false
    
    # Use generic HTTP tracers only (no Go-specific uprobes)
    skip_go_specific_tracers: false
    
    # Disable BPF-level PID filtering (debug only)
    bpf_pid_filter_off: false
    
    # =========================================================================
    # Process Instrumentation Targeting
    # =========================================================================
    # Each entry can specify one or more criteria (AND logic):
    #   - open_ports: Port numbers/ranges ("8080", "8000-8999", "80,443")
    #   - exe_path: Glob pattern for executable path
    #   - k8s_namespace: Kubernetes namespace (glob)
    #   - k8s_pod_name: Pod name (glob)
    #   - k8s_deployment_name: Deployment name (glob)
    #   - k8s_pod_labels: Map of label to glob pattern
    #   - k8s_pod_annotations: Map of annotation to glob pattern
    #   - containers_only: Only match containerized processes
    #   - name: Service name override
    #   - exports: What to export (traces, metrics)
    #   - sampler: Sampling configuration
    # =========================================================================
    instrument:
      # Port-based (recommended for containers)
      - open_ports: "8080-8089"
      
      # Path-based
      # - exe_path: "*java*"
      
      # Combined (AND logic)
      # - open_ports: "8080"
      #   exe_path: "*myapp*"
      
      # Kubernetes-aware
      # - k8s_namespace: "production"
      #   open_ports: "8080"
      
      # By pod labels
      # - k8s_pod_labels:
      #     app: "frontend*"
      
      # Containers only
      # - containers_only: true
      #   open_ports: "3000"
      
      # With custom sampling
      # - open_ports: "8080"
      #   sampler:
      #     name: parent_based_traceidratio
      #     arg: 0.1  # 10% sampling
    
    # Exclusions (takes precedence over instrument)
    exclude_instrument:
      # - k8s_namespace: "*-test"
      # - open_ports: "9090"
    
    # Default exclusions (telegen and observability tools)
    default_exclude_instrument:
      - exe_path: "*telegen*"
      - exe_path: "*alloy*"
      - exe_path: "*otelcol*"
      - k8s_namespace: "kube-system"
      - k8s_namespace: "monitoring"
    
    # Process discovery timing
    min_process_age: 5s
    poll_interval: 5s
    
    # Default OTLP port for detecting OTel-instrumented apps
    default_otlp_grpc_port: 4317
    
    # Route harvesting
    route_harvester_timeout: 10s
    disabled_route_harvesters: []
    route_harvester_advanced:
      java_harvest_delay: 60s

  # Which protocols produce spans
  otel_traces_export:
    instrumentations:
      - "*"

  # Drop noisy endpoints by attribute
  filter:
    application:
      url.path:
        not_match: "/{health,ready,metrics}*"

# Continuous profiling
profiling:
  enabled: false
  collection_interval: 10s
  upload_interval: 60s
  cpu:
    enabled: true
    sample_rate: 99      # Hz
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
  symbols:
    demangling_enabled: true
    go_symbols: true
    kernel_symbols: true

# Log collection
pipelines:
  logs:
    enabled: true
    filelog:
      include:
        - /var/log/*.log
        - /var/log/**/*.log
      exclude:
        - "*.gz"
        - "*.zip"
      position_file: /var/lib/telegen/logs.pos
      poll_interval: "5s"
```

```{note}
Protocol parsing, DNS capture, TCP metrics, XDP, syscall auditing, file
integrity monitoring, container-escape detection, and GPU polling have no
configuration surface. They are either always active with network
observability, or not configurable at all. Unknown keys stop the agent from
starting, so do not invent sections for them.
```

---

## Collector Configuration

Collector mode does not use a `collector:` wrapper. Each remote-collection
subsystem is its own top-level section. The shipped examples
(`configs/snmp_receiver.example.yaml`, `configs/storage.yaml`,
`configs/netinfra-firewalls.yaml`) carry the exhaustive field lists.

```yaml
# SNMP polling and trap reception
snmp_receiver:
  enabled: true

  trap_receiver:
    enabled: true
    listen_address: "0.0.0.0:162"
    community_strings:
      - "public"

  polling:
    enabled: true
    default_interval: 60s
    timeout: 10s
    retries: 3
    max_concurrent: 100

  targets:
    - name: "core-switch-01"
      address: "10.0.1.1:161"
      version: "v2c"
      community: "public"
      interval: 30s
      modules:
        - "if_mib"
        - "system"
      labels:
        location: "dc1"

# Storage arrays. Each vendor is a list of targets, not an enabled/targets pair.
storage:
  enabled: true
  collect_interval: 60s

  dell_powerstore:
    - name: "powerstore-01"
      address: "https://10.0.10.100"
      username: "monitor"
      password: "${DELL_PASSWORD}"
      verify_ssl: true
      collect: [capacity, performance, volumes, hosts]

  pure_flasharray:
    - name: "pure-01"
      address: "https://10.0.10.110"
      api_token: "${PURE_TOKEN}"
      verify_ssl: true

  netapp_ontap:
    - name: "ontap-01"
      address: "https://10.0.10.120"
      username: "monitor"
      password: "${NETAPP_PASSWORD}"
      verify_ssl: true

# Network infrastructure devices
netinfra:
  enabled: true
  collect_interval: 30s

  cloudvision:
    - name: "cvp-prod"
      cvp_url: "https://cloudvision.example.com"
      token: "${ARISTA_CVP_TOKEN}"
      verify_ssl: true

  aci:
    - name: "aci-fabric-a"
      apic_url: "https://apic.example.com"
      username: "${ACI_USERNAME}"
      password: "${ACI_PASSWORD}"
      verify_ssl: true
```

---

## Queue Configuration

```yaml
queues:
  # Trace queue
  traces:
    mem_limit: "256Mi"
    max_age: "6h"

  # Metrics queue
  metrics:
    mem_limit: "128Mi"
    max_age: "5m"

  # Logs queue
  logs:
    mem_limit: "256Mi"
    max_age: "24h"
```

---

## Retry Configuration

```yaml
backoff:
  initial: "500ms"
  max: "30s"
  multiplier: 2.0
  jitter: 0.2
```

---

## Self-Telemetry

The `selfTelemetry` section configures the agent's health endpoints and internal metrics.

```yaml
selfTelemetry:
  # HTTP endpoint for health probes and Prometheus metrics
  # Serves: /healthz, /readyz, /metrics
  listen: ":19090"
  
  # Prometheus metrics namespace prefix
  prometheus_namespace: "telegen"
```

### Endpoints

| Path | Description |
|------|-------------|
| `/healthz` | Liveness probe - returns 200 if agent is alive |
| `/readyz` | Readiness probe - returns 200 when pipeline is ready |
| `/metrics` | Prometheus metrics for agent internals |

---

## Cloud Configuration

```yaml
cloud:
  # Probe the instance metadata service to identify the provider
  auto_detect: true
  detection_timeout: 5s
  detection_interval: 5m

  # Discover cloud resources attached to this instance
  discover_resources: true
  resource_interval: 5m

  # AWS configuration
  aws:
    enabled: true
    timeout: "200ms"
    refresh_interval: "15m"
    collect_tags: false
    tag_allowlist:
      - "app_*"
      - "env"
      - "team"
    imdsv2_only: true
    imds_timeout: 200ms

  # GCP configuration
  gcp:
    enabled: true
    project: ""
    zone: ""
    metadata_timeout: 200ms

  # Azure configuration
  azure:
    enabled: true
    subscription_id: ""
    resource_group: ""
    imds_timeout: 200ms
```

---

## Signal Metadata

```yaml
exports:
  # Include signal metadata in all exports
  include_signal_metadata: true
  
  # Control which metadata fields are exported
  metadata_fields:
    enable_category: true
    enable_subcategory: true
    enable_source_module: true
    enable_bpf_component: true
    enable_description: false  # Verbose, disabled by default
    enable_collector_type: true
```

---

## Next Steps

- {doc}`agent-mode` - Agent-specific configuration
- {doc}`collector-mode` - Collector-specific configuration
- {doc}`environment-variables` - Environment variable reference
