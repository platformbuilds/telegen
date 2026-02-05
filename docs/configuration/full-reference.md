# Full Configuration Reference

Complete reference for all Telegen configuration options.

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

```yaml
agent:
  # Service name for telemetry
  service_name: "telegen"
  
  # eBPF configuration
  ebpf:
    enabled: true
    
    # Ring buffer size (must be power of 2)
    ringbuf_size: 16777216  # 16MB
    
    # Per-CPU perf buffer size
    perf_buffer_size: 8192  # 8KB
    
    # Network tracing
    network:
      enabled: true
      http: true
      grpc: true
      dns: true
      tcp_metrics: true
    
    # Syscall tracing
    syscalls:
      enabled: true
      include: []  # Empty = all syscalls
      exclude:
        - futex
        - nanosleep
        - clock_gettime
    
    # Process lifecycle tracking
    process:
      enabled: true
      lifecycle: true
      file_ops: true
  
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
  
  # Cloud/K8s metadata discovery (automatic)
  metadata_discovery:
    enabled: true
    interval: 30s
    detect_cloud: true
    detect_kubernetes: true
    detect_runtimes: true
    detect_databases: true
    detect_message_queues: true
  
  # Continuous profiling
  profiling:
    enabled: false
    sample_rate: 99  # Hz
    
    # Profile types
    cpu: true
    off_cpu: true
    memory: true
    mutex: true
    block: true
    goroutine: true
    
    # Duration for each profile
    duration: 10s
    
    # Upload interval
    upload_interval: 60s
  
  # Security monitoring
  security:
    enabled: false
    
    # Syscall auditing
    syscall_audit:
      enabled: true
      syscalls:
        - execve
        - execveat
        - ptrace
        - setuid
        - setgid
        - mount
        - umount
        - init_module
        - finit_module
        - delete_module
    
    # File integrity monitoring
    file_integrity:
      enabled: true
      paths:
        - /etc/passwd
        - /etc/shadow
        - /etc/sudoers
        - /etc/ssh/sshd_config
        - /root/.ssh
      recursive: true
    
    # Container escape detection
    container_escape:
      enabled: true
  
  # Network observability
  network:
    enabled: true
    
    # DNS tracing
    dns:
      enabled: true
      capture_queries: true
      capture_responses: true
    
    # TCP metrics
    tcp:
      enabled: true
      rtt: true
      retransmits: true
      connection_tracking: true
    
    # XDP packet tracing
    xdp:
      enabled: false
      sample_rate: 1000  # 1 in N packets
      interfaces: []  # Empty = all interfaces
  
  # Log collection
  logs:
    enabled: true
    
    # File paths to tail
    paths:
      - /var/log/*.log
      - /var/log/**/*.log
    
    # Container logs
    container_logs: true
    
    # Exclude patterns
    exclude:
      - "*.gz"
      - "*.zip"
    
    # Multiline configuration
    multiline:
      enabled: true
      pattern: "^\\d{4}-\\d{2}-\\d{2}"
      negate: true
      match: after
  
  # GPU monitoring
  gpu:
    enabled: true
    nvidia: true
    poll_interval: 10s
```

---

## Collector Configuration

```yaml
collector:
  # SNMP configuration
  snmp:
    enabled: false
    poll_interval: 60s
    timeout: 10s
    retries: 3
    
    # SNMP targets
    targets:
      - name: "core-switch-01"
        address: "10.0.1.1:161"
        version: "v2c"  # v1, v2c, v3
        community: "public"
        modules:
          - if_mib
          - entity_mib
        labels:
          location: "dc1"
      
      - name: "router-01"
        address: "10.0.1.2:161"
        version: "v3"
        security:
          user: "monitor"
          auth_protocol: "SHA256"
          auth_password: "${SNMP_AUTH_PASSWORD}"
          priv_protocol: "AES256"
          priv_password: "${SNMP_PRIV_PASSWORD}"
        modules:
          - if_mib
          - bgp4_mib
    
    # SNMP trap receiver
    trap_receiver:
      enabled: true
      listen_address: ":162"
    
    # Network discovery
    discovery:
      enabled: false
      networks:
        - "10.0.0.0/16"
      interval: 1h
  
  # Storage array monitoring
  storage:
    # Dell PowerStore/PowerScale
    dell:
      enabled: false
      poll_interval: 60s
      targets:
        - name: "powerstore-01"
          address: "https://10.0.10.100"
          username: "monitor"
          password: "${DELL_PASSWORD}"
          verify_ssl: true
    
    # Pure Storage FlashArray
    pure:
      enabled: false
      poll_interval: 60s
      targets:
        - name: "pure-01"
          address: "https://10.0.10.110"
          api_token: "${PURE_TOKEN}"
    
    # NetApp ONTAP
    netapp:
      enabled: false
      poll_interval: 60s
      targets:
        - name: "ontap-01"
          address: "https://10.0.10.120"
          username: "monitor"
          password: "${NETAPP_PASSWORD}"
    
    # HPE Primera/3PAR
    hpe:
      enabled: false
      poll_interval: 60s
      targets:
        - name: "primera-01"
          address: "https://10.0.10.130"
          username: "monitor"
          password: "${HPE_PASSWORD}"
  
  # Network infrastructure
  network_infra:
    # Arista CloudVision
    arista:
      enabled: false
      address: "https://cloudvision.example.com"
      token: "${ARISTA_TOKEN}"
    
    # Cisco ACI
    cisco_aci:
      enabled: false
      address: "https://apic.example.com"
      username: "monitor"
      password: "${ACI_PASSWORD}"
```

---

## Queue Configuration

```yaml
queues:
  # Trace queue
  traces:
    mem_limit: "256Mi"
    max_age: "6h"
    batch_size: 512
  
  # Metrics queue
  metrics:
    mem_limit: "128Mi"
    max_age: "5m"
    batch_size: 1000
  
  # Logs queue
  logs:
    mem_limit: "256Mi"
    max_age: "24h"
    batch_size: 1000
```

---

## Retry Configuration

```yaml
backoff:
  initial: "500ms"
  max: "30s"
  multiplier: 2.0
  jitter: 0.2
  max_retries: 5
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
  
  # GCP configuration  
  gcp:
    enabled: true
    timeout: "200ms"
    refresh_interval: "15m"
  
  # Azure configuration
  azure:
    enabled: true
    timeout: "200ms"
    refresh_interval: "15m"
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
