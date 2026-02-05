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
telegen:
  mode: agent

otlp:
  endpoint: "otel-collector:4317"
```

---

## eBPF Configuration

### Ring Buffer Sizing

Ring buffers are used for high-throughput event streaming from kernel to userspace:

```yaml
agent:
  ebpf:
    # Ring buffer size - must be power of 2
    # Larger = more buffer, less event loss
    # Smaller = less memory usage
    ringbuf_size: 16777216  # 16MB (default)
```

| Size | Use Case |
|------|----------|
| 4MB | Low-throughput environments |
| 16MB | Default, balanced |
| 64MB | High-throughput, many connections |
| 256MB | Very high volume, latency-sensitive |

### Perf Buffer Sizing

Perf buffers are used for per-CPU event collection:

```yaml
agent:
  ebpf:
    perf_buffer_size: 8192  # 8KB per CPU (default)
```

---

## Network Tracing

```yaml
agent:
  ebpf:
    network:
      enabled: true
      
      # Protocol tracing
      http: true     # HTTP/1.1 and HTTP/2
      grpc: true     # gRPC over HTTP/2
      dns: true      # DNS queries/responses
      
      # TCP metrics
      tcp_metrics: true  # RTT, retransmits, connections
      
      # Interface filtering (empty = all interfaces)
      interfaces: []
      
      # Exclude by port
      exclude_ports:
        - 22    # SSH
        - 2379  # etcd
```

---

## Syscall Tracing

```yaml
agent:
  ebpf:
    syscalls:
      enabled: true
      
      # Include specific syscalls (empty = all)
      include: []
      
      # Exclude noisy syscalls
      exclude:
        - futex
        - nanosleep
        - clock_gettime
        - poll
        - select
        - epoll_wait
```

---

## Process Discovery

Telegen discovers which processes to instrument using **port-based** and/or **path-based** selection.

### Basic Discovery

```yaml
agent:
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
agent:
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
agent:
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
agent:
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
agent:
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
agent:
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

Automatic detection of cloud and runtime environments:

```yaml
agent:
  metadata_discovery:
    enabled: true
    interval: 30s
    detect_cloud: true        # AWS, GCP, Azure
    detect_kubernetes: true   # K8s metadata
    detect_runtimes: true     # Go, Java, Python, Node.js
    detect_databases: true    # MySQL, PostgreSQL, MongoDB
    detect_message_queues: true  # Kafka, RabbitMQ, Redis
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
agent:
  profiling:
    enabled: true
    
    # Sampling rate in Hz
    sample_rate: 99  # 99 Hz is common to avoid aliasing
    
    # Profile types
    cpu: true          # On-CPU time
    off_cpu: true      # Off-CPU waiting time
    memory: true       # Heap allocations
    mutex: true        # Lock contention (Go, Java)
    block: true        # Blocking operations (Go)
    goroutine: true    # Goroutine profiles (Go only)
    
    # Each profile sample duration
    duration: 10s
    
    # How often to upload profiles
    upload_interval: 60s
    
    # Symbol resolution
    symbols:
      demangle_rust: true
      demangle_cpp: true
```

---

## Security Monitoring

Enable runtime security monitoring:

```yaml
agent:
  security:
    enabled: true
    
    # Syscall auditing
    syscall_audit:
      enabled: true
      syscalls:
        - execve       # Process execution
        - execveat
        - ptrace       # Debugging/tracing
        - setuid       # Privilege changes
        - setgid
        - mount        # Filesystem mounts
        - umount
        - init_module  # Kernel modules
        - finit_module
        - delete_module
        - open_by_handle_at  # Filesystem escape
    
    # File integrity monitoring
    file_integrity:
      enabled: true
      paths:
        - /etc/passwd
        - /etc/shadow
        - /etc/sudoers
        - /etc/ssh/sshd_config
        - /root/.ssh
        - /etc/cron.d
        - /etc/crontab
      recursive: true
      events:
        - create
        - modify
        - delete
        - chmod
        - chown
    
    # Container escape detection
    container_escape:
      enabled: true
```

---

## Log Collection

```yaml
agent:
  logs:
    enabled: true
    
    # File paths to tail
    paths:
      - /var/log/syslog
      - /var/log/auth.log
      - /var/log/*.log
      - /var/log/**/*.log
    
    # Collect container logs
    container_logs: true
    
    # Exclude patterns
    exclude:
      - "*.gz"
      - "*.zip"
      - "*.old"
      - "lastlog"
      - "wtmp"
      - "btmp"
    
    # Multiline log handling
    multiline:
      enabled: true
      pattern: "^\\d{4}-\\d{2}-\\d{2}"  # ISO date
      negate: true
      match: after
      max_lines: 500
      timeout: 5s
```

---

## GPU Monitoring

```yaml
agent:
  gpu:
    enabled: true
    
    # NVIDIA GPU support (via NVML)
    nvidia: true
    
    # AMD GPU support (via ROCm SMI)
    amd: false
    
    # Polling interval
    poll_interval: 10s
    
    # Metrics to collect
    metrics:
      utilization: true      # GPU utilization %
      memory: true           # Memory usage
      temperature: true      # GPU temperature
      power: true            # Power consumption
      clock: true            # Clock speeds
      pcie_throughput: true  # PCIe bandwidth
```

---

## Resource Limits

```yaml
agent:
  resources:
    # CPU limit (number of cores)
    cpu_limit: 1.0
    
    # Memory limit
    memory_limit: "512Mi"
    
    # Limit concurrent eBPF programs
    max_ebpf_programs: 100
    
    # Rate limiting
    rate_limit:
      spans_per_second: 10000
      metrics_per_second: 50000
      logs_per_second: 5000
```

---

## Kubernetes-Specific

When running in Kubernetes, additional features are available:

```yaml
agent:
  kubernetes:
    enabled: true
    
    # Enrich with pod metadata
    pod_metadata: true
    
    # Enrich with node metadata
    node_metadata: true
    
    # Label filtering
    label_allowlist:
      - "app.kubernetes.io/*"
      - "helm.sh/*"
      - "app"
      - "version"
    
    # Namespace filtering
    namespace_include: []  # Empty = all
    namespace_exclude:
      - kube-system
      - kube-public
```

---

## Example: High-Security Environment

```yaml
telegen:
  mode: agent
  log_level: info

otlp:
  endpoint: "otel-collector:4317"
  tls:
    enabled: true
    ca_file: "/etc/ssl/certs/ca.crt"
    cert_file: "/etc/ssl/certs/client.crt"
    key_file: "/etc/ssl/certs/client.key"

agent:
  ebpf:
    enabled: true
    network:
      enabled: true
      http: true
      dns: true
    syscalls:
      enabled: true
  
  security:
    enabled: true
    syscall_audit:
      enabled: true
    file_integrity:
      enabled: true
      paths:
        - /etc
        - /root
        - /home
      recursive: true
    container_escape:
      enabled: true
  
  profiling:
    enabled: true
    cpu: true
    memory: true
```

---

## Example: Performance-Optimized

```yaml
telegen:
  mode: agent
  log_level: warn

otlp:
  endpoint: "otel-collector:4317"
  compression: gzip

agent:
  ebpf:
    enabled: true
    ringbuf_size: 67108864  # 64MB
    perf_buffer_size: 16384  # 16KB
    
    network:
      enabled: true
      exclude_ports: [22, 2379, 2380]
    
    syscalls:
      enabled: false  # Disable for performance
  
  resources:
    cpu_limit: 2.0
    memory_limit: "1Gi"
    rate_limit:
      spans_per_second: 50000
      metrics_per_second: 100000
```

---

## Next Steps

- {doc}`collector-mode` - Remote collection without eBPF
- {doc}`environment-variables` - Environment variable reference
