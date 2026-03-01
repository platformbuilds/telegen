# Helm Installation

Deploy Telegen using the official Helm chart for simplified configuration management.

## Prerequisites

- Helm 3.8+
- Kubernetes 1.21+
- Cluster admin permissions

---

## Quick Start

### Install from OCI Registry

```bash
helm install telegen oci://ghcr.io/mirastacklabs-ai/charts/telegen \
  --namespace telegen \
  --create-namespace \
  --set otlp.endpoint="otel-collector.observability:4317"
```

With a specific version:

```bash
helm install telegen oci://ghcr.io/mirastacklabs-ai/charts/telegen \
  --version 3.0.0 \
  --namespace telegen \
  --create-namespace \
  --set otlp.endpoint="otel-collector.observability:4317"
```

---

## Configuration

### Using Values File

Create a `values.yaml`:

```yaml
# Required: OTLP endpoint
otlp:
  endpoint: "otel-collector.observability:4317"
  protocol: "grpc"
  insecure: true

# Agent configuration
agent:
  enabled: true
  logLevel: INFO
  
  # eBPF settings
  ebpf:
    enabled: true
    network: true
    syscalls: true
    ringbufSize: "16Mi"
  
  # Profiling
  profiling:
    enabled: true
    sampleRate: 99
    cpu: true
    offCpu: true
    memory: true
  
  # Auto-discovery
  discovery:
    enabled: true
    interval: "30s"
    detectRuntimes: true
    detectDatabases: true
  
  # Security monitoring
  security:
    enabled: true
    syscallAudit: true
    fileIntegrity: true
    containerEscape: true

# Resources
resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

Install with values file:

```bash
helm install telegen telegen/telegen \
  --namespace telegen \
  --create-namespace \
  -f values.yaml
```

---

## Complete Values Reference

### OTLP Configuration

```yaml
otlp:
  # Primary endpoint (required)
  endpoint: "otel-collector:4317"
  protocol: "grpc"  # grpc or http
  insecure: true
  compression: "gzip"
  timeout: "10s"
  
  # Custom headers (e.g., for authentication)
  headers:
    Authorization: "Bearer ${OTEL_TOKEN}"
  
  # TLS configuration
  tls:
    enabled: false
    caFile: "/etc/ssl/certs/ca.crt"
    certFile: "/etc/ssl/certs/client.crt"
    keyFile: "/etc/ssl/certs/client.key"
    insecureSkipVerify: false
  
  # Per-signal configuration
  traces:
    enabled: true
    endpoint: ""  # Override main endpoint
    sampleRate: 1.0
  
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

### Agent Configuration

```yaml
agent:
  enabled: true
  serviceName: "telegen"
  logLevel: INFO  # DEBUG, INFO, WARN, ERROR
  logFormat: json
  shutdownTimeout: 10s
  
  # Host access (required for eBPF)
  hostPID: true
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  
  # Scheduling
  priorityClassName: system-node-critical
  
  tolerations:
    - operator: Exists
      effect: NoSchedule
    - operator: Exists
      effect: NoExecute
  
  nodeSelector: {}
  
  affinity: {}
  
  # Pod annotations
  podAnnotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "19090"
```

### eBPF Configuration

```yaml
agent:
  ebpf:
    enabled: true
    
    # Network tracing
    network:
      enabled: true
      http: true
      grpc: true
      dns: true
      tcpMetrics: true
    
    # Syscall tracing
    syscalls:
      enabled: true
      include: []  # Empty = all
      exclude:
        - futex
        - nanosleep
    
    # Process tracking
    process:
      enabled: true
      lifecycle: true
      fileOps: true
    
    # Buffer sizes
    ringbufSize: "16Mi"
    perfBufferSize: "8Ki"
```

### Profiling Configuration

```yaml
agent:
  profiling:
    enabled: true
    sampleRate: 99
    
    # Profile types
    cpu: true
    offCpu: true
    memory: true
    mutex: true
    block: true
    goroutine: true
    
    # Flame graph generation
    flameGraph:
      enabled: true
      format: "folded"
```

### Security Configuration

```yaml
agent:
  security:
    enabled: true
    
    # Syscall auditing
    syscallAudit:
      enabled: true
      syscalls:
        - execve
        - ptrace
        - setuid
        - mount
    
    # File integrity monitoring
    fileIntegrity:
      enabled: true
      paths:
        - /etc/passwd
        - /etc/shadow
        - /etc/sudoers
        - /root/.ssh
    
    # Container escape detection
    containerEscape:
      enabled: true
```

### Network Observability Configuration

```yaml
agent:
  network:
    enabled: true
    
    # XDP packet tracing
    xdp:
      enabled: true
      sampleRate: 1000
    
    # DNS tracing
    dns:
      enabled: true
      captureQueries: true
      captureResponses: true
    
    # TCP metrics
    tcp:
      enabled: true
      rtt: true
      retransmits: true
```

### Collector Mode

```yaml
collector:
  enabled: false  # Set to true for collector mode
  replicas: 2
  
  # SNMP configuration
  snmp:
    enabled: true
    pollInterval: "60s"
    targets: []
    
    trapReceiver:
      enabled: true
      listenAddress: ":162"
  
  # Storage arrays
  storage:
    enabled: false
    
    dell:
      enabled: false
      targets: []
    
    pure:
      enabled: false
      targets: []
    
    netapp:
      enabled: false
      targets: []
```

### Image Configuration

```yaml
image:
  repository: ghcr.io/mirastacklabs-ai/telegen
  tag: "latest"  # Or specific version like "3.0.0"
  pullPolicy: IfNotPresent

imagePullSecrets: []
```

### Service Account

```yaml
serviceAccount:
  create: true
  name: telegen
  annotations: {}

rbac:
  create: true
```

### Resources

```yaml
resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

### Self-Telemetry

```yaml
selfTelemetry:
  enabled: true
  port: 19090
  path: "/metrics"
  
  serviceMonitor:
    enabled: false
    interval: 30s
    labels: {}
```

### Health Checks

```yaml
healthCheck:
  port: 8080
  
  livenessProbe:
    enabled: true
    initialDelaySeconds: 10
    periodSeconds: 30
    failureThreshold: 3
  
  readinessProbe:
    enabled: true
    initialDelaySeconds: 5
    periodSeconds: 10
    failureThreshold: 3
```

---

## Common Configurations

### Production with TLS

```yaml
otlp:
  endpoint: "otel-collector.observability:4317"
  tls:
    enabled: true
    caFile: "/etc/ssl/certs/ca.crt"

agent:
  logLevel: WARN
  
  profiling:
    enabled: true
    sampleRate: 49  # Lower for production
  
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 2Gi
```

### Minimal Overhead

```yaml
agent:
  ebpf:
    network: true
    syscalls: false
  
  profiling:
    enabled: false
  
  security:
    enabled: false

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

### Security-Focused

```yaml
agent:
  security:
    enabled: true
    syscallAudit:
      enabled: true
    fileIntegrity:
      enabled: true
      paths:
        - /etc/passwd
        - /etc/shadow
        - /etc/sudoers
        - /etc/ssh/sshd_config
        - /root/.ssh
        - /etc/kubernetes
    containerEscape:
      enabled: true
```

---

## Upgrade

```bash
helm upgrade telegen oci://ghcr.io/mirastacklabs-ai/charts/telegen \
  --namespace telegen \
  -f values.yaml
```

## Uninstall

```bash
helm uninstall telegen --namespace telegen
kubectl delete namespace telegen
```

---

## Next Steps

- {doc}`../configuration/full-reference` - Complete configuration reference
- {doc}`../features/index` - Explore features
