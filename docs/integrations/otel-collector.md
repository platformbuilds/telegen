# OpenTelemetry Collector Integration

How to configure Telegen with OpenTelemetry Collector.

## Overview

The OpenTelemetry Collector acts as a central pipeline for receiving, processing, and exporting telemetry data. Telegen exports directly to the Collector via OTLP.

```
┌─────────────┐     OTLP      ┌─────────────────────┐     Various     ┌──────────┐
│   Telegen   │──────────────▶│  OTel Collector     │────────────────▶│ Backends │
│   (Agent)   │               │  (Gateway)          │                 │          │
└─────────────┘               └─────────────────────┘                 └──────────┘
```

---

## Basic Setup

### Telegen Configuration

```yaml
otlp:
  endpoint: "otel-collector:4317"
  insecure: true
  
  traces:
    enabled: true
  metrics:
    enabled: true
  logs:
    enabled: true
```

### Collector Configuration

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 5s
    send_batch_size: 512

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
```

---

## Deployment Patterns

### Sidecar Pattern

Collector runs alongside Telegen on each node:

```yaml
# Kubernetes DaemonSet
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: telegen-collector
spec:
  template:
    spec:
      containers:
        - name: telegen
          image: ghcr.io/mirastacklabs-ai/telegen:latest
          env:
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "localhost:4317"
        
        - name: otel-collector
          image: otel/opentelemetry-collector-contrib:latest
          ports:
            - containerPort: 4317
```

### Gateway Pattern

Centralized collector cluster:

```yaml
# Telegen on each node
otlp:
  endpoint: "otel-collector.monitoring.svc:4317"
```

```yaml
# Collector Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
  namespace: monitoring
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: collector
          image: otel/opentelemetry-collector-contrib:latest
```

---

## Collector Processing

### Memory Limiter

Protect collector from OOM:

```yaml
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 1024
    spike_limit_mib: 256

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [...]
```

### Tail-Based Sampling

Intelligent sampling in collector:

```yaml
processors:
  tail_sampling:
    decision_wait: 30s
    num_traces: 100000
    policies:
      - name: errors
        type: status_code
        status_code:
          status_codes: [ERROR]
      
      - name: slow-requests
        type: latency
        latency:
          threshold_ms: 1000
      
      - name: probabilistic
        type: probabilistic
        probabilistic:
          sampling_percentage: 10

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, tail_sampling, batch]
      exporters: [...]
```

### Resource Detection

Enrich with infrastructure metadata:

```yaml
processors:
  resourcedetection:
    detectors: [env, system, docker, gcp, aws, azure]
    timeout: 5s
    override: false
  
  k8sattributes:
    auth_type: "serviceAccount"
    passthrough: false
    extract:
      metadata:
        - k8s.pod.name
        - k8s.namespace.name
        - k8s.deployment.name
        - k8s.node.name
```

### Transform Processor

Modify telemetry data:

```yaml
processors:
  transform:
    trace_statements:
      - context: span
        statements:
          # Add custom attribute
          - set(attributes["env"], "production")
          # Truncate long attribute values
          - truncate_all(attributes, 4096)
          
    metric_statements:
      - context: metric
        statements:
          # Rename metric
          - set(name, Concat([name, "_renamed"], "")) where name == "old_metric"
```

---

## Multi-Tenant Setup

### Per-Tenant Headers

```yaml
# Telegen config for tenant-a
otlp:
  endpoint: "otel-collector:4317"
  headers:
    X-Tenant-ID: "tenant-a"
```

### Collector Routing

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  routing:
    from_attribute: X-Tenant-ID
    table:
      - value: tenant-a
        exporters: [exporter-tenant-a]
      - value: tenant-b
        exporters: [exporter-tenant-b]

exporters:
  otlp/tenant-a:
    endpoint: "backend-a:4317"
  otlp/tenant-b:
    endpoint: "backend-b:4317"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [routing]
      exporters: [otlp/tenant-a, otlp/tenant-b]
```

---

## Load Balancing

### Collector Behind Load Balancer

```yaml
# Telegen
otlp:
  endpoint: "otel-collector-lb.monitoring.svc:4317"
  
# Use gRPC load balancing
otlp:
  endpoint: "dns:///otel-collector-headless.monitoring.svc:4317"
```

### Kubernetes Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: otel-collector
spec:
  type: ClusterIP
  ports:
    - port: 4317
      targetPort: 4317
  selector:
    app: otel-collector
---
# Headless for DNS load balancing
apiVersion: v1
kind: Service
metadata:
  name: otel-collector-headless
spec:
  clusterIP: None
  ports:
    - port: 4317
  selector:
    app: otel-collector
```

---

## High Availability

### Collector with Kafka

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  kafka:
    brokers:
      - kafka-0:9092
      - kafka-1:9092
      - kafka-2:9092
    topic: telemetry-traces
    encoding: otlp_proto

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [kafka]
```

### Consumer Collector

```yaml
receivers:
  kafka:
    brokers:
      - kafka-0:9092
    topic: telemetry-traces
    encoding: otlp_proto
    group_id: otel-consumer

exporters:
  otlp:
    endpoint: "backend:4317"

service:
  pipelines:
    traces:
      receivers: [kafka]
      processors: [batch]
      exporters: [otlp]
```

---

## Security

### TLS Configuration

```yaml
# Telegen
otlp:
  endpoint: "otel-collector:4317"
  tls:
    ca_file: "/etc/tls/ca.crt"
    cert_file: "/etc/tls/client.crt"
    key_file: "/etc/tls/client.key"
```

```yaml
# Collector
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls:
          cert_file: /etc/tls/server.crt
          key_file: /etc/tls/server.key
          client_ca_file: /etc/tls/ca.crt
```

### Authentication

```yaml
# Telegen with bearer token
otlp:
  endpoint: "otel-collector:4317"
  headers:
    Authorization: "Bearer ${OTEL_TOKEN}"
```

```yaml
# Collector with auth extension
extensions:
  bearertokenauth:
    token: "${OTEL_TOKEN}"

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        auth:
          authenticator: bearertokenauth
```

---

## Profiles (OTLP Profiles)

For continuous profiling data:

```yaml
# Collector receiving profiles
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  otlp/pyroscope:
    endpoint: "pyroscope:4317"

service:
  pipelines:
    profiles:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/pyroscope]
```

---

## Example: Complete Production Setup

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 2048
  
  batch:
    timeout: 5s
    send_batch_size: 1024
  
  resource:
    attributes:
      - key: environment
        value: production
        action: upsert
  
  filter:
    spans:
      exclude:
        match_type: regexp
        attributes:
          - key: http.target
            value: "^/health.*"

exporters:
  otlp/traces:
    endpoint: "tempo:4317"
    tls:
      insecure: true
  
  prometheusremotewrite:
    endpoint: "http://mimir:9009/api/v1/push"
  
  loki:
    endpoint: "http://loki:3100/loki/api/v1/push"

service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, filter, resource, batch]
      exporters: [otlp/traces]
    
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [prometheusremotewrite]
    
    logs:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [loki]

extensions:
  health_check:
    endpoint: 0.0.0.0:13133
```

---

## Next Steps

- {doc}`backends` - Configure specific backends
- {doc}`../operations/monitoring` - Monitor the collector
- {doc}`../operations/performance-tuning` - Tune collector performance
