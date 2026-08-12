# Kubernetes Metrics & Events Streaming

Telegen provides comprehensive Kubernetes observability by streaming kube-state-metrics, cadvisor metrics, and Kubernetes events directly to OTLP — no Prometheus scraping required.

---

## Overview

Telegen's Kubernetes integration supports three signal paths:

| Signal | Source | Export Method |
|--------|--------|--------------|
| **kube-state-metrics** | K8s API (pods, deployments, services, etc.) | OTLP streaming push |
| **cadvisor** | Node-level container metrics | OTLP streaming push |
| **K8s events** | K8s Event API (Normal/Warning) | OTLP logs |

All three share the same OTLP exporter configured in `exports.otlp`, and all signals include `telegen.*` metadata attributes for indexing and discovery.

---

## Kube-State-Metrics Streaming

Telegen replaces the traditional Prometheus-scraped kube-state-metrics deployment with a built-in streaming exporter.

### Configuration

```yaml
kube_metrics:
  enabled: true

  # Skip collection when the agent is not running inside a cluster
  auto_detect: true

  # Streaming OTLP export
  streaming:
    enabled: true
    interval: 30s          # Push interval
    batch_size: 100        # Max samples per batch
    flush_timeout: "5s"    # Max wait before flush
    use_otlp: true         # Use shared OTLP exporter

  # Object-state metrics
  kube_state:
    enabled: true
    resync_period: 30s

  # Container resource metrics
  cadvisor:
    enabled: true

  # Optional legacy scrape endpoint, for backward compatibility
  listen_address: ":8080"
  metrics_path: "/metrics"
```

### Metrics Collected

Telegen streams all standard kube-state-metrics:

| Resource | Metrics |
|----------|---------|
| **Pods** | `kube_pod_status_ready`, `kube_pod_status_scheduled`, `kube_pod_container_status_restarts_total` |
| **Deployments** | `kube_deployment_status_replicas`, `kube_deployment_spec_replicas` |
| **Nodes** | `kube_node_status_capacity`, `kube_node_status_allocatable` |
| **Services** | `kube_service_info` |
| **ConfigMaps/Secrets** | `kube_configmap_info`, `kube_secret_info` |
| **HPAs** | `kube_hpa_status_current_replicas`, `kube_hpa_spec_target_metric` |
| **PVCs** | `kube_persistentvolumeclaim_status_phase` |

### Signal Metadata

All K8s metrics include `telegen.*` attributes:

```yaml
metric:
  name: "kube_pod_status_ready"
  attributes:
    telegen.signal.category: "Kubernetes Metrics"
    telegen.signal.subcategory: "Pod Status"
    telegen.source.module: "internal/kubemetrics"
    telegen.collector.type: "k8s-api"
    k8s.pod.name: "my-app-xyz"
    k8s.namespace.name: "default"
```

---

## cadvisor Streaming

Container-level CPU, memory, network, and filesystem metrics are streamed from the node's cadvisor API.

### Configuration

cadvisor streaming is enabled automatically when `kube_metrics.enabled: true` and the agent is running on a Kubernetes node.

### Metrics Collected

| Category | Metrics |
|----------|---------|
| **CPU** | `container_cpu_usage_seconds_total`, `container_cpu_cfs_throttled_seconds_total` |
| **Memory** | `container_memory_usage_bytes`, `container_memory_working_set_bytes`, `container_memory_rss` |
| **Network** | `container_network_receive_bytes_total`, `container_network_transmit_bytes_total` |
| **Filesystem** | `container_fs_usage_bytes`, `container_fs_reads_bytes_total` |
| **Process** | `container_processes`, `container_threads` |

---

## Kubernetes Events as OTLP Logs

Telegen converts Kubernetes events (Normal/Warning) into OTLP log records, enabling event analysis alongside metrics and traces.

### Configuration

```yaml
kube_metrics:
  logs_streaming:
    enabled: true
    buffer_size: 1000        # Event buffer size
    flush_interval: "10s"    # Flush interval
    event_types: ["Normal", "Warning"]  # Filter by event type
    namespaces: []            # Empty = all namespaces
```

### Sample Event Log

```yaml
log_record:
  body: "Successfully pulled image \"nginx:latest\""
  severity: INFO
  attributes:
    k8s.event.type: "Normal"
    k8s.event.reason: "Pulled"
    k8s.event.count: 1
    k8s.event.first_timestamp: "2026-07-30T00:00:00Z"
    k8s.event.last_timestamp: "2026-07-30T00:00:00Z"
    k8s.pod.name: "my-app-xyz"
    k8s.namespace.name: "default"
    k8s.node.name: "node-1"
    telegen.signal.category: "Kubernetes Events"
```

### Event Types

| Event Type | Severity | Description |
|-----------|----------|-------------|
| `Normal` | INFO | Routine events (image pulls, scheduled pods, etc.) |
| `Warning` | WARN | Problem indicators (failed mounts, evicted pods, etc.) |

---

## Start-Order Independence

Telegen's `Provider.Start` method is **start-order independent**: `SetupStreaming` (which may run later) detects that `Start` already executed and immediately starts freshly-created streamers. This prevents subtle wiring-order bugs in complex deployments.

---

## Health Endpoints

Telegen exposes Kubernetes health and telemetry endpoints:

| Endpoint | Description |
|----------|-------------|
| `/healthz` | Health check with per-component status |
| `/metrics` | Prometheus-compatible metrics (legacy) |
| `/metrics/kubestate` | kube-state-metrics in Prometheus format |
| `/metrics/cadvisor` | cadvisor metrics in Prometheus format |
| `/telemetry` | Telegen self-telemetry counters |

### Telemetry Counters

| Counter | Description |
|---------|-------------|
| `kubemetrics_streaming_exports_total` | Total streaming export count |
| `kubemetrics_logs_events_received_total` | K8s events received |
| `kubemetrics_logs_events_exported_total` | K8s events exported as logs |

---

## Deployment

### DaemonSet (Agent Mode)

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: telegen
spec:
  template:
    spec:
      serviceAccountName: telegen
      containers:
      - name: telegen
        image: ghcr.io/mirastacklabs-ai/telegen:latest
        env:
        - name: otlp.endpoint
          value: "otel-collector:4317"
        - name: kube_metrics.enabled
          value: "true"
        - name: kube_metrics.streaming.enabled
          value: "true"
```

### RBAC

Telegen requires read-only access to the K8s API:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: telegen
rules:
- apiGroups: [""]
  resources: ["pods", "services", "nodes", "namespaces", "configmaps", "secrets", "endpoints", "persistentvolumeclaims", "replicationcontrollers"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["get", "list", "watch"]
```

---

## Configuration Reference

See {doc}`../configuration/full-reference` for the complete `kube_metrics` configuration schema.
