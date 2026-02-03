# Kubernetes Native Metrics Integration - Engineering Documentation

## Overview

This document describes the native integration of kube-state-metrics and cAdvisor equivalent functionality into Telegen. This eliminates the need for separate deployments while providing comprehensive Kubernetes observability.

**One Agent, Many Signals** - Kubernetes metrics are integrated directly into the Telegen agent configuration, not as a separate component.

## Auto-Detection

When `kube_metrics.auto_detect: true` (default), Telegen automatically enables Kubernetes metrics collection when:

1. Running inside a Kubernetes cluster (in-cluster config available)
2. `kubernetes.enable: true` in the configuration

This means no additional configuration is needed for basic K8s observability - just deploy Telegen as a DaemonSet.

## Configuration

Kubernetes metrics are configured in the main `telegen.yaml` (or `telegen-full.yaml`) under the `kube_metrics` section:

```yaml
# Main telegen configuration
kubernetes:
  enable: true  # Enables K8s metadata decoration

kube_metrics:
  enabled: true          # Explicitly enable, or use auto_detect
  auto_detect: true      # Auto-enable when running in K8s cluster
  listen_address: ":9443"
  separate_endpoints: true
  
  kube_state:
    enabled: true
    resources:
      - pods
      - deployments
      - nodes
      # ... see full config for all resources
    namespaces_exclude:
      - kube-system
  
  cadvisor:
    enabled: true
    collect_interval: 10s
  
  streaming:
    enabled: false       # OTLP push (in addition to HTTP pull)
  
  logs_streaming:
    enabled: false       # K8s events as OTLP logs
  
  signal_metadata:
    enabled: true        # telegen.* attributes
```

## Architecture

### Components

1. **kubestate** (`internal/kubestate/`) - kube-state-metrics equivalent
   - Provides ~200 metrics about Kubernetes object state
   - Uses client-go informers for efficient API watching
   - Supports sharding via Jump Consistent Hash

2. **cadvisor** (`internal/cadvisor/`) - cAdvisor equivalent
   - Provides container resource utilization metrics
   - Reads directly from cgroups v1/v2 filesystem
   - No dependency on kubelet metrics endpoint

3. **kubemetrics** (`internal/kubemetrics/`) - Unified provider
   - Combines kubestate and cadvisor
   - Provides unified HTTP endpoints

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Telegen DaemonSet                           │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐    ┌──────────────────┐                       │
│  │    kubestate     │    │     cadvisor     │                       │
│  │                  │    │                  │                       │
│  │  ┌────────────┐  │    │  ┌────────────┐  │                       │
│  │  │ Informers  │  │    │  │  cgroup    │  │                       │
│  │  │ (client-go)│  │    │  │  reader    │  │                       │
│  │  └─────┬──────┘  │    │  └─────┬──────┘  │                       │
│  │        │         │    │        │         │                       │
│  │  ┌─────▼──────┐  │    │  ┌─────▼──────┐  │                       │
│  │  │ Generators │  │    │  │ Collectors │  │                       │
│  │  └─────┬──────┘  │    │  └─────┬──────┘  │                       │
│  │        │         │    │        │         │                       │
│  │  ┌─────▼──────┐  │    │  ┌─────▼──────┐  │                       │
│  │  │   Stores   │  │    │  │   Stats    │  │                       │
│  │  └─────┬──────┘  │    │  └─────┬──────┘  │                       │
│  └────────┼─────────┘    └────────┼─────────┘                       │
│           │                       │                                  │
│           └───────────┬───────────┘                                  │
│                       ▼                                              │
│              ┌────────────────┐                                      │
│              │  HTTP Handler  │ :9443/metrics                        │
│              └────────┬───────┘                                      │
└───────────────────────┼─────────────────────────────────────────────┘
                        │
                        ▼
               ┌────────────────┐
               │   Prometheus   │
               └────────────────┘
```

## Package Structure

```
internal/
├── kubestate/
│   ├── config.go                 # Configuration with validation
│   ├── metric.go                 # Metric types, Prometheus serialization
│   ├── generator.go              # FamilyGenerator pattern, filters
│   ├── metrics_store.go          # cache.Store implementation
│   ├── kubestate.go              # Main orchestrator
│   ├── helpers.go                # Helper functions (resourceValue, etc.)
│   ├── sharding/
│   │   └── sharding.go           # Jump Consistent Hash
│   │
│   │ # Resource Collectors (~200 metrics total)
│   ├── pod_collector.go          # 35 generators
│   ├── deployment_collector.go   # 15 generators
│   ├── node_collector.go         # 10 generators
│   ├── statefulset_collector.go  # 12 generators
│   ├── daemonset_collector.go    # 11 generators
│   ├── replicaset_collector.go   # 9 generators
│   ├── job_collector.go          # 14 generators
│   ├── cronjob_collector.go      # 10 generators
│   ├── service_collector.go      # 6 generators
│   ├── namespace_collector.go    # 5 generators
│   ├── pvc_collector.go          # 7 generators
│   ├── pv_collector.go           # 6 generators
│   ├── configmap_collector.go    # 3 generators
│   ├── secret_collector.go       # 5 generators
│   ├── hpa_collector.go          # 10 generators
│   ├── ingress_collector.go      # 6 generators
│   ├── endpoints_collector.go    # 11 generators
│   └── kubestate_test.go         # Unit tests
│
├── cadvisor/
│   ├── config.go                 # Configuration
│   ├── cgroup.go                 # cgroups v1/v2 reader
│   ├── network.go                # Network and filesystem stats
│   ├── collector.go              # Main collector, HTTP handler
│   └── cadvisor_test.go          # Unit tests
│
├── kubemetrics/
│   ├── kubemetrics.go            # Unified provider
│   ├── streaming.go              # OTLP streaming export
│   ├── logs_streaming.go         # K8s events → OTLP logs
│   └── signal_metadata.go        # telegen.* metadata definitions
│
└── config/
    └── kubemetrics.go            # Telegen config integration
```

## Export Modes

### Mode 1: HTTP/Prometheus Pull (Default)

Standard Prometheus scrape model:

```
┌─────────────────┐         ┌─────────────────┐
│    Telegen      │◀───────│   Prometheus    │
│  :9443/metrics  │  scrape │                 │
└─────────────────┘         └─────────────────┘
```

### Mode 2: OTLP Push (Streaming)

Push metrics directly to OTLP-compatible collectors:

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│    Telegen      │────────▶│ OTEL Collector  │────────▶│   Backend       │
│  kubemetrics    │  OTLP   │  (or compatible)│  export │ (Prometheus,    │
│  streaming      │         │                 │         │  Datadog, etc)  │
└─────────────────┘         └─────────────────┘         └─────────────────┘
```

### Mode 3: K8s Events as OTLP Logs

Stream Kubernetes events as structured OTLP logs:

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  K8s API Server │────────▶│    Telegen      │────────▶│ OTEL Collector  │
│    Events       │  watch  │  logs_streaming │  OTLP   │                 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
```

## Signal Metadata

All kubemetrics signals include configurable `telegen.*` attributes for indexing and discovery:

| Attribute | Description | Example |
|-----------|-------------|---------|
| `telegen.signal.category` | Top-level category | "Kubernetes State", "Container Metrics" |
| `telegen.signal.subcategory` | Sub-category | "Pod Metrics", "CPU Utilization" |
| `telegen.source.module` | Go source module | "github.com/telegen/telegen/internal/kubestate" |
| `telegen.collector.type` | Collection method | "api", "procfs" |
| `telegen.signal.description` | Human-readable description | "Pod state and status metrics from Kubernetes API" |

### Metadata Configuration

```yaml
signal_metadata:
  enabled: true
  fields:
    enable_category: true
    enable_subcategory: true
    enable_source_module: true
    enable_collector_type: true
    enable_description: false  # Verbose, disabled by default
```

### Metadata Definitions by Metric Prefix

| Metric Prefix | Category | SubCategory | CollectorType |
|---------------|----------|-------------|---------------|
| `kube_pod_*` | Kubernetes State | Pod Metrics | api |
| `kube_deployment_*` | Kubernetes State | Deployment Metrics | api |
| `kube_node_*` | Kubernetes State | Node Metrics | api |
| `container_cpu_*` | Container Metrics | CPU Utilization | procfs |
| `container_memory_*` | Container Metrics | Memory Utilization | procfs |
| `container_network_*` | Container Metrics | Network Utilization | procfs |
| `container_fs_*` | Container Metrics | Disk Utilization | procfs |

## Metrics Summary

### kubestate Metrics (~200)

| Resource | Metric Count | Key Metrics |
|----------|--------------|-------------|
| Pods | 35 | info, phase, ready, container_status_*, resource_requests/limits, restarts |
| Deployments | 15 | created, replicas, available, unavailable, condition |
| Nodes | 10 | info, labels, role, unschedulable, taint, condition, capacity |
| StatefulSets | 12 | replicas, available, current, updated, revision |
| DaemonSets | 11 | current_scheduled, desired_scheduled, available, ready |
| ReplicaSets | 9 | replicas, fully_labeled, ready, spec_replicas, owner |
| Jobs | 14 | parallelism, completions, active, succeeded, failed, duration |
| CronJobs | 10 | status_active, last_schedule_time, spec_suspend |
| Services | 6 | info, type, external_ip, load_balancer |
| Namespaces | 5 | created, labels, phase, condition |
| PVCs | 7 | phase, storage_bytes, access_mode, condition |
| PVs | 6 | phase, capacity_bytes, claim_ref |
| ConfigMaps | 3 | info, created, resource_version |
| Secrets | 5 | info, type, labels, resource_version |
| HPAs | 10 | spec_max/min_replicas, target_metric, current/desired_replicas |
| Ingresses | 6 | info, labels, path, tls |
| Endpoints | 11 | address_available, address_not_ready, ports, endpointslice_* |

### cadvisor Metrics (~20)

| Category | Metrics |
|----------|---------|
| CPU | container_cpu_usage_seconds_total, container_cpu_user_seconds_total, container_cpu_system_seconds_total, container_cpu_cfs_throttled_periods_total, container_cpu_cfs_throttled_seconds_total |
| Memory | container_memory_usage_bytes, container_memory_working_set_bytes, container_memory_rss, container_memory_cache, container_memory_swap, container_memory_max_usage_bytes, container_memory_failcnt, container_oom_events_total |
| Disk I/O | container_fs_reads_bytes_total, container_fs_writes_bytes_total, container_fs_reads_total, container_fs_writes_total |
| Network | container_network_receive_bytes_total, container_network_transmit_bytes_total, container_network_receive_packets_total, container_network_transmit_packets_total, container_network_receive_errors_total, container_network_transmit_errors_total, container_network_receive_packets_dropped_total, container_network_transmit_packets_dropped_total |

## Key Design Patterns

### 1. FamilyGenerator Pattern (from kube-state-metrics)

Each metric is defined as a `FamilyGenerator`:

```go
NewFamilyGenerator(
    "kube_pod_info",                    // Metric name
    "Information about pod.",           // Help text
    Info,                               // Metric type
    StabilityStable,                    // Stability level
    func(obj interface{}) *Family {     // Generator function
        pod := obj.(*corev1.Pod)
        return &Family{
            Metrics: []*Metric{{
                LabelKeys:   []string{"namespace", "pod", "node"},
                LabelValues: []string{pod.Namespace, pod.Name, pod.Spec.NodeName},
                Value:       1,
            }},
        }
    },
)
```

### 2. MetricsStore with Informers

The `MetricsStore` implements `cache.Store` interface:

```go
type MetricsStore struct {
    mu               sync.RWMutex
    metrics          map[string][]byte  // UID -> serialized metrics
    headers          []byte             // HELP/TYPE headers
    generateMetrics  func(obj interface{}) []byte
}
```

Informers push Add/Update/Delete events:
```go
informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
    AddFunc:    func(obj interface{}) { store.Add(obj) },
    UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
    DeleteFunc: func(obj interface{}) { store.Delete(obj) },
})
```

### 3. Jump Consistent Hash for Sharding

```go
func JumpConsistentHash(key uint64, numBuckets int32) int32 {
    var b, j int64 = -1, 0
    for j < int64(numBuckets) {
        b = j
        key = key*2862933555777941757 + 1
        j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
    }
    return int32(b)
}
```

### 4. Direct cgroups Reading

Instead of scraping kubelet's /metrics/cadvisor, we read cgroups directly:

```go
// cgroups v2
cpuStatPath := filepath.Join(cgroupRoot, cgroupPath, "cpu.stat")
memCurrentPath := filepath.Join(cgroupRoot, cgroupPath, "memory.current")
ioStatPath := filepath.Join(cgroupRoot, cgroupPath, "io.stat")
```

Benefits:
- No network overhead
- No authentication needed
- Works even if kubelet is unresponsive
- Faster collection

## Configuration

```yaml
kube_metrics:
  enabled: true
  listen_address: ":9443"
  
  kube_state:
    enabled: true
    resources:
      - pods
      - deployments
      - nodes
    namespaces_exclude:
      - kube-system
    resync_period: 5m
    shard: 0
    total_shards: 1
    
  cadvisor:
    enabled: true
    cgroup_root: "/sys/fs/cgroup"
    collect_interval: 10s
    disk_io_enabled: true
    network_enabled: true
```

## Implementation Phases

### Phase 1: Vanilla Kubernetes (COMPLETED ✅)

- [x] Core infrastructure (config, metric, generator, store)
- [x] All 17 resource collectors
- [x] Jump Consistent Hash sharding
- [x] cgroups v1/v2 reading
- [x] Prometheus exposition format
- [x] Configuration integration
- [x] Unit tests

### Phase 2: Enterprise Kubernetes (PLANNED)

- [ ] OpenShift-specific resources (Routes, DeploymentConfigs, etc.)
- [ ] VMware Tanzu-specific resources
- [ ] Custom Resource State support
- [ ] Operator metrics

### Phase 3: Advanced Features (PLANNED)

- [ ] Vertical Pod Autoscaler metrics
- [ ] Custom metrics adapters
- [ ] Multi-cluster support
- [ ] Enhanced labeling (pod annotations as labels)

## Deployment

Telegen runs as a DaemonSet with:

```yaml
securityContext:
  privileged: true  # Required for cgroups access
  
volumeMounts:
  - name: sys-fs-cgroup
    mountPath: /sys/fs/cgroup
    readOnly: true
  - name: proc
    mountPath: /proc
    readOnly: true

volumes:
  - name: sys-fs-cgroup
    hostPath:
      path: /sys/fs/cgroup
  - name: proc
    hostPath:
      path: /proc
```

## Prometheus Scrape Configuration

```yaml
scrape_configs:
  # Combined endpoint
  - job_name: 'telegen-kubemetrics'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: telegen
      - source_labels: [__address__]
        target_label: __address__
        regex: ([^:]+):\d+
        replacement: ${1}:9443

  # Separate endpoints (if separate_endpoints: true)
  - job_name: 'telegen-kubestate'
    metrics_path: /metrics/kubestate
    # ... same SD config

  - job_name: 'telegen-cadvisor'
    metrics_path: /metrics/cadvisor
    # ... same SD config
```

## Testing

Run the unit tests:

```bash
go test ./internal/kubestate/...
go test ./internal/cadvisor/...
```

## Migration from kube-state-metrics + cAdvisor

1. Deploy Telegen with kube_metrics enabled
2. Update Prometheus to scrape Telegen endpoints
3. Verify metric parity with Grafana dashboards
4. Remove kube-state-metrics deployment
5. (Optional) Disable kubelet cAdvisor scraping

## Compatibility

- Kubernetes: 1.25+
- cgroups: v1 and v2
- Container runtimes: containerd, CRI-O, Docker
- Prometheus client format: 0.0.4
