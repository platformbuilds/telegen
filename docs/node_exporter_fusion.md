# Node Exporter Fusion

Telegen includes a fully integrated node_exporter compatibility layer that makes it a drop-in replacement for Prometheus node_exporter. This document describes the architecture, configuration, and usage.

## Overview

The node_exporter fusion feature provides:

- **100% Prometheus Compatibility**: Metrics use the standard `node_` namespace and are fully compatible with Prometheus scrape configs, Grafana dashboards, and alerting rules designed for node_exporter.
- **Drop-in Replacement**: Runs on port 9100 by default, the same port as node_exporter.
- **19 Collectors**: Complete system metrics coverage including CPU, memory, disk, network, filesystem, and more.
- **Configuration-Driven**: YAML-based configuration integrated with telegen's configuration system.
- **Streaming Metrics**: Telegen-compliant metric streaming at configurable intervals to OTLP endpoints.
- **Environment Aware**: Automatically detects bare metal, virtual machine, Kubernetes, or container deployments.

## Quick Start

Enable node_exporter in your telegen configuration:

```yaml
node_exporter:
  enabled: true
```

That's it! Telegen will now expose node_exporter compatible metrics on port 9100.

## Streaming Metrics (Telegen Compliant)

Unlike traditional node_exporter which only exposes a pull-based `/metrics` endpoint, telegen's node_exporter fusion supports push-based streaming to OTLP endpoints:

```yaml
node_exporter:
  enabled: true
  
  # Streaming export configuration
  export:
    # Enable streaming metrics to OTLP endpoint
    enabled: true
    # Collection and export interval (how often metrics are pushed)
    interval: 15s
    # Use telegen's configured OTLP exporter
    use_otlp: true
    # Batch size for export
    batch_size: 1000
    # Flush timeout
    flush_timeout: 5s
```

This enables telegen to:
- Push metrics at regular intervals (configurable via `interval`)
- Integrate with telegen's main OTLP export pipeline
- Batch metrics efficiently for network transport

## Environment Detection

Telegen automatically detects the deployment environment and adds appropriate labels:

```yaml
node_exporter:
  enabled: true
  
  environment:
    # auto, bare_metal, virtual_machine, kubernetes, container
    type: "auto"
    auto_detect: true
    
    # Kubernetes-specific (auto-populated from downward API)
    kubernetes:
      node_name: "${NODE_NAME}"
      namespace: "${POD_NAMESPACE}"
      pod_name: "${POD_NAME}"
      cluster_name: "${CLUSTER_NAME}"
      include_node_labels: false
      include_pod_labels: false
    
    # Additional labels for all metrics
    labels:
      datacenter: "us-west-2"
      environment: "production"
```

### Detected Environments

| Environment | Detection Method |
|-------------|-----------------|
| **Kubernetes** | `KUBERNETES_SERVICE_HOST` env, service account token, downward API |
| **Container** | `/.dockerenv`, cgroup containing "docker", "containerd", or "lxc" |
| **Virtual Machine** | `/sys/class/dmi/id/product_name` containing VMware, VirtualBox, KVM, Xen, Hyper-V |
| **Bare Metal** | Default when no virtualization detected |

## Full Configuration Example

```yaml
node_exporter:
  # Enable node_exporter compatible metrics
  enabled: true
  
  # Metric namespace (default: "node" for compatibility)
  namespace: "node"
  
  # Filesystem paths
  paths:
    procfs: "/proc"
    sysfs: "/sys"
    rootfs: "/"
    udev_data: "/run/udev/data"
  
  # HTTP endpoint
  endpoint:
    port: 9100
    path: "/metrics"
  
  # Scrape settings
  scrape:
    timeout: 20s
  
  # Streaming export
  export:
    enabled: true
    interval: 15s
    use_otlp: true
  
  # Environment detection
  environment:
    type: "auto"
    auto_detect: true
  
  # Collector configuration
  collectors:
    cpu:
      enabled: true
      enable_guest: false
      enable_info: true
    meminfo: true
    loadavg: true
    diskstats:
      enabled: true
    filesystem:
      enabled: true
      mount_timeout: 5s
    netdev:
      enabled: true
    stat:
      enabled: true
    uname: true
    time: true
    vmstat: true
    netstat: true
    conntrack: true
    pressure: true
    entropy: true
    sockstat: true
    thermal: true
    hwmon: false  # Disabled by default (heavyweight)
    textfile:
      enabled: false
      directory: "/var/lib/node_exporter/textfile_collector"
```

## Implemented Collectors

| Collector | Default | Description |
|-----------|---------|-------------|
| `cpu` | Enabled | CPU usage per core, info (model, flags, bugs) |
| `meminfo` | Enabled | Memory usage from /proc/meminfo (50+ metrics) |
| `loadavg` | Enabled | System load averages (1m, 5m, 15m) |
| `diskstats` | Enabled | Disk I/O statistics (reads, writes, time) |
| `filesystem` | Enabled | Filesystem usage (size, free, available) |
| `netdev` | Enabled | Network device statistics (rx/tx bytes, packets, errors) |
| `stat` | Enabled | System statistics (boot time, context switches, forks) |
| `uname` | Enabled | System identification (kernel, hostname) |
| `time` | Enabled | System time and clocksource |
| `vmstat` | Enabled | Virtual memory statistics (page faults, swap) |
| `netstat` | Enabled | Network protocol statistics (TCP, UDP, IP) |
| `conntrack` | Enabled | Connection tracking (netfilter) |
| `pressure` | Enabled | PSI (Pressure Stall Information) for CPU, memory, I/O |
| `entropy` | Enabled | Entropy pool available bits |
| `sockstat` | Enabled | Socket statistics (TCP/UDP in use, orphan, memory) |
| `thermal` | Enabled | Thermal zones and cooling devices |
| `filefd` | Enabled | File descriptor limits |
| `hwmon` | Disabled | Hardware monitoring (temperatures, fans, voltages) |
| `textfile` | Disabled | Custom metrics from .prom files |

## Endpoints

When enabled, the following endpoints are available on the node_exporter port (default 9100):

| Endpoint | Description |
|----------|-------------|
| `/metrics` | Prometheus metrics in OpenMetrics format |
| `/health` | JSON health status with collector count |
| `/ready` | Readiness check (returns 200 when collectors are initialized) |
| `/live` | Liveness check (always returns 200 if process is running) |
| `/` | Landing page with links to other endpoints |

## Prometheus Scrape Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
```

## Grafana Dashboard Compatibility

The node_exporter metrics are fully compatible with standard Grafana dashboards:

- **Node Exporter Full** (Dashboard ID: 1860)
- **Node Exporter Quickstart** (Dashboard ID: 13978)
- **Linux Server Monitoring** (Dashboard ID: 14513)

Simply point these dashboards at your telegen instance.

## Architecture

The node_exporter fusion is implemented in `internal/nodeexporter/`:

```
internal/nodeexporter/
├── config.go           # Configuration types
├── exporter.go         # Main exporter with HTTP server
└── collector/
    ├── collector.go    # Collector interface and NodeCollector
    ├── registry.go     # Factory registration pattern
    ├── paths.go        # Path helpers for /proc and /sys
    ├── types.go        # Shared configuration types
    ├── device_filter.go # Regex-based device filtering
    ├── loadavg.go      # Load average collector
    ├── cpu_linux.go    # CPU metrics collector
    ├── meminfo_linux.go # Memory info collector
    ├── diskstats_linux.go # Disk I/O collector
    ├── filesystem_linux.go # Filesystem collector
    ├── netdev_linux.go # Network device collector
    ├── stat_linux.go   # System stat collector
    ├── uname_linux.go  # Uname collector
    ├── time_linux.go   # Time collector
    ├── vmstat_linux.go # Virtual memory collector
    ├── netstat_linux.go # Network protocol collector
    ├── conntrack_linux.go # Connection tracking collector
    ├── pressure_linux.go # PSI collector
    ├── filefd_linux.go # File descriptor collector
    ├── entropy_linux.go # Entropy collector
    ├── sockstat_linux.go # Socket statistics collector
    ├── thermal_zone_linux.go # Thermal zone collector
    ├── hwmon_linux.go  # Hardware monitoring collector
    └── textfile.go     # Textfile collector
```

## Comparison with node_exporter

| Feature | node_exporter | telegen |
|---------|--------------|---------|
| Core collectors | ✅ 100+ | ✅ 19 (most common) |
| Port 9100 | ✅ | ✅ |
| /metrics endpoint | ✅ | ✅ |
| OpenMetrics format | ✅ | ✅ |
| Health endpoints | ❌ | ✅ |
| YAML config | ❌ (flags only) | ✅ |
| eBPF traces | ❌ | ✅ |
| Application metrics | ❌ | ✅ |
| Log collection | ❌ | ✅ |
| JFR profiling | ❌ | ✅ |
| Network flows | ❌ | ✅ |

## Migration from node_exporter

1. Install telegen alongside node_exporter
2. Configure telegen with `node_exporter.enabled: true`
3. Verify metrics match: `curl localhost:9100/metrics | head -100`
4. Update Prometheus targets if using a different port
5. Remove node_exporter

## Troubleshooting

### Metrics not appearing

Check the exporter is enabled and running:
```bash
curl localhost:9100/health
```

### Collector errors

Check logs for collector-specific errors. Some collectors may fail gracefully if the underlying system feature is not available (e.g., conntrack on systems without netfilter).

### Port conflict

If node_exporter is already running on port 9100, either:
- Stop node_exporter: `systemctl stop node_exporter`
- Change telegen's port: `node_exporter.endpoint.port: 9101`
