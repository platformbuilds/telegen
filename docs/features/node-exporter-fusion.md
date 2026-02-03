# Node Exporter Fusion

Telegen includes a drop-in replacement for Prometheus node_exporter, providing full compatibility with existing dashboards and alerts.

## Overview

Node Exporter Fusion provides:

- **120+ system metrics** - Full node_exporter compatibility
- **`node_*` namespace** - Works with existing dashboards
- **Zero configuration** - Automatically enabled
- **eBPF enhanced** - Additional metrics via eBPF

---

## Compatibility

Telegen replaces node_exporter while maintaining full compatibility:

| Feature | node_exporter | Telegen |
|---------|---------------|---------|
| Metric namespace | `node_*` | `node_*` ✅ |
| Grafana dashboards | ✅ | ✅ |
| Alert rules | ✅ | ✅ |
| Prometheus scraping | `/metrics` | `/metrics` ✅ |
| Collectors | 50+ | 50+ ✅ |

---

## Collectors

### P0 Collectors (Always Enabled)

| Collector | Metrics | Description |
|-----------|---------|-------------|
| **loadavg** | 3 | `node_load1`, `node_load5`, `node_load15` |
| **cpu** | 15+ per core | CPU time per mode, frequency, info |
| **meminfo** | 50+ | Memory statistics from `/proc/meminfo` |
| **diskstats** | 17+ per device | Disk I/O statistics |
| **filesystem** | 8 per mount | Filesystem space and inodes |
| **netdev** | 25+ per interface | Network device statistics |
| **stat** | 16 | Boot time, context switches, interrupts |

### Sample Metrics

```promql
# Load averages
node_load1
node_load5
node_load15

# CPU usage per mode
node_cpu_seconds_total{mode="user"}
node_cpu_seconds_total{mode="system"}
node_cpu_seconds_total{mode="idle"}
node_cpu_seconds_total{mode="iowait"}

# Memory
node_memory_MemTotal_bytes
node_memory_MemFree_bytes
node_memory_MemAvailable_bytes
node_memory_Buffers_bytes
node_memory_Cached_bytes
node_memory_SwapTotal_bytes
node_memory_SwapFree_bytes

# Disk I/O
node_disk_read_bytes_total
node_disk_written_bytes_total
node_disk_reads_completed_total
node_disk_writes_completed_total
node_disk_io_time_seconds_total
node_disk_read_time_seconds_total
node_disk_write_time_seconds_total

# Filesystem
node_filesystem_size_bytes
node_filesystem_free_bytes
node_filesystem_avail_bytes
node_filesystem_files
node_filesystem_files_free

# Network
node_network_receive_bytes_total
node_network_transmit_bytes_total
node_network_receive_packets_total
node_network_transmit_packets_total
node_network_receive_errs_total
node_network_transmit_errs_total
node_network_receive_drop_total
node_network_transmit_drop_total

# System
node_boot_time_seconds
node_context_switches_total
node_forks_total
node_intr_total
node_procs_running
node_procs_blocked
```

---

## Configuration

### Enable/Disable Collectors

```yaml
agent:
  nodeexporter:
    enabled: true
    
    # Listen address for /metrics endpoint
    listen_address: ":9100"
    
    # Metric namespace (default: node)
    namespace: "node"
    
    # Collectors to enable
    collectors:
      loadavg: true
      cpu: true
      meminfo: true
      diskstats: true
      filesystem: true
      netdev: true
      stat: true
      
      # P1 collectors
      netstat: true
      sockstat: true
      vmstat: true
      
      # P2 collectors
      hwmon: false      # Hardware monitoring
      thermal: false    # Thermal zones
      pressure: true    # PSI metrics
```

### Device Filtering

Filter which devices to collect metrics from:

```yaml
agent:
  nodeexporter:
    filesystem:
      # Ignore these filesystem types
      ignored_fs_types:
        - autofs
        - binfmt_misc
        - cgroup
        - configfs
        - debugfs
        - devpts
        - devtmpfs
        - fusectl
        - hugetlbfs
        - mqueue
        - nsfs
        - overlay
        - proc
        - procfs
        - pstore
        - securityfs
        - sysfs
        - tmpfs
        - tracefs
      
      # Ignore these mount points
      ignored_mount_points:
        - "^/(dev|proc|sys|var/lib/docker/.+)($|/)"
    
    diskstats:
      # Only these devices
      device_include:
        - "^sd[a-z]+$"
        - "^nvme[0-9]+n[0-9]+$"
      
      # Ignore these devices
      device_exclude:
        - "^loop[0-9]+$"
        - "^ram[0-9]+$"
    
    netdev:
      # Ignore these interfaces
      device_exclude:
        - "^veth.*"
        - "^docker.*"
        - "^br-.*"
```

---

## Prometheus Integration

### Scrape Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets:
          - 'host1:9100'
          - 'host2:9100'
```

### Service Discovery (Kubernetes)

```yaml
scrape_configs:
  - job_name: 'kubernetes-nodes'
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - source_labels: [__address__]
        regex: '(.+):10250'
        replacement: '${1}:9100'
        target_label: __address__
```

---

## Grafana Dashboards

Telegen is compatible with standard node_exporter dashboards:

### Recommended Dashboards

| Dashboard | Grafana ID | Description |
|-----------|------------|-------------|
| Node Exporter Full | 1860 | Comprehensive system metrics |
| Node Exporter for Prometheus | 11074 | Clean, modern layout |
| Linux Server Metrics | 180 | Classic dashboard |

### Import Dashboard

1. Go to Grafana → Dashboards → Import
2. Enter dashboard ID (e.g., `1860`)
3. Select Prometheus data source
4. Dashboard works immediately with Telegen

---

## eBPF-Enhanced Metrics

Telegen adds eBPF-based metrics beyond standard node_exporter:

### Additional Metrics

| Metric | Description |
|--------|-------------|
| `node_tcp_rtt_microseconds` | TCP round-trip time |
| `node_tcp_retransmits_total` | TCP retransmissions |
| `node_process_open_fds` | Open file descriptors per process |
| `node_cgroup_cpu_usage_seconds_total` | Per-cgroup CPU usage |
| `node_cgroup_memory_usage_bytes` | Per-cgroup memory usage |

### Enable eBPF Enhancements

```yaml
agent:
  nodeexporter:
    enabled: true
    
    # Enable eBPF-enhanced metrics
    ebpf_enhanced: true
```

---

## Migration from node_exporter

### Step 1: Deploy Telegen

Deploy Telegen alongside node_exporter:

```bash
# Telegen on different port initially
agent:
  nodeexporter:
    listen_address: ":9101"  # Different port
```

### Step 2: Compare Metrics

Verify metric compatibility:

```promql
# Compare CPU metrics
node_cpu_seconds_total{port="9100"}  # node_exporter
node_cpu_seconds_total{port="9101"}  # Telegen
```

### Step 3: Switch Scrape Targets

Update Prometheus to scrape Telegen:

```yaml
scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['host:9100']  # Now points to Telegen
```

### Step 4: Remove node_exporter

Once verified, remove node_exporter.

---

## Textfile Collector

Import custom metrics from files:

```yaml
agent:
  nodeexporter:
    textfile:
      enabled: true
      directory: "/var/lib/node_exporter/textfile_collector"
```

### Create Custom Metrics

```bash
# /var/lib/node_exporter/textfile_collector/custom.prom
# HELP node_custom_metric A custom metric
# TYPE node_custom_metric gauge
node_custom_metric{label="value"} 42
```

---

## Performance

### Resource Usage

| Metric | Value |
|--------|-------|
| CPU overhead | < 0.5% |
| Memory | ~20MB |
| Scrape time | < 100ms |

### Optimization

For large systems (many disks, interfaces):

```yaml
agent:
  nodeexporter:
    # Increase scrape timeout
    timeout: 10s
    
    # Reduce collection frequency
    collector_interval: 30s
    
    # Limit concurrent collectors
    max_procs: 2
```

---

## Common Queries

### CPU Usage

```promql
# CPU utilization percentage
100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Per-CPU utilization
1 - avg by(instance, cpu) (irate(node_cpu_seconds_total{mode="idle"}[5m]))
```

### Memory Usage

```promql
# Memory utilization percentage
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# Memory breakdown
node_memory_MemTotal_bytes - node_memory_MemFree_bytes - node_memory_Buffers_bytes - node_memory_Cached_bytes
```

### Disk I/O

```promql
# Disk read/write rate
rate(node_disk_read_bytes_total[5m])
rate(node_disk_written_bytes_total[5m])

# Disk I/O utilization
rate(node_disk_io_time_seconds_total[5m]) * 100
```

### Network

```promql
# Network throughput
rate(node_network_receive_bytes_total[5m]) * 8
rate(node_network_transmit_bytes_total[5m]) * 8

# Packet errors
rate(node_network_receive_errs_total[5m])
rate(node_network_transmit_errs_total[5m])
```

### Filesystem

```promql
# Filesystem usage percentage
(1 - node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100

# Inode usage
(1 - node_filesystem_files_free / node_filesystem_files) * 100
```

---

## Alerting Examples

```yaml
groups:
  - name: node
    rules:
      - alert: HostHighCpuLoad
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU load on {{ $labels.instance }}"
      
      - alert: HostOutOfMemory
        expr: node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Host {{ $labels.instance }} is running out of memory"
      
      - alert: HostOutOfDiskSpace
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Host {{ $labels.instance }} disk space is below 10%"
      
      - alert: HostHighDiskIO
        expr: rate(node_disk_io_time_seconds_total[5m]) > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High disk I/O on {{ $labels.instance }}"
```

---

## Next Steps

- {doc}`auto-discovery` - Automatic service detection
- {doc}`distributed-tracing` - Application tracing
- {doc}`../configuration/agent-mode` - Full configuration
