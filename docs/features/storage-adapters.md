# Storage Adapters

Telegen's storage adapters collect metrics from enterprise storage arrays via vendor APIs.

## Overview

Storage adapters support:

| Vendor | Products | API |
|--------|----------|-----|
| **Dell** | PowerStore, PowerScale | REST API |
| **HPE** | Primera, 3PAR | WSAPI |
| **Pure Storage** | FlashArray, FlashBlade | REST API v2 |
| **NetApp** | ONTAP, E-Series | ONTAP REST API |

---

## Dell PowerStore

### Configuration

```yaml
collector:
  storage:
    dell:
      enabled: true
      poll_interval: 60s
      
      targets:
        - name: "powerstore-prod-01"
          address: "https://powerstore.example.com"
          username: "monitor"
          password: "${DELL_PASSWORD}"
          verify_ssl: true
          
          metrics:
            performance: true
            capacity: true
            alerts: true
            hardware: true
```

### Metrics Collected

| Metric | Description |
|--------|-------------|
| `dell_powerstore_volume_read_iops` | Read IOPS per volume |
| `dell_powerstore_volume_write_iops` | Write IOPS per volume |
| `dell_powerstore_volume_read_latency_us` | Read latency (microseconds) |
| `dell_powerstore_volume_write_latency_us` | Write latency (microseconds) |
| `dell_powerstore_volume_size_bytes` | Volume total size |
| `dell_powerstore_volume_used_bytes` | Volume used space |
| `dell_powerstore_cluster_capacity_total_bytes` | Total cluster capacity |
| `dell_powerstore_cluster_capacity_used_bytes` | Used cluster capacity |
| `dell_powerstore_data_reduction_ratio` | Data reduction ratio |
| `dell_powerstore_hardware_health` | Hardware component health |

### Labels

| Label | Description |
|-------|-------------|
| `array` | Array name |
| `volume` | Volume name |
| `appliance` | Appliance ID |
| `host` | Host attachment |

---

## HPE Primera/3PAR

### Configuration

```yaml
collector:
  storage:
    hpe:
      enabled: true
      poll_interval: 60s
      
      targets:
        - name: "primera-prod"
          address: "https://primera.example.com:8080"
          username: "monitor"
          password: "${HPE_PASSWORD}"
          verify_ssl: true
          
          metrics:
            system: true
            cpgs: true
            volumes: true
            hosts: true
            ports: true
```

### Metrics Collected

| Metric | Description |
|--------|-------------|
| `hpe_primera_capacity_total_bytes` | Total system capacity |
| `hpe_primera_capacity_allocated_bytes` | Allocated capacity |
| `hpe_primera_capacity_free_bytes` | Free capacity |
| `hpe_primera_efficiency_ratio` | Compaction ratio |
| `hpe_primera_volume_size_bytes` | Volume size |
| `hpe_primera_volume_used_bytes` | Volume used space |
| `hpe_primera_cpg_capacity_bytes` | CPG capacity |
| `hpe_primera_port_bandwidth_bytes` | Port bandwidth |
| `hpe_primera_node_cpu_percent` | Node CPU usage |
| `hpe_primera_node_cache_hit_percent` | Cache hit ratio |

### Labels

| Label | Description |
|-------|-------------|
| `array` | Array name |
| `volume` | Volume name |
| `cpg` | Common provisioning group |
| `node` | Controller node |
| `port` | FC/iSCSI port |

---

## Pure Storage FlashArray

### Configuration

```yaml
collector:
  storage:
    pure:
      enabled: true
      poll_interval: 60s
      
      targets:
        - name: "pure-prod-01"
          address: "https://purestorage.example.com"
          api_token: "${PURE_API_TOKEN}"
          
          metrics:
            arrays: true
            volumes: true
            hosts: true
            pods: true
            replication: true
```

### Generating API Token

```bash
# On Pure Storage array
pureuser@array01> pureapitoken create --user monitor
```

### Metrics Collected

| Metric | Description |
|--------|-------------|
| `pure_flasharray_capacity_bytes` | Total array capacity |
| `pure_flasharray_used_bytes` | Used capacity |
| `pure_flasharray_data_reduction` | Data reduction ratio |
| `pure_flasharray_volume_size_bytes` | Volume provisioned size |
| `pure_flasharray_volume_used_bytes` | Volume used space |
| `pure_flasharray_volume_read_iops` | Volume read IOPS |
| `pure_flasharray_volume_write_iops` | Volume write IOPS |
| `pure_flasharray_volume_read_latency_us` | Read latency |
| `pure_flasharray_volume_write_latency_us` | Write latency |
| `pure_flasharray_pod_status` | Pod replication status |
| `pure_flasharray_hardware_status` | Hardware health |

### Labels

| Label | Description |
|-------|-------------|
| `array` | Array name |
| `volume` | Volume name |
| `host` | Connected host |
| `pod` | Replication pod |
| `drive` | Drive bay |

---

## NetApp ONTAP

### Configuration

```yaml
collector:
  storage:
    netapp:
      enabled: true
      poll_interval: 60s
      
      targets:
        - name: "ontap-prod"
          address: "https://ontap.example.com"
          username: "monitor"
          password: "${NETAPP_PASSWORD}"
          verify_ssl: true
          
          metrics:
            aggregates: true
            volumes: true
            luns: true
            network: true
            performance: true
```

### Required Permissions

Create a read-only monitoring role:

```bash
# On ONTAP cluster
security login role create -role monitor -cmddirname "volume show" -access readonly
security login role create -role monitor -cmddirname "aggregate show" -access readonly
security login role create -role monitor -cmddirname "lun show" -access readonly
security login role create -role monitor -cmddirname "statistics" -access readonly
security login create -user-or-group-name monitor -role monitor -application http -authmethod password
```

### Metrics Collected

| Metric | Description |
|--------|-------------|
| `netapp_ontap_aggregate_size_bytes` | Aggregate total size |
| `netapp_ontap_aggregate_used_bytes` | Aggregate used space |
| `netapp_ontap_volume_size_bytes` | Volume size |
| `netapp_ontap_volume_used_bytes` | Volume used space |
| `netapp_ontap_volume_iops` | Volume IOPS |
| `netapp_ontap_volume_throughput_bytes` | Volume throughput |
| `netapp_ontap_volume_latency_us` | Volume latency |
| `netapp_ontap_lun_size_bytes` | LUN size |
| `netapp_ontap_lun_used_bytes` | LUN used space |
| `netapp_ontap_port_speed_bytes` | Port speed |
| `netapp_ontap_cluster_health` | Cluster health status |

### Labels

| Label | Description |
|-------|-------------|
| `cluster` | Cluster name |
| `node` | Node name |
| `aggregate` | Aggregate name |
| `volume` | Volume name |
| `svm` | Storage VM name |
| `lun` | LUN path |

---

## Common Dashboards

### Capacity Planning

```promql
# Total capacity across all arrays
sum(storage_capacity_total_bytes) by (vendor)

# Capacity utilization
sum(storage_capacity_used_bytes) / sum(storage_capacity_total_bytes) * 100

# Days until full (at current growth rate)
(storage_capacity_total_bytes - storage_capacity_used_bytes)
/ deriv(storage_capacity_used_bytes[7d])
/ 86400
```

### Performance

```promql
# Total IOPS across arrays
sum(rate(storage_volume_read_iops[5m]) + rate(storage_volume_write_iops[5m]))

# Average latency
avg(storage_volume_read_latency_us + storage_volume_write_latency_us) / 2

# Top 10 volumes by IOPS
topk(10, rate(storage_volume_read_iops[5m]) + rate(storage_volume_write_iops[5m]))
```

### Health Alerts

```yaml
groups:
  - name: storage
    rules:
      - alert: StorageArrayCapacityHigh
        expr: storage_capacity_used_bytes / storage_capacity_total_bytes > 0.85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Storage array {{ $labels.array }} is over 85% capacity"
      
      - alert: StorageVolumeLatencyHigh
        expr: storage_volume_read_latency_us > 10000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Volume {{ $labels.volume }} has high latency"
      
      - alert: StorageHardwareFailure
        expr: storage_hardware_status != 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Hardware issue on {{ $labels.array }}"
```

---

## Security Considerations

### Credential Management

Use environment variables or secrets:

```yaml
collector:
  storage:
    pure:
      targets:
        - name: "pure-prod"
          address: "https://pure.example.com"
          # Reference environment variable
          api_token: "${PURE_API_TOKEN}"
```

In Kubernetes:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: storage-credentials
type: Opaque
stringData:
  PURE_API_TOKEN: "your-token-here"
  DELL_PASSWORD: "your-password"
  NETAPP_PASSWORD: "your-password"
```

### Network Security

- Use HTTPS with valid certificates
- Restrict collector IP access on storage arrays
- Use read-only monitoring accounts
- Rotate credentials regularly

---

## Multi-Array Example

```yaml
telegen:
  mode: collector
  service_name: "storage-collector"

otlp:
  endpoint: "otel-collector:4317"

collector:
  storage:
    # Dell PowerStore
    dell:
      enabled: true
      poll_interval: 60s
      targets:
        - name: "powerstore-dc1"
          address: "https://10.0.10.100"
          username: "monitor"
          password: "${DELL_PASSWORD}"
        - name: "powerstore-dc2"
          address: "https://10.0.20.100"
          username: "monitor"
          password: "${DELL_PASSWORD}"
    
    # Pure Storage
    pure:
      enabled: true
      poll_interval: 60s
      targets:
        - name: "pure-prod"
          address: "https://10.0.10.110"
          api_token: "${PURE_TOKEN_PROD}"
        - name: "pure-dev"
          address: "https://10.0.10.111"
          api_token: "${PURE_TOKEN_DEV}"
    
    # NetApp
    netapp:
      enabled: true
      poll_interval: 60s
      targets:
        - name: "ontap-nas"
          address: "https://10.0.10.120"
          username: "monitor"
          password: "${NETAPP_PASSWORD}"
```

---

## Next Steps

- {doc}`snmp-receiver` - Network device monitoring
- {doc}`../configuration/collector-mode` - Collector configuration
- {doc}`../operations/monitoring` - Storage monitoring dashboards
