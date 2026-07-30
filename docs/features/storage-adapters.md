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

## NetApp ONTAP (Harvest-Parity Collector)

Telegen includes a **Harvest-parity ONTAP collector** that provides comprehensive observability for NetApp ONTAP storage arrays. This collector is a drop-in replacement for NetApp Harvest with full metric catalog coverage.

### Collector Types

| Collector | Engine | Description |
|-----------|--------|-------------|
| **Rest** | ONTAP REST API | 65+ inventory/configuration objects (capacity, state, config) |
| **RestPerf** | Counter Tables API | 54+ performance counter tables with rate cooking |
| **KeyPerf** | Resource Endpoints | Performance via `statistics.*` (Volume always; fallback for ASA r2, GCNV) |
| **EMS** | Event Management System | EMS events → OTLP logs (86 message types) |

### Auto-Selection Logic

Telegen automatically probes ONTAP capabilities and selects the appropriate collectors:

- **RESTPerf** enabled when `api/cluster/counter/tables` responds (ONTAP ~9.11.1+)
- **RESTPerf disabled** for ASA r2 (disaggregated), GCNV mode, or older clusters → KeyPerf takes over
- **Default collectors**: `[rest, restperf, keyperf, ems]`

### ONTAP Object Coverage

#### Rest Catalog (65 Objects)

| Category | Objects |
|----------|---------|
| **Core** | Cluster, Node, SVM, Volume, Aggregate, LUN, Namespace, Qtree, Snapshot, Quota |
| **Network** | LIF, NetPort, NetRoute, EthernetSwitchPort, NetConnections, NIC |
| **Protocols** | CIFS Session/Share, NFS Clients, iSCSI, FCP, OntapS3, OntapS3Policy |
| **Data Protection** | SnapMirror, SnapMirrorPolicy, SnapshotPolicy |
| **Security** | Security, SecurityAccount, SecurityCert, SecurityLogin, SecuritySsh, SecurityAuditDestination |
| **Hardware** | Disk, Shelf, Sensor, FRU, License |
| **Management** | ExportRule, Lock, MAVRequest, Mediator, NtpServer, ClusterSchedule, ClusterSoftware |
| **v3 Opt-In** | AuditLog, CIFSSession, CIFSShare, ExportRule, NFSClients, NDMPSession, NetConnections |

#### RestPerf Catalog (54+ Objects)

| Protocol | Objects |
|----------|---------|
| **NFS** | NFSv3, NFSv4, NFSv4.1, NFSv4.2 (per-node and per-SVM), NFSv4Pool |
| **SMB/CIFS** | CIFSNode, CIFSvserver, SMB2 |
| **Block** | iSCSI, FCP, FCPPort, FCPLif, FCVI |
| **NVMe** | Namespace, NVMfLif, NVMfRdmaPort, NVMfTcpPort |
| **Object** | OntapS3SVM |
| **System** | SystemNode, HostAdapter, Disk, Path, NicCommon, Netstat |
| **WAFL** | WAFL, WAFLAggr, WAFLSizer, WAFLCompBin |
| **QoS** | Workload, WorkloadVolume |
| **Other** | TokenManager, CopyManager, FlexCachePerf, Vscan, VscanSVM, FPolicy, Netstat |

#### KeyPerf Catalog (14 Objects)

Volume, Aggregate, CIFSvserver, Cluster, EthernetSwitchPort, LUN, Namespace, NFSv3, NFSv4, NFSv4.1, SystemNode, Qtree (opt-in)

### Configuration

```yaml
telegen:
  mode: collector  # or unified

netapp_ontap:
  - name: "ontap-prod-01"
    address: "https://10.0.10.140"
    username: "monitor"
    password: "${NETAPP_PASSWORD}"
    verify_ssl: true
    timeout: 30s
    coverage: full                    # full | harvest_default
    collectors: [rest, restperf, keyperf, ems]
    templates_dir: ""                 # empty = configs/netapp
    ems:
      enabled: true
      resolve_after: 672h
    labels:
      environment: "production"

# NetApp E-Series (SANtricity)
netapp_eseries:
  - name: "eseries-prod-01"
    address: "https://10.0.10.150"
    username: "monitor"
    password: "${NETAPP_ESERIES_PASSWORD}"
    verify_ssl: true
    timeout: 30s
    labels:
      environment: "production"
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

### Performance Metrics (Exhaustive)

#### Cluster

| Metric | Description |
|--------|-------------|
| `cluster_read_ops`, `cluster_write_ops`, `cluster_total_ops` | IOPS |
| `cluster_read_data`, `cluster_write_data`, `cluster_total_data` | Throughput |
| `cluster_read_latency`, `cluster_write_latency`, `cluster_total_latency` | Latency |
| `cluster_space_available` | Available space |

#### Volume

| Metric | Description |
|--------|-------------|
| `volume_size`, `volume_size_used`, `volume_size_used_percent` | Capacity |
| `volume_read_ops`, `volume_write_ops`, `volume_total_ops` | IOPS |
| `volume_read_data`, `volume_write_data`, `volume_total_data` | Throughput |
| `volume_read_latency`, `volume_write_latency`, `volume_total_latency` | Latency |
| `volume_nfs_total_ops`, `volume_sis_*_saved_percent` | NFS ops, dedupe savings |

#### Node

| Metric | Description |
|--------|-------------|
| `node_avg_processor_busy`, `node_cpu_busy` | CPU |
| `node_total_ops`, `node_read_ops`, `node_write_ops` | IOPS |
| `node_net_data_recv`, `node_net_data_sent` | Network |
| `node_disk_data_read`, `node_disk_data_written` | Disk |

#### LUN / Namespace

| Metric | Description |
|--------|-------------|
| `lun_size`, `lun_size_used` | Capacity |
| `lun_read_ops`, `lun_write_ops`, `lun_total_ops` | IOPS |
| `lun_read_data`, `lun_write_data` | Throughput |
| `namespace_size`, `namespace_read_ops` | NVMe namespace metrics |

### Plugin System

Telegen includes a plugin system for computed metrics:

| Plugin | Description |
|--------|-------------|
| **MetricAgent** | `compute_metric` expressions (ADD, SUBTRACT, MULTIPLY, DIVIDE, PERCENT) |
| **LabelAgent** | Convert label strings to numeric metrics |
| **Volume** | Marks `style` label; derives NFS ops totals |
| **Aggregator** | Rolls up metrics by label (e.g., node-level summaries) |
| **Health** | Ensures synthetic `status` metric |
| **Sensor** | Hardware sensor metrics (temperature, fan, power) |
| **Shelf** | Shelf hardware inventory |
| **Nic** | NIC utilization |
| **Fcp** | FCP utilization |
| **FabricPool** | Cloud tier metrics |
| **VolumeTopClients** | Top clients/files/users |
| **VolumeAnalytics** | Activity analytics |
| **QoS** | Workload throughput bounds |

### EMS Events (OTLP Logs)

NetApp EMS events are exported as OTLP log records:

```yaml
log_record:
  body: "Volume vol01 is nearly full (95% used)"
  severity: WARNING
  attributes:
    netapp.ems.message_name: "wafl.vol.full"
    netapp.ems.severity: "WARNING"
    netapp.cluster.name: "ontap-prod-01"
    netapp.volume.name: "vol01"
    telegen.signal.category: "Storage Logs"
    telegen.signal.subcategory: "NetApp EMS"
```

### E-Series Support (SANtricity)

NetApp E-Series arrays are supported via the SANtricity REST API:

| Collector | Objects |
|-----------|---------|
| **E-Series Rest** | Volume, Array, Host, Hardware, SsdCache, Pool, Workload (7 objects) |
| **E-Series Perf** | Volume, Controller, Drive, Pool, Array, SsdCache, Interface, Application, Workload (9 objects) |

### Dashboards

Six pre-built dashboards are available in `docs/reference/netapp-ontap-dashboards.md`:

1. **Fleet Overview** (9 panels) — Arrays, nodes, aggregates, volumes, capacity
2. **Node Performance** (8 panels) — CPU, IOPS, latency, throughput, network, disk
3. **Aggregate & Volume Capacity** (7 panels) — Capacity, free, used %, physical used
4. **Volume / LUN Performance** (8 panels) — IOPS, throughput, latency, top volumes
5. **Data Protection / SnapMirror** (4 panels) — Lag time, last transfer, failed updates
6. **EMS / Events** (7 panels) — Live EMS stream, severity, top messages, hardware events

### Metric Parity

The NetApp ONTAP collector targets **1,558 unique Harvest-compatible metric families** covering all Rest/RestPerf/KeyPerf templates, aggregator plugins, computed metrics, and ZAPI legacy aliases.

### Labels

| Label | Description |
|-------|-------------|
| `cluster` | Cluster name |
| `node` | Node name |
| `aggregate` | Aggregate name |
| `volume` | Volume name |
| `svm` | Storage VM name |
| `lun` | LUN path |
| `array` | Array name (E-Series) |

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
