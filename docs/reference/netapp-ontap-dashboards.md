# NetApp ONTAP → MIRASTACK Data Studio Query Reference

This document catalogs **metric and log signals** emitted by Telegen's native
NetApp ONTAP collector and provides **ready-to-paste PromQL and LogSQL queries**
formatted for the **MIRASTACK UI Data Studio** dashboard builder.

Use it to build dashboards in Data Studio: pick an integration (data source),
choose a chart type, and paste the query.

- **Metrics source:** `internal/storage/netapp/` — Harvest-compatible
  `{object}_{counter}` gauges/counters exported over OTLP (shared pipeline
  exporter, scope `telegen.storage`).
- **Logs source:** `internal/storage/netapp/ems/` — ONTAP EMS events from
  `api/support/ems/events`, exported over the OTLP log bridge (scope
  `telegen.storage.netapp.ems`).
- **Templates:** `configs/netapp/{rest,restperf,keyperf,ems}/` (adapted from
  NetApp Harvest; see `configs/netapp/SOURCE.md`).

Related feature overview: {doc}`../features/storage-netapp`.

---

## 1. Overview and caveats

### 1.1 Which collector this covers

| Collector | Path | Metric naming | Logs | Covered here |
|-----------|------|---------------|------|--------------|
| **ONTAP Harvest-parity (storage adapter)** | `internal/storage/netapp/` | `{object}_{display}` (e.g. `volume_read_ops`) | EMS yes | **Yes** |
| **E-Series SANtricity** | `internal/storage/netapp/eseries/` | template `object` prefix | No | Appendix C (brief) |
| Legacy hardcoded NetApp gauges | removed (`netapp_ontap_*`) | — | — | No |

If queries return nothing, confirm `storage.netapp_ontap` is configured and that
metric names use Harvest-style prefixes (`volume_`, `node_`, `aggr_`, …), not
the old `netapp_ontap_*` names.

### 1.2 Gauge vs counter — when to use `rate()`

Telegen maps template counters as follows (`matrix.ToStorageMetrics`):

| Template / cook result | Exported type | PromQL guidance |
|------------------------|---------------|-----------------|
| Rest inventory (capacity, state, sizes) | **gauge** | Do **not** use `rate()` |
| RestPerf / KeyPerf after rate cooking | usually **gauge** (already per-second) | Do **not** use `rate()` again |
| Explicit `MetricTypeCounter` (rare) | **counter** | Use `rate()` / `increase()` |

RestPerf and KeyPerf cook raw ONTAP counters into **per-second rates** (or
copy averages/percents) across consecutive polls (`matrix.CookRates`). Values
you see in VictoriaMetrics for IOPS, throughput, and latency are therefore
already rate-like gauges for dashboard purposes.

Consequences for PromQL:

- Prefer `avg_over_time`, `max_over_time`, `sum by (...)`, `topk` for smoothing.
- Only apply `rate()` if you have confirmed a true monotonic counter series.

### 1.3 Label glossary

Common labels stamped on every ONTAP metric (`ONTAPCollector.commonLabels`):

| Label | Meaning |
|-------|---------|
| `array_name` | Collector instance name from config (`netapp_ontap[].name`) |
| `vendor` | Always `netapp` |
| `product` | Always `ontap` (E-Series uses `eseries`) |
| `cluster` | Cluster name from capability probe (when available) |
| `cluster_uuid` | Cluster UUID from capability probe (when available) |

Instance labels come from template `^` / `^^` counters and vary by object. Common
ones:

| Label | Typical objects | Meaning |
|-------|-----------------|---------|
| `node` | node, aggr, volume, disk, … | Node name |
| `svm` | volume, lun, lif, nfs/cifs, … | SVM / vserver |
| `volume` | volume, snapmirror, lun, … | Volume name |
| `aggr` | aggr, volume, … | Aggregate name |
| `style` | volume | e.g. `flexvol`, `flexgroup`, aggregator rollups |
| `uuid` | many | Instance UUID / key |
| `state` | volume, aggr, node, … | Operational state string (as label where templated) |

Operator `labels:` from config are merged onto every metric. Resource attribute
`service.name=telegen-storage`; scope `telegen.storage`. Depending on VictoriaMetrics
OTLP ingestion these may appear as extra labels (e.g. `otel_scope_name`).

### 1.4 Engines and coverage

| Engine | Role | Schedule (typical) |
|--------|------|--------------------|
| **Rest** | Inventory / capacity / config (public REST + `api/private/cli`) | ~3m |
| **RestPerf** | Perf via `api/cluster/counter/tables/...` | ~1m |
| **KeyPerf** | Perf via resource `statistics.*` (Volume always; ASA r2 / GCNV / no RestPerf) | ~1m |
| **EMS** | Events → OTLP logs + optional `ems_events` gauge | ~3m |

Capability probe auto-disables RestPerf when counter tables are unavailable
(ASA r2, GCNV, older clusters) and enables KeyPerf instead.

`coverage: full` (default) includes Harvest opt-in objects (CIFS sessions,
locks, NFS clients, …). Use `harvest_default` to reduce cardinality.

### 1.5 How Data Studio sends these queries

Same contract as the VMware reference:

**Metrics** — integration `victoriametrics`, `queryType: promql`:

- Single-value (`chartType: metric`) → instant `/api/v1/query`
- Time-series → range `/api/v1/query_range` with toolbar `start` / `end` / `step`

**Logs** — integration `victorialogs`, `queryType: logsql`:

- Raw `logs` / `table` → `/select/logsql/query`
- Chart widgets → `/select/logsql/stats_query_range` with canonical order:

  ```
  <filter> | stats by (_time:<bucket>[, <group fields>]) <aggFn>(...) as value
  ```

### 1.6 Log field-name caveat

EMS attributes become VictoriaLogs fields; body maps to `_msg`. Exact field
names depend on OTLP → VictoriaLogs mapping. Queries below use attribute keys
verbatim (`message`, `severity`, `node`, `array_name`, …). Validate with
`field_names` on a live instance before locking dashboards.

---

## 2. Metrics catalog

All PromQL assumes one or more clusters. Scope with
`array_name="<collector-name>"` or `cluster="<cluster-name>"`, e.g.
`volume_read_ops{array_name="ontap-prod"}`.

Telegen enumerates the **full Harvest ONTAP catalog (1,558 metric families)**
from Rest / RestPerf / KeyPerf templates plus Aggregator, Max, MetricAgent,
LabelAgent, VolumeTop, Sensor/Shelf/Health, and related plugin expansions
(`make netapp-parity`). Sections below highlight families used most often in
dashboards; they are not exhaustive.

### 2.1 Cluster / health

Sources: Rest `cluster.yaml`, `status.yaml`, `health.yaml`, `subsystem.yaml`;
KeyPerf `cluster.yaml`.

| Metric (examples) | Type | Meaning | Common labels |
|-------------------|------|---------|---------------|
| `cluster_space_available` | gauge | Cluster free space | `array_name`, `cluster` |
| `cluster_read_ops` / `cluster_write_ops` / `cluster_total_ops` | gauge | Cluster IOPS | `array_name` |
| `cluster_read_data` / `cluster_write_data` / `cluster_total_data` | gauge | Cluster throughput (bytes/s after cook) | `array_name` |
| `cluster_read_latency` / `cluster_write_latency` / `cluster_total_latency` | gauge | Cluster latency | `array_name` |
| `cluster_health` | gauge | Cluster health indicator | `array_name` |
| `cluster_subsystem_outstanding_alerts` | gauge | Outstanding subsystem alerts | `array_name` |
| `ems_events` | gauge | EMS events seen in last poll (by severity label) | `array_name`, `severity` |

Queries:

```promql
# Cluster count (metric widget)
count(count by (array_name, cluster) (cluster_total_ops))

# Cluster total IOPS (timeseries)
sum(cluster_total_ops) by (array_name, cluster)

# Cluster throughput bytes/s (timeseries)
sum(cluster_total_data) by (array_name, cluster)

# EMS events in last poll by severity (table)
ems_events
```

### 2.2 Node / SystemNode

Sources: Rest `node.yaml`; RestPerf `system_node.yaml` (`object: node`).

| Metric (examples) | Type | Unit | Meaning |
|-------------------|------|------|---------|
| `node_avg_processor_busy` | gauge | percent | Average processor busy |
| `node_cpu_busy` | gauge | — | CPU busy |
| `node_memory` | gauge | — | Memory counter from system:node |
| `node_total_ops` / `node_read_ops` / `node_write_ops` | gauge | ops/s | Node IOPS |
| `node_total_data` / `node_read_data` / `node_write_data` | gauge | bytes/s | Node throughput |
| `node_total_latency` / `node_read_latency` / `node_write_latency` | gauge | — | Node latency |
| `node_net_data_recv` / `node_net_data_sent` | gauge | — | Network data |
| `node_disk_data_read` / `node_disk_data_written` | gauge | — | Disk data |
| `node_nfs_ops` / `node_cifs_ops` / `node_fcp_ops` / `node_iscsi_ops` | gauge | ops/s | Protocol ops |
| `node_failed_fan` / `node_failed_power` | gauge | count | Hardware failure counts (inventory) |

Labels: `node`, `array_name`, `cluster`, …

Queries:

```promql
# Nodes reporting CPU busy (metric)
count(node_avg_processor_busy)

# Per-node CPU busy (timeseries)
node_avg_processor_busy

# Top 5 busy nodes (timeseries)
topk(5, node_avg_processor_busy)

# Per-node total IOPS (timeseries)
node_total_ops

# Per-node network throughput (timeseries)
sum(node_net_data_recv + node_net_data_sent) by (node, array_name)
```

### 2.3 Aggregate capacity & performance

Sources: Rest `aggr.yaml`; KeyPerf `aggr.yaml`; Aggregator rollups may add
node-level summaries.

| Metric (examples) | Type | Unit | Meaning |
|-------------------|------|------|---------|
| `aggr_space_total` | gauge | bytes | Aggregate size |
| `aggr_space_available` | gauge | bytes | Free space |
| `aggr_space_used` | gauge | bytes | Used space |
| `aggr_space_physical_used` | gauge | bytes | Physical used |
| `aggr_space_physical_used_percent` | gauge | percent | Physical used % |
| `aggr_space_sis_saved_percent` | gauge | percent | Storage efficiency savings % |
| `aggr_read_ops` / `aggr_write_ops` / `aggr_total_ops` | gauge | ops/s | Aggr IOPS |
| `aggr_read_data` / `aggr_write_data` / `aggr_total_data` | gauge | bytes/s | Aggr throughput |
| `aggr_read_latency` / `aggr_write_latency` / `aggr_total_latency` | gauge | — | Aggr latency |

Labels: `aggr`, `node`, `uuid`, `state`, `array_name`, …

Queries:

```promql
# Aggregate count
count(aggr_space_total)

# Used percent per aggregate (timeseries)
100 * aggr_space_used / aggr_space_total

# Aggregates above 90% used (metric / instant)
count((100 * aggr_space_used / aggr_space_total) >= 90)

# Free space per aggregate (timeseries)
aggr_space_available

# Total free capacity across estate (metric)
sum(aggr_space_available)
```

- Suggested `unit`: `bytes` for space; `percent` for used%.

### 2.4 Volume capacity & performance

Sources: Rest `volume.yaml` (private CLI capacity); KeyPerf `volume.yaml`
(statistics IOPS/latency/throughput — RestPerf Volume delegates here).

**Capacity (Rest):**

| Metric (examples) | Type | Unit | Meaning |
|-------------------|------|------|---------|
| `volume_size` / `volume_size_total` | gauge | bytes | Volume size |
| `volume_size_available` | gauge | bytes | Available |
| `volume_size_used` | gauge | bytes | Used |
| `volume_size_used_percent` | gauge | percent | Used % |
| `volume_space_physical_used` | gauge | bytes | Physical used |
| `volume_inode_files_total` / `volume_inode_files_used` | gauge | count | Inodes |
| `volume_sis_*_saved` / `volume_sis_*_saved_percent` | gauge | bytes / % | Efficiency |
| `volume_snapshot_reserve_*` | gauge | — | Snapshot reserve |

**Performance (KeyPerf):**

| Metric (examples) | Type | Unit | Meaning |
|-------------------|------|------|---------|
| `volume_read_ops` / `volume_write_ops` / `volume_other_ops` / `volume_total_ops` | gauge | ops/s | IOPS |
| `volume_read_data` / `volume_write_data` / `volume_other_data` / `volume_total_data` | gauge | bytes/s | Throughput |
| `volume_read_latency` / `volume_write_latency` / `volume_other_latency` / `volume_avg_latency` | gauge | — | Latency |
| `volume_nfs_*_ops` / `volume_nfs_*_latency` | gauge | — | Per-NFS-op stats |

Labels: `volume`, `svm`, `style`, `node`, `aggr`, `array_name`, …

Queries:

```promql
# Online volume count (approx — instance presence)
count(volume_size_used)

# Volume used % (timeseries)
volume_size_used_percent

# Volumes above 90% used (instant)
count(volume_size_used_percent >= 90)

# Per-volume IOPS (timeseries)
volume_total_ops

# Per-volume throughput (timeseries)
volume_total_data

# Per-volume average latency (timeseries)
volume_avg_latency

# Top 10 volumes by IOPS
topk(10, volume_total_ops)

# Top 10 volumes by used %
topk(10, volume_size_used_percent)

# IOPS by SVM
sum(volume_total_ops) by (svm, array_name)
```

### 2.5 LUN / Namespace (SAN / NVMe)

Sources: Rest + RestPerf / KeyPerf `lun.yaml`, `namespace.yaml`.

| Metric (examples) | Type | Meaning |
|-------------------|------|---------|
| `lun_size` / `lun_size_used` | gauge | LUN capacity |
| `lun_read_ops` / `lun_write_ops` / `lun_total_ops` | gauge | LUN IOPS |
| `lun_read_data` / `lun_write_data` / `lun_total_data` | gauge | LUN throughput |
| `lun_avg_read_latency` / `lun_avg_write_latency` / `lun_total_latency` | gauge | LUN latency |
| `namespace_size` / `namespace_size_used` | gauge | NVMe namespace capacity |
| `namespace_read_ops` / `namespace_write_ops` / `namespace_total_ops` | gauge | Namespace IOPS |
| `namespace_avg_read_latency` / `namespace_avg_write_latency` | gauge | Namespace latency |

Queries:

```promql
# LUN count
count(lun_size)

# LUN IOPS
lun_total_ops

# Namespace latency
namespace_avg_total_latency
```

### 2.6 Disk / Shelf / NIC / LIF

| Area | Example metrics | Notes |
|------|-----------------|-------|
| Disk | `disk_busy`, `disk_capacity`, `disk_user_reads`, `disk_user_writes`, `disk_total_transfers` | RestPerf `disk:constituent` |
| Shelf | Rest `shelf.yaml` inventory metrics | Hardware / shelf state |
| NIC | `nic_rx_bytes`, `nic_tx_bytes`, `nic_rx_errors`, `nic_tx_errors` | RestPerf `nic_common`; plugins may add `rx_percent` / `tx_percent` |
| LIF | `lif_recv_data`, `lif_sent_data`, `lif_recv_errors`, `lif_sent_errors`, `lif_uptime` | RestPerf / KeyPerf |

Queries:

```promql
# Busiest disks
topk(10, disk_busy)

# NIC errors
sum(nic_rx_errors + nic_tx_errors) by (array_name)

# LIF throughput
sum(lif_recv_data + lif_sent_data) by (array_name)
```

### 2.7 Protocol performance (NFS / CIFS / SMB / FCP / iSCSI)

RestPerf objects: `nfsv3`, `nfsv4`, `nfsv4_1`, `nfsv4_2`, node variants,
`cifs_vserver`, `cifs_node`, `smb2`, `fcp`, `fcp_lif`, `iscsi_lif`, …

Metric prefixes commonly include `svm_`, `nfsv3_`, `nfsv4_`, `smb2_`, `fcp_`,
`iscsi_`, `node_nfs_*`, `node_cifs_*` depending on template `object:` and
display rename. Discover exact names with:

```promql
# VictoriaMetrics metric names matching a prefix (Data Studio / Explore)
{__name__=~"nfsv3_.*"}
{__name__=~"smb2_.*"}
{__name__=~"fcp_.*"}
```

Queries:

```promql
# Example: NFS v3 ops if present in your estate
sum({__name__=~"nfsv3_.*_ops"}) by (array_name)

# Node-level NFS / CIFS ops from system:node
node_nfs_ops
node_cifs_ops
```

### 2.8 QoS workloads

Sources: RestPerf `workload.yaml`, `workload_volume.yaml`; Rest QoS policy
templates.

| Metric (examples) | Type | Meaning |
|-------------------|------|---------|
| `qos_ops` / `qos_read_ops` / `qos_write_ops` / `qos_other_ops` | gauge | Workload IOPS |
| `qos_latency` / `qos_read_latency` / `qos_write_latency` | gauge | Workload latency |
| `qos_total_data` / `qos_read_data` / `qos_write_data` | gauge | Workload throughput |
| `qos_concurrency` | gauge | Concurrency |

Queries:

```promql
# QoS workload IOPS
qos_ops

# Top 10 QoS workloads by latency
topk(10, qos_latency)
```

### 2.9 SnapMirror

Source: Rest `snapmirror.yaml` (private CLI).

| Metric (examples) | Type | Meaning |
|-------------------|------|---------|
| `snapmirror_lag_time` | gauge | Replication lag |
| `snapmirror_last_transfer_duration` | gauge | Last transfer duration |
| `snapmirror_last_transfer_size` | gauge | Last transfer size |
| `snapmirror_total_transfer_bytes` | gauge | Cumulative transfer bytes |
| `snapmirror_update_successful_count` / `snapmirror_update_failed_count` | gauge | Update outcomes |
| `snapmirror_break_*` / `snapmirror_resync_*` | gauge | Break / resync counters |

Queries:

```promql
# SnapMirror lag (timeseries)
snapmirror_lag_time

# Relationships with lag > 1h (instant) — adjust threshold to your SLA
count(snapmirror_lag_time > 3600)

# Failed updates
sum(snapmirror_update_failed_count) by (array_name)
```

### 2.10 WAFL / headroom / flash

RestPerf: `wafl`, `wafl_hya_per_aggr`, `wafl_hya_sizer`,
`wafl_comp_aggr_vol_bin`, `resource_headroom_*`, `external_cache`, …

Examples: `wafl_memory_used`, `wafl_memory_free`, `wafl_cp_count`,
`wafl_total_cp_util`, `headroom_*`. Use `{__name__=~"wafl_.*"}` /
`{__name__=~"headroom_.*"}` to explore.

---

## 3. Logs catalog (EMS)

Source: `internal/storage/netapp/ems/`, template `configs/netapp/ems/9.6.0/ems.yaml`
(~86 unique ONTAP message names, including bookend pairs).

Each matching EMS event becomes one OTLP log record. Optional metric
`ems_events` counts events per poll by `severity`.

### 3.1 Log fields

| Field | Always present? | Meaning |
|-------|-----------------|---------|
| `_msg` (body) | yes | `log_message` or message name |
| `message` | yes | ONTAP EMS message name (e.g. `LUN.offline`, `callhome.battery.low`) |
| `severity` | usually | EMS severity |
| `node` / `node_uuid` | usually | Node that logged the event |
| `index` | usually | EMS event index (watermark) |
| `array_name` / `vendor` / `product` | yes | From collector common labels |
| `cluster` / `cluster_uuid` | when probed | Cluster identity |
| `resolved` | bookend resolve | `true` or `timeout` |

Additional parameter attributes (e.g. `volume`, `lun_path`, `svm`) are copied
from EMS `parameters` when present.

### 3.2 Representative message names

Catalog includes (non-exhaustive): `LUN.destroy`, `LUN.offline`,
`NVMeNS.*`, `Nblade.cifs*`, `Nblade.vscan*`, `callhome.*`,
`disk.outOfService`, `diskShelf.psu.*`, `fabricpool.full`,
`fabricpool.nearly.full`, `hm.alert.raised`, `monitor.fan.*`,
`object.store.unavailable`, `qos.monitor.memory.maxed`, `sk.panic`,
`wafl.*`, SnapMirror / MetroCluster / mediator messages, ransomware
(`arw.volume.state`, …).

Bookend example: `LUN.offline` resolves on `LUN.online` or after
`resolve_after` (default `672h`).

### 3.3 LogSQL — raw stream

```logsql
# All EMS for an array
array_name:"ontap-prod"

# Specific message
message:"LUN.offline"

# Hardware / shelf power
message:~"diskShelf|monitor.fan|callhome.battery"

# Vscan / antivirus
message:~"vscan"

# FabricPool capacity
message:~"fabricpool"

# Errors / critical (adjust to your severity strings)
severity:~"(?i)error|alert|emergency|critical"
```

### 3.4 LogSQL — charts

```logsql
# EMS volume over time
array_name:* | stats by (_time:1m) count() as value

# By message name
array_name:* | stats by (_time:5m, message) count() as value

# By severity
array_name:* | stats by (_time:5m, severity) count() as value

# Top messages
array_name:* | stats by (_time:5m, message) count() as value | sort by (value) desc | limit 15

# Bookend resolutions
resolved:* | stats by (_time:1h, resolved) count() as value
```

---

## 4. Example dashboards

Each panel is a Data Studio widget. Use integration kind `victoriametrics` for
`promql` and `victorialogs` for `logsql`.

### 4.1 ONTAP Fleet Overview

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Arrays | metrics | promql | metric | — | `count(count by (array_name) (cluster_total_ops))` |
| Nodes | metrics | promql | metric | — | `count(node_avg_processor_busy)` |
| Aggregates | metrics | promql | metric | — | `count(aggr_space_total)` |
| Volumes | metrics | promql | metric | — | `count(volume_size_used)` |
| Total aggr free | metrics | promql | metric | bytes | `sum(aggr_space_available)` |
| Aggrs > 90% used | metrics | promql | metric | — | `count((100 * aggr_space_used / aggr_space_total) >= 90)` |
| Volumes > 90% used | metrics | promql | metric | — | `count(volume_size_used_percent >= 90)` |
| Cluster IOPS | metrics | promql | timeseries | — | `sum(cluster_total_ops) by (array_name, cluster)` |
| Cluster throughput | metrics | promql | timeseries | bytes | `sum(cluster_total_data) by (array_name, cluster)` |

### 4.2 Node Performance

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| CPU busy | metrics | promql | timeseries | percent | `node_avg_processor_busy` |
| Top 5 CPU | metrics | promql | timeseries | percent | `topk(5, node_avg_processor_busy)` |
| Node IOPS | metrics | promql | timeseries | — | `node_total_ops` |
| Node latency | metrics | promql | timeseries | — | `node_total_latency` |
| Node throughput | metrics | promql | timeseries | bytes | `node_total_data` |
| Network Rx+Tx | metrics | promql | timeseries | — | `sum(node_net_data_recv + node_net_data_sent) by (node, array_name)` |
| Disk data | metrics | promql | timeseries | — | `sum(node_disk_data_read + node_disk_data_written) by (node, array_name)` |
| Failed fans | metrics | promql | metric | — | `sum(node_failed_fan)` |

### 4.3 Aggregate & Volume Capacity

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Aggr capacity | metrics | promql | timeseries | bytes | `aggr_space_total` |
| Aggr free | metrics | promql | timeseries | bytes | `aggr_space_available` |
| Aggr used % | metrics | promql | timeseries | percent | `100 * aggr_space_used / aggr_space_total` |
| Volume used % | metrics | promql | timeseries | percent | `volume_size_used_percent` |
| Top volumes by used % | metrics | promql | timeseries | percent | `topk(10, volume_size_used_percent)` |
| Physical used | metrics | promql | timeseries | bytes | `volume_space_physical_used` |
| Efficiency saved % | metrics | promql | timeseries | percent | `volume_sis_total_saved_percent` |

### 4.4 Volume / LUN Performance

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Volume IOPS | metrics | promql | timeseries | — | `volume_total_ops` |
| Volume throughput | metrics | promql | timeseries | bytes | `volume_total_data` |
| Volume latency | metrics | promql | timeseries | — | `volume_avg_latency` |
| Top volumes by IOPS | metrics | promql | timeseries | — | `topk(10, volume_total_ops)` |
| IOPS by SVM | metrics | promql | timeseries | — | `sum(volume_total_ops) by (svm, array_name)` |
| LUN IOPS | metrics | promql | timeseries | — | `lun_total_ops` |
| LUN latency | metrics | promql | timeseries | — | `lun_total_latency` |
| Namespace IOPS | metrics | promql | timeseries | — | `namespace_total_ops` |

### 4.5 Data Protection (SnapMirror)

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Lag time | metrics | promql | timeseries | s | `snapmirror_lag_time` |
| Lag > 1h | metrics | promql | metric | — | `count(snapmirror_lag_time > 3600)` |
| Last transfer size | metrics | promql | timeseries | bytes | `snapmirror_last_transfer_size` |
| Failed updates | metrics | promql | timeseries | — | `sum(snapmirror_update_failed_count) by (array_name)` |

### 4.6 EMS / Events

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Live EMS stream | logs | logsql | logs | — | `array_name:*` |
| EMS volume | logs | logsql | timeseries | — | `array_name:* \| stats by (_time:1m) count() as value` |
| By severity | logs | logsql | timeseries | — | `array_name:* \| stats by (_time:5m, severity) count() as value` |
| Top messages | logs | logsql | table | — | `array_name:* \| stats by (_time:5m, message) count() as value \| sort by (value) desc \| limit 15` |
| Hardware events | logs | logsql | logs | — | `message:~"diskShelf\|monitor.fan\|callhome.battery\|disk.outOfService"` |
| Vscan events | logs | logsql | logs | — | `message:~"vscan"` |
| Poll counters | metrics | promql | timeseries | — | `ems_events` |

---

## Appendix A — Enumerating metric names

Template-derived family count (repo root):

```bash
go run ./cmd/netapp-parity -templates configs/netapp -v
# or with Harvest catalog parity:
HARVEST_ONTAP_METRICS_JSON=/path/to/harvest/mcp/metadata/ontap_metrics.json make netapp-parity
```

Explore live names in VictoriaMetrics:

```promql
{__name__=~"volume_.*", array_name="ontap-prod"}
{__name__=~"node_.*"}
{__name__=~"aggr_.*"}
{__name__=~"snapmirror_.*"}
{__name__=~"qos_.*"}
{__name__=~"wafl_.*"}
```

Naming rule: `{template.object}_{sanitized_display}` where `display` comes from
Harvest `=>` renames (or the counter path with `.`/`-` → `_`).

---

## Appendix B — Config sketch

```yaml
storage:
  enabled: true
  collect_interval: 60s
  netapp_ontap:
    - name: ontap-prod
      address: https://cluster.example.com
      username: monitor
      password: ${NETAPP_PASSWORD}
      verify_ssl: true
      coverage: full                 # or harvest_default
      collectors: [rest, restperf, keyperf, ems]
      templates_dir: ""              # default configs/netapp
      ems:
        enabled: true
        resolve_after: 672h
      labels:
        datacenter: dc1
```

Schema truth: top-level `storage.netapp_ontap` (not `collector.storage.netapp.targets`).

---

## Appendix C — E-Series (brief)

`storage.netapp_eseries` uses templates under `configs/netapp/eseries` and
`eseriesperf`. Metrics use the template `object` prefix with labels
`vendor=netapp`, `product=eseries`, `array_name=<name>`. This document focuses
on ONTAP; treat E-Series as a sibling collector and discover names with
`{__name__=~".+", product="eseries"}`.

---

## Appendix D — Catalog parity

Telegen targets **100% Harvest ONTAP catalog parity** (1,558 families in
`harvest/mcp/metadata/ontap_metrics.json`). Catalog expansion includes:

- Rest / RestPerf / KeyPerf templates (including `coverage: full` opt-ins and ASA r2)
- Aggregator / Max object renames (`aggr_disk_*`, `node_disk_max_*`, `plex_disk_*`, …)
- MetricAgent / LabelAgent (`*_new_status`, compute metrics)
- VolumeTopClients / Files / Users (`volume_top_*`)
- Sensor / Shelf / Health / FabricPool / QoS / Volume plugin families
- Harvest-compatible `metadata_*` / `poller_*` collector self-metrics

Verify:

```bash
HARVEST_ONTAP_METRICS_JSON=/path/to/harvest/mcp/metadata/ontap_metrics.json make netapp-parity
```

`configs/netapp/parity-allowlist.txt` must stay empty of metric names. Prefer
live `{__name__=~...}` discovery when wiring a new dashboard panel.
