# VMware vCenter → MIRASTACK Data Studio Query Reference

This document catalogs **every metric and log signal** emitted by Telegen's native
VMware vCenter collector and provides **ready-to-paste PromQL and LogSQL queries**
formatted for the **MIRASTACK UI Data Studio** dashboard builder.

Use it to build dashboards in Data Studio: pick an integration (data source),
choose a chart type, and paste the query.

- **Metrics source:** `internal/vmware/` (govmomi collector) — Prometheus-style
  `vmware_*` gauges exported over OTLP.
- **Logs source:** `internal/vmware/events.go` — vCenter EventManager events plus
  synthesized inventory state-change logs, exported over the OTLP log bridge.

---

## 1. Overview and caveats

### 1.1 Which collector this covers

Telegen ships **two** unrelated VMware code paths. This document covers the
**native vCenter collector mode** only:

| Collector | Path | Metric naming | Logs | Covered here |
|-----------|------|---------------|------|--------------|
| **Native govmomi (vCenter collector mode)** | `internal/vmware/` | `vmware_<subsystem>_<field>` (underscores) | Yes | **Yes** |
| Cloud "unified" REST collector | `internal/cloud/unified/collectors/vmware.go` | `vmware.<object>.<field>` (dots) | No | No (see Appendix B) |

If your queries return nothing, first confirm which collector is feeding your
data source — the metric name shape (`vmware_host_...` vs `vmware.host....`)
tells you immediately.

### 1.2 Everything is a gauge — do NOT use `rate()`

Both inventory metrics (`addGauge`, `collectors.go`) and performance metrics
(`emitPerformanceMetrics`, `collect.go`) are emitted as **gauges**
(`vmwaredef.MetricTypeGauge`). No counters or histograms are produced.

Performance counters are emitted **per vCenter sample** (one OTLP data point
per `PerfSampleInfo` entry) with the source timestamp preserved. Counter names
like `*.summation` or `*.average` still represent vSphere's own semantics and
arrive as gauge values, not monotonic counters.

Consequences for PromQL:

- **Do not** wrap these metrics in `rate()`, `irate()`, or `increase()` — those
  functions assume a monotonic counter and will produce wrong or empty results.
- To smooth or aggregate over time, use gauge-friendly functions:
  `avg_over_time(...)`, `max_over_time(...)`, `min_over_time(...)`,
  `sum(...) by (...)`, `topk(...)`.
- To display "per second" style rates for `.summation` counters (e.g.
  `cpu.ready.summation`), divide the summed milliseconds by the collection
  interval yourself if needed — the raw value is a summed quantity over the
  sample window.

### 1.3 Label glossary

Every metric carries `vcenter`. Object metrics carry identity labels:

| Label | Meaning |
|-------|---------|
| `vcenter` | Target vCenter address (present on **all** metrics and logs) |
| `dc` / `dcmo` | Datacenter name / managed-object reference |
| `foldermo` | Folder managed-object reference |
| `cmo` | Cluster or compute-resource managed-object reference |
| `vmwcluster` | Cluster name |
| `datastores` | Comma-joined datastore moref list (cluster/compute info metrics) |
| `host` / `hostmo` | ESXi host name / moref |
| `vm` / `vmmo` | Virtual machine name / moref |
| `ds` / `dsmo` | Datastore name / moref |
| `type` | Datastore type (e.g. `VMFS`, `NFS`) |
| `pfinstance` | Performance instance (e.g. a specific vNIC or disk); also datastore URL-derived instance |
| `vendor` / `model` / `cpu_type` | Host hardware info labels |
| `software` / `version` / `build` / `patch` | Product/version info labels |
| `name` / `created` | Snapshot name / creation timestamp (RFC3339) |

Any operator-configured `extra_labels` are merged into every metric and log
record (`metrics_exporter.go`, `logs_exporter.go`).

Resource attributes applied to all telemetry: `service.name=telegen-vmware`;
instrumentation scope `telegen.vmware`. Depending on your VictoriaMetrics OTLP
ingestion settings these may surface as extra labels (e.g. `otel_scope_name`).

### 1.4 How Data Studio sends these queries

The MIRASTACK UI browser never calls VictoriaMetrics/VictoriaLogs directly — it
proxies through the BFF at `/api/v1/integrations/:id/proxy/*`. What matters for
authoring is:

**Metrics widgets** — integration kind `victoriametrics`, `queryType: promql`:

- A single-value widget (`chartType: metric`) is sent to the **instant** endpoint
  `/api/v1/query`. Use a scalar/vector-reducing expression (e.g. `sum(...)`).
- Any time-series widget is sent to **range** `/api/v1/query_range` with
  `start`, `end` (Unix seconds) and `step` (e.g. `60s`). The toolbar supplies the
  time window and step — you only author the `query`.

**Logs widgets** — integration kind `victorialogs`, `queryType: logsql`:

- A raw `logs` or `table` widget is sent to `/select/logsql/query`. A bare filter
  is fine (no stats pipe required).
- A **chart** widget is sent to `/select/logsql/stats_query_range` and **must**
  produce a series aliased `value`, using the canonical stats order where the
  `by (...)` clause comes **before** the aggregation function:

  ```
  <filter> | stats by (_time:<bucket>[, <group fields>]) <aggFn>(<field?>) as value
  ```

  Example: `event_type:* | stats by (_time:1m) count() as value`. The legacy
  order (`| stats count() as value by (...)`) is rejected/rewritten by Data
  Studio, so always author the canonical order.

Each Data Studio widget is defined by: `integrationId`, `signalType`
(`metrics` | `logs`), `queryType` (`promql` | `logsql`), `query`, `chartType`,
and optional `unit` / `thresholds`.

### 1.5 Log field-name caveat

Telegen emits logs as OTLP records whose **attributes** (see the tables in
section 3) become queryable fields in VictoriaLogs, with the record body mapped
to `_msg`. The exact VictoriaLogs field name for each attribute depends on your
OTLP → VictoriaLogs ingestion mapping (some setups prefix or flatten attribute
keys). The LogSQL queries below use the attribute keys verbatim
(`event_type`, `change`, `host`, `vm`, `ds`, ...). **Validate the field names
against a live VictoriaLogs instance** using `field_names` before finalizing
dashboards; adjust filter keys if your ingestion prefixes them.

---

## 2. Metrics catalog

All PromQL below assumes a single vCenter. To scope to a specific target, add a
`vcenter="<address>"` matcher, e.g. `vmware_host_info{vcenter="vcsa.corp.local"}`.

### 2.1 vCenter server / Datacenter / Folder

Source: `collectDatacenter` (`collectors.go`). All are info gauges valued `1.0`.

| Metric | Type | Meaning | Labels |
|--------|------|---------|--------|
| `vmware_vcenter_info` | gauge | vCenter server build/version | `version`, `build`, `patch`, `vcenter` |
| `vmware_datacenter_info` | gauge | Datacenter identity | `dcmo`, `dc`, `vcenter` |
| `vmware_folder_info` | gauge | `host`/`datastore` folder identity | `foldermo`, `dc`, `dcmo`, `vcenter` |

Queries:

```promql
# vCenter build info (metric / stat widget)
vmware_vcenter_info

# Datacenter count (metric widget, chartType: metric → instant query)
count(vmware_datacenter_info)
```

- Suggested `chartType`: `table` (info attributes) or `metric` (counts). `unit`: none.

### 2.2 Cluster / Compute

Source: `collectCluster` (`collectors.go:109-152`). `compute_*` metrics are a
fallback emitted only when no clusters exist.

| Metric | Type | Meaning | Labels |
|--------|------|---------|--------|
| `vmware_cluster_info` | gauge | Cluster identity | `cmo`, `vmwcluster`, `foldermo`, `vcenter` |
| `vmware_cluster_datastores` | gauge | Datastore moref list for a cluster | `cmo`, `vmwcluster`, `datastores`, `vcenter` |
| `vmware_compute_info` | gauge | Standalone compute resource identity (fallback) | `cmo`, `host`, `foldermo`, `vcenter` |
| `vmware_compute_datastores` | gauge | Datastore list for compute resource (fallback) | `cmo`, `host`, `datastores`, `vcenter` |

Queries:

```promql
# Cluster inventory (table widget)
vmware_cluster_info

# Number of clusters (metric widget)
count(vmware_cluster_info)
```

### 2.3 Datastore

Sources: inventory `collectDatastoreFromData` (`collectors.go`);
performance counters `datastoreCounters` (`collectors.go`).
Datastore performance counters are sampled on vCenter's 300s interval and are
re-emitted only when a new 300s sample window is available.

| Metric | Type | Unit | Meaning | Labels |
|--------|------|------|---------|--------|
| `vmware_datastore_info` | gauge | — | Datastore identity | `dsmo`, `ds`, `type`, `pfinstance`, `foldermo`, `vcenter` |
| `vmware_datastore_capacity` | gauge | bytes | Total capacity | `dsmo`, `ds`, `vcenter` |
| `vmware_datastore_free` | gauge | bytes | Free space | `dsmo`, `ds`, `vcenter` |
| `vmware_datastore_accessible` | gauge | 0/1 | Accessibility flag | `dsmo`, `ds`, `vcenter` |
| `vmware_datastore_disk_provisioned_latest` | gauge | KB | Provisioned disk (perf) | `ds`, `dsmo`, `vcenter` (+`pfinstance`) |
| `vmware_datastore_disk_used_latest` | gauge | KB | Used disk (perf) | `ds`, `dsmo`, `vcenter` (+`pfinstance`) |

Queries:

```promql
# Datastore free space per datastore (timeseries)
vmware_datastore_free

# Datastore total capacity per datastore (timeseries)
vmware_datastore_capacity

# Datastore used percent (timeseries or gauge) — derived
100 * (1 - vmware_datastore_free / vmware_datastore_capacity)

# Datastores above 90% used (table / stat) — instant
count(100 * (1 - vmware_datastore_free / vmware_datastore_capacity) >= 90)

# Inaccessible datastores (stat) — instant
count(vmware_datastore_accessible == 0)

# Total free capacity across the estate (metric widget) — instant
sum(vmware_datastore_free)
```

- Suggested `unit`: `bytes` for capacity/free; `percent` for used%.

### 2.4 Host / ESXi

Sources: inventory `collectHostFromData` (`collectors.go`); performance
counters `cHostCounters` + `iHostCounters` (`collectors.go`). Only hosts
that are powered-on, connected, and not in maintenance are scraped.

**Inventory:**

| Metric | Type | Unit | Meaning | Labels |
|--------|------|------|---------|--------|
| `vmware_host_info` | gauge | — | Host identity | `hostmo`, `host`, `cmo`, `vcenter` |
| `vmware_host_hardware_info` | gauge | — | Hardware make/model/CPU | `hostmo`, `host`, `vendor`, `model`, `cpu_type`, `vcenter` |
| `vmware_host_software_info` | gauge | — | ESXi product/version/build | `hostmo`, `host`, `software`, `version`, `build`, `vcenter` |
| `vmware_host_cpu_corecount` | gauge | cores | Physical CPU cores | `hostmo`, `host`, `vcenter` |
| `vmware_host_cpu_threadcount` | gauge | threads | Logical (HT) threads | `hostmo`, `host`, `vcenter` |
| `vmware_host_cpu_capacity` | gauge | MHz | Per-core frequency | `hostmo`, `host`, `vcenter` |
| `vmware_host_mem_capacity` | gauge | MB | Installed RAM | `hostmo`, `host`, `vcenter` |

**Performance** (labels `vcenter`, `host`, `hostmo`; network/datastore counters also carry `pfinstance`). Units follow the vSphere counter definition (embedded in each metric's Help string):

| Metric | vSphere unit |
|--------|--------------|
| `vmware_host_cpu_usagemhz_average` | MHz |
| `vmware_host_cpu_demand_average` | MHz |
| `vmware_host_cpu_latency_average` | percent |
| `vmware_host_cpu_entitlement_latest` | MHz |
| `vmware_host_cpu_ready_summation` | ms (summed over window) |
| `vmware_host_cpu_readiness_average` | percent |
| `vmware_host_cpu_costop_summation` | ms (summed over window) |
| `vmware_host_cpu_maxlimited_summation` | ms (summed over window) |
| `vmware_host_mem_entitlement_average` | KB |
| `vmware_host_mem_active_average` | KB |
| `vmware_host_mem_shared_average` | KB |
| `vmware_host_mem_vmmemctl_average` | KB (balloon) |
| `vmware_host_mem_swapped_average` | KB |
| `vmware_host_mem_consumed_average` | KB |
| `vmware_host_sys_uptime_latest` | seconds |
| `vmware_host_net_bytesRx_average` | KBps |
| `vmware_host_net_bytesTx_average` | KBps |
| `vmware_host_net_errorsRx_summation` | count (summed) |
| `vmware_host_net_errorsTx_summation` | count (summed) |
| `vmware_host_net_droppedRx_summation` | count (summed) |
| `vmware_host_net_droppedTx_summation` | count (summed) |
| `vmware_host_datastore_read_average` | KBps |
| `vmware_host_datastore_write_average` | KBps |
| `vmware_host_datastore_numberReadAveraged_average` | IOPS |
| `vmware_host_datastore_numberWriteAveraged_average` | IOPS |
| `vmware_host_datastore_totalReadLatency_average` | ms |
| `vmware_host_datastore_totalWriteLatency_average` | ms |

Queries:

```promql
# Powered-on/connected hosts (metric widget) — instant
count(vmware_host_info)

# Per-host CPU usage in MHz (timeseries)
vmware_host_cpu_usagemhz_average

# Host CPU usage as a percent of capacity (timeseries) — derived
100 * vmware_host_cpu_usagemhz_average
  / on(hostmo, vcenter) (vmware_host_cpu_capacity * vmware_host_cpu_corecount)

# Host consumed memory in bytes (timeseries) — mem.*.average is in KB
vmware_host_mem_consumed_average * 1024

# Host memory consumed as percent of installed RAM — derived
100 * (vmware_host_mem_consumed_average / 1024)
  / on(hostmo, vcenter) vmware_host_mem_capacity

# CPU ready (contention) per host (timeseries), ms summed over the window
vmware_host_cpu_ready_summation

# Host network throughput Rx+Tx (timeseries), KBps summed across vNICs per host
sum(vmware_host_net_bytesRx_average + vmware_host_net_bytesTx_average) by (host, vcenter)

# Datastore read/write latency per host (timeseries), ms
sum(vmware_host_datastore_totalReadLatency_average) by (host, vcenter)

# Top 5 hosts by CPU usage (timeseries) — instant-friendly for stat too
topk(5, vmware_host_cpu_usagemhz_average)

# Host uptime in days (table/stat)
vmware_host_sys_uptime_latest / 86400
```

### 2.5 Virtual Machine

Sources: inventory `collectVMFromData` (`collectors.go`); performance
counters `cVMCounters` + `iVMCounters` (`collectors.go`). Only powered-on
VMs are scraped.

**Inventory:**

| Metric | Type | Unit | Meaning | Labels |
|--------|------|------|---------|--------|
| `vmware_vm_info` | gauge | — | VM identity + host placement | `vmmo`, `vm`, `hostmo`, `vcenter` |
| `vmware_vm_cpu_corecount` | gauge | vCPUs | Configured virtual CPUs | `vmmo`, `vm`, `hostmo`, `vcenter` |
| `vmware_vm_mem_capacity` | gauge | MB | Configured memory | `vmmo`, `vm`, `hostmo`, `vcenter` |
| `vmware_vm_datastore_capacity_used` | gauge | bytes | Committed storage per datastore | `vmmo`, `vm`, `vcenter`, `dsmo` |
| `vmware_vm_snapshot_info` | gauge | unix ts | Snapshot creation time (epoch seconds) | `vmmo`, `vm`, `vcenter`, `name`, `created` |

**Performance** (labels `vcenter`, `vm`, `vmmo`; network/datastore counters also carry `pfinstance`):

| Metric | vSphere unit |
|--------|--------------|
| `vmware_vm_cpu_usagemhz_average` | MHz |
| `vmware_vm_cpu_demand_average` | MHz |
| `vmware_vm_cpu_latency_average` | percent |
| `vmware_vm_cpu_entitlement_latest` | MHz |
| `vmware_vm_cpu_ready_summation` | ms (summed over window) |
| `vmware_vm_cpu_readiness_average` | percent |
| `vmware_vm_cpu_costop_summation` | ms (summed over window) |
| `vmware_vm_cpu_maxlimited_summation` | ms (summed over window) |
| `vmware_vm_mem_entitlement_average` | KB |
| `vmware_vm_mem_active_average` | KB |
| `vmware_vm_mem_shared_average` | KB |
| `vmware_vm_mem_vmmemctl_average` | KB (balloon) |
| `vmware_vm_mem_swapped_average` | KB |
| `vmware_vm_mem_consumed_average` | KB |
| `vmware_vm_sys_uptime_latest` | seconds |
| `vmware_vm_net_bytesRx_average` | KBps |
| `vmware_vm_net_bytesTx_average` | KBps |
| `vmware_vm_datastore_read_average` | KBps |
| `vmware_vm_datastore_write_average` | KBps |
| `vmware_vm_datastore_numberReadAveraged_average` | IOPS |
| `vmware_vm_datastore_numberWriteAveraged_average` | IOPS |
| `vmware_vm_datastore_totalReadLatency_average` | ms |
| `vmware_vm_datastore_totalWriteLatency_average` | ms |

Queries:

```promql
# Powered-on VMs (metric widget) — instant
count(vmware_vm_info)

# VMs per host (table/bar) — instant
count(vmware_vm_info) by (hostmo, vcenter)

# Per-VM CPU usage in MHz (timeseries)
vmware_vm_cpu_usagemhz_average

# CPU ready per VM (contention indicator), ms summed over window (timeseries)
vmware_vm_cpu_ready_summation

# VM memory ballooning (memory pressure signal), bytes (timeseries)
vmware_vm_mem_vmmemctl_average * 1024

# VM active memory as percent of configured memory — derived
100 * (vmware_vm_mem_active_average / 1024)
  / on(vmmo, vcenter) vmware_vm_mem_capacity

# Committed storage per VM across all datastores, bytes (timeseries)
sum(vmware_vm_datastore_capacity_used) by (vm, vcenter)

# Top 10 noisiest VMs by network throughput (timeseries)
topk(10, sum(vmware_vm_net_bytesRx_average + vmware_vm_net_bytesTx_average) by (vm, vcenter))

# Snapshot age in days (table/stat) — flags stale snapshots
(time() - vmware_vm_snapshot_info) / 86400

# Snapshots older than 7 days (metric widget) — instant
count((time() - vmware_vm_snapshot_info) / 86400 > 7)
```

### 2.6 Scrape health metrics

Source: `addScrapeResult` (`health.go`) with call sites in `manager.go`.
These gauges report collection outcomes per target and collector unit.

| Metric | Type | Meaning | Labels |
|--------|------|---------|--------|
| `vmware_scrape_collector_success` | gauge | Collector result (1=success, 0=failure) | `collector`, `vcenter` |
| `vmware_scrape_collector_duration_seconds` | gauge | Collector wall-clock duration in seconds | `collector`, `vcenter` |

`collector` label values:

- `login`
- `datacenter`
- `cluster`
- `datastore`
- `host`
- `vm`
- `esxcli_storage`
- `esxcli_host_nic`
- `events`
- `export`
- `all_collectors`

Interpretation details:

- `success == 0` means that collector unit returned an error or panicked.
- `export` is reported one cycle later (carried forward in target state), because
  an export failure cannot describe itself inside the failed batch.

PromQL example:

```promql
vmware_scrape_collector_success == 0
```

---

## 3. Logs catalog

Source: `internal/vmware/events.go`, exported via the OTLP log bridge
(`logs_exporter.go`). Two log families exist. Both are gated by
`events.enabled` (and state-changes additionally by `events.state_changes`).

Severity is normalized to `trace | debug | info | warn | error`
(`mapEventSeverity`, `events.go:205-233`).

### 3.1 vCenter EventManager events

Each event drained from the vCenter EventManager becomes one log record
(`eventToRecord`, `events.go:141-176`). The body is the vSphere
`FullFormattedMessage`.

| Field | Always present? | Meaning |
|-------|-----------------|---------|
| `_msg` (body) | yes | Full formatted vCenter event message |
| `vcenter` | yes | Target vCenter address |
| `event_type` | yes | vSphere event type id (open-ended set, e.g. `VmPoweredOffEvent`, `AlarmStatusChangedEvent`, `UserLoginSessionEvent`) |
| `user` | when set | User associated with the event |
| `datacenter` | when set | Datacenter name |
| `compute_resource` | when set | Cluster/compute resource name |
| `host` | when set | Host name |
| `vm` | when set | VM name |
| `ds` | when set | Datastore name |

> The `event_type` set is whatever vSphere emits — it is not a fixed enum in
> Telegen. Use `field_values` on `event_type` against a live instance to
> discover the concrete types in your environment.

LogSQL — raw log stream (`logs` / `table` widget, `/select/logsql/query`):

```logsql
# All vCenter events for a host
event_type:* host:"esx01.corp.local"

# Login/session activity
event_type:~"Login|Logout|Session"

# Errors and warnings only (relies on severity being ingested; adjust field name)
event_type:* AND (Error OR Warning)
```

LogSQL — chart form (`stats_query_range`, canonical `by(...)` before agg):

```logsql
# Event volume over time
event_type:* | stats by (_time:1m) count() as value

# Event volume by type (multi-series)
event_type:* | stats by (_time:1m, event_type) count() as value

# Top event types over the window
event_type:* | stats by (_time:5m, event_type) count() as value | sort by (value) desc | limit 10

# Events by user
event_type:* | stats by (_time:5m, user) count() as value
```

### 3.2 Synthesized inventory state-change logs

The collector diffs successive inventory snapshots and emits four kinds of
state-change logs (`collectStateChangesFromData`, `events.go:276-367`). All carry
`vcenter` and `source="state_change"` (`stateRecord`, `events.go:369-381`).

| Body (message) | Severity | `change` | Extra fields |
|----------------|----------|----------|--------------|
| `VM <name> power state changed from <prev> to <power>` | warn | `vm_power` | `vm`, `vmmo`, `from`, `to` |
| `VM <name> snapshot created` | info | `vm_snapshot` | `vm`, `vmmo`, `snapshots` |
| `Host <name> connection state changed from <prev> to <conn>` | info (warn if new state ≠ `connected`) | `host_connection` | `host`, `hostmo`, `from`, `to` |
| `Datastore <name> crossed used-capacity threshold` | warn | `datastore_pressure` | `ds`, `dsmo` |

The datastore pressure threshold is `0.90` used (`datastoreUsedThreshold`,
`events.go:23`).

LogSQL — raw state-change stream:

```logsql
# All state changes
source:"state_change"

# VM power transitions only
source:"state_change" change:"vm_power"

# Host disconnect/connection changes
source:"state_change" change:"host_connection"

# Datastore capacity-pressure crossings
source:"state_change" change:"datastore_pressure"

# New snapshots created
source:"state_change" change:"vm_snapshot"
```

LogSQL — chart form:

```logsql
# State-change volume by kind over time (multi-series)
source:"state_change" | stats by (_time:5m, change) count() as value

# VM power-change events per interval
source:"state_change" change:"vm_power" | stats by (_time:5m) count() as value

# Datastore pressure crossings per hour
source:"state_change" change:"datastore_pressure" | stats by (_time:1h) count() as value
```

---

## 4. Example dashboards

Each panel below is a Data Studio widget. Pick the matching integration
(`victoriametrics` for `promql`, `victorialogs` for `logsql`), set the chart
type and unit, and paste the query. Layout (`w`/`h`) is a suggestion.

### 4.1 vCenter Fleet Overview

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Powered-on hosts | metrics | promql | metric | — | `count(vmware_host_info)` |
| Powered-on VMs | metrics | promql | metric | — | `count(vmware_vm_info)` |
| Clusters | metrics | promql | metric | — | `count(vmware_cluster_info)` |
| Datastores | metrics | promql | metric | — | `count(vmware_datastore_info)` |
| Total datastore capacity | metrics | promql | metric | bytes | `sum(vmware_datastore_capacity)` |
| Total datastore free | metrics | promql | metric | bytes | `sum(vmware_datastore_free)` |
| Datastores > 90% used | metrics | promql | metric | — | `count(100 * (1 - vmware_datastore_free / vmware_datastore_capacity) >= 90)` |
| VMs per host | metrics | promql | table | — | `count(vmware_vm_info) by (hostmo, vcenter)` |
| Host inventory | metrics | promql | table | — | `vmware_host_hardware_info` |

### 4.2 Host / ESXi Performance

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Host CPU usage (MHz) | metrics | promql | timeseries | — | `vmware_host_cpu_usagemhz_average` |
| Host CPU usage (%) | metrics | promql | timeseries | percent | `100 * vmware_host_cpu_usagemhz_average / on(hostmo, vcenter) (vmware_host_cpu_capacity * vmware_host_cpu_corecount)` |
| Host CPU ready (ms) | metrics | promql | timeseries | ms | `vmware_host_cpu_ready_summation` |
| Host consumed memory (bytes) | metrics | promql | timeseries | bytes | `vmware_host_mem_consumed_average * 1024` |
| Host memory used (%) | metrics | promql | timeseries | percent | `100 * (vmware_host_mem_consumed_average / 1024) / on(hostmo, vcenter) vmware_host_mem_capacity` |
| Host network throughput (KBps) | metrics | promql | timeseries | — | `sum(vmware_host_net_bytesRx_average + vmware_host_net_bytesTx_average) by (host, vcenter)` |
| Host datastore read latency (ms) | metrics | promql | timeseries | ms | `sum(vmware_host_datastore_totalReadLatency_average) by (host, vcenter)` |
| Host datastore write latency (ms) | metrics | promql | timeseries | ms | `sum(vmware_host_datastore_totalWriteLatency_average) by (host, vcenter)` |
| Top 5 hosts by CPU | metrics | promql | timeseries | — | `topk(5, vmware_host_cpu_usagemhz_average)` |
| Host uptime (days) | metrics | promql | table | — | `vmware_host_sys_uptime_latest / 86400` |

### 4.3 VM Performance

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| VM CPU usage (MHz) | metrics | promql | timeseries | — | `vmware_vm_cpu_usagemhz_average` |
| VM CPU ready (ms) | metrics | promql | timeseries | ms | `vmware_vm_cpu_ready_summation` |
| VM active memory (%) | metrics | promql | timeseries | percent | `100 * (vmware_vm_mem_active_average / 1024) / on(vmmo, vcenter) vmware_vm_mem_capacity` |
| VM ballooned memory (bytes) | metrics | promql | timeseries | bytes | `vmware_vm_mem_vmmemctl_average * 1024` |
| VM swapped memory (bytes) | metrics | promql | timeseries | bytes | `vmware_vm_mem_swapped_average * 1024` |
| VM committed storage (bytes) | metrics | promql | timeseries | bytes | `sum(vmware_vm_datastore_capacity_used) by (vm, vcenter)` |
| Top 10 VMs by network | metrics | promql | timeseries | — | `topk(10, sum(vmware_vm_net_bytesRx_average + vmware_vm_net_bytesTx_average) by (vm, vcenter))` |
| VM datastore IOPS (read) | metrics | promql | timeseries | — | `sum(vmware_vm_datastore_numberReadAveraged_average) by (vm, vcenter)` |
| Snapshot age (days) | metrics | promql | table | — | `(time() - vmware_vm_snapshot_info) / 86400` |
| Stale snapshots (> 7d) | metrics | promql | metric | — | `count((time() - vmware_vm_snapshot_info) / 86400 > 7)` |

### 4.4 Datastore Capacity & Pressure

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Capacity per datastore | metrics | promql | timeseries | bytes | `vmware_datastore_capacity` |
| Free per datastore | metrics | promql | timeseries | bytes | `vmware_datastore_free` |
| Used % per datastore | metrics | promql | timeseries | percent | `100 * (1 - vmware_datastore_free / vmware_datastore_capacity)` |
| Provisioned disk (KB) | metrics | promql | timeseries | — | `vmware_datastore_disk_provisioned_latest` |
| Used disk (KB) | metrics | promql | timeseries | — | `vmware_datastore_disk_used_latest` |
| Inaccessible datastores | metrics | promql | metric | — | `count(vmware_datastore_accessible == 0)` |
| Pressure crossings over time | logs | logsql | timeseries | — | `source:"state_change" change:"datastore_pressure" \| stats by (_time:1h) count() as value` |
| Recent pressure events | logs | logsql | logs | — | `source:"state_change" change:"datastore_pressure"` |

### 4.5 vCenter Events & State Changes

| Panel | signalType | queryType | chartType | unit | query |
|-------|-----------|-----------|-----------|------|-------|
| Live event stream | logs | logsql | logs | — | `event_type:*` |
| Event volume over time | logs | logsql | timeseries | — | `event_type:* \| stats by (_time:1m) count() as value` |
| Top event types | logs | logsql | table | — | `event_type:* \| stats by (_time:5m, event_type) count() as value \| sort by (value) desc \| limit 10` |
| State changes by kind | logs | logsql | timeseries | — | `source:"state_change" \| stats by (_time:5m, change) count() as value` |
| VM power transitions | logs | logsql | logs | — | `source:"state_change" change:"vm_power"` |
| Host connection changes | logs | logsql | logs | — | `source:"state_change" change:"host_connection"` |
| New snapshots | logs | logsql | logs | — | `source:"state_change" change:"vm_snapshot"` |

---

## Appendix A — Full raw metric name list

Inventory gauges:

```
vmware_vcenter_info
vmware_datacenter_info
vmware_folder_info
vmware_cluster_info
vmware_cluster_datastores
vmware_compute_info
vmware_compute_datastores
vmware_datastore_info
vmware_datastore_capacity
vmware_datastore_free
vmware_datastore_accessible
vmware_host_info
vmware_host_hardware_info
vmware_host_software_info
vmware_host_cpu_corecount
vmware_host_cpu_threadcount
vmware_host_cpu_capacity
vmware_host_mem_capacity
vmware_vm_info
vmware_vm_cpu_corecount
vmware_vm_mem_capacity
vmware_vm_datastore_capacity_used
vmware_vm_snapshot_info
vmware_esxcli_storage_driver
vmware_esxcli_host_nic_driver
vmware_scrape_collector_success
vmware_scrape_collector_duration_seconds
collector_clock_skew_seconds
collector_timestamp_fallback_total
```

Datastore performance gauges:

```
vmware_datastore_disk_provisioned_latest
vmware_datastore_disk_used_latest
```

Host performance gauges:

```
vmware_host_cpu_usagemhz_average
vmware_host_cpu_demand_average
vmware_host_cpu_latency_average
vmware_host_cpu_entitlement_latest
vmware_host_cpu_ready_summation
vmware_host_cpu_readiness_average
vmware_host_cpu_costop_summation
vmware_host_cpu_maxlimited_summation
vmware_host_mem_entitlement_average
vmware_host_mem_active_average
vmware_host_mem_shared_average
vmware_host_mem_vmmemctl_average
vmware_host_mem_swapped_average
vmware_host_mem_consumed_average
vmware_host_sys_uptime_latest
vmware_host_net_bytesRx_average
vmware_host_net_bytesTx_average
vmware_host_net_errorsRx_summation
vmware_host_net_errorsTx_summation
vmware_host_net_droppedRx_summation
vmware_host_net_droppedTx_summation
vmware_host_datastore_read_average
vmware_host_datastore_write_average
vmware_host_datastore_numberReadAveraged_average
vmware_host_datastore_numberWriteAveraged_average
vmware_host_datastore_totalReadLatency_average
vmware_host_datastore_totalWriteLatency_average
```

VM performance gauges:

```
vmware_vm_cpu_usagemhz_average
vmware_vm_cpu_demand_average
vmware_vm_cpu_latency_average
vmware_vm_cpu_entitlement_latest
vmware_vm_cpu_ready_summation
vmware_vm_cpu_readiness_average
vmware_vm_cpu_costop_summation
vmware_vm_cpu_maxlimited_summation
vmware_vm_mem_entitlement_average
vmware_vm_mem_active_average
vmware_vm_mem_shared_average
vmware_vm_mem_vmmemctl_average
vmware_vm_mem_swapped_average
vmware_vm_mem_consumed_average
vmware_vm_sys_uptime_latest
vmware_vm_net_bytesRx_average
vmware_vm_net_bytesTx_average
vmware_vm_datastore_read_average
vmware_vm_datastore_write_average
vmware_vm_datastore_numberReadAveraged_average
vmware_vm_datastore_numberWriteAveraged_average
vmware_vm_datastore_totalReadLatency_average
vmware_vm_datastore_totalWriteLatency_average
```

> Note: perf counter names preserve camelCase from vSphere (e.g. `bytesRx`,
> `numberReadAveraged`); only the dots in the vSphere counter id are converted to
> underscores (`collect.go`).

## Appendix B — Excluded: cloud "unified" REST collector

The file `internal/cloud/unified/collectors/vmware.go` is a **separate** collector
that talks to the vSphere REST API and emits dot-named metrics
(`vmware.host.count`, `vmware.vm.total`, `vmware.datastore.capacity_bytes`, ...)
with a `provider="vmware"` label and **no logs**. It is part of the cloud
"unified" subsystem, not the native vCenter collector mode, and is intentionally
out of scope for this document. If your data source shows `vmware.*`
(dot-separated) metric names, you are querying that collector instead and the
PromQL/label names in this document will not match.
