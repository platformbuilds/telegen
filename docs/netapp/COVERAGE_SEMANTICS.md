# NetApp ONTAP Coverage Semantics

## Overview
Telegen provides two coverage profiles for NetApp ONTAP collectors: `full` and `harvest_default`. These profiles control which ONTAP objects are collected, balancing completeness against cardinality cost.

## Coverage Profiles

### `harvest_default` (Recommended for Production)
Mirrors NetApp Harvest's default catalog (`conf/rest/default.yaml`), which **disables high-cardinality objects** known to overwhelm monitoring backends in large deployments.

**Disabled objects:**
| Object | Reason | Typical Cardinality |
|--------|--------|---------------------|
| `CIFSSession` | High per-client cardinality | 1000-10000+ per cluster |
| `Lock` | One series per open file lock | 10000-100000+ per cluster |
| `NetConnections` | One series per TCP connection | 5000-50000+ per cluster |
| `NFSClients` | One series per NFS client mount | 1000-10000+ per cluster |
| `MAVRequest` | Rarely used (multi-admin verify) | N/A |
| `NDMPSession` | Rarely used (tape backup) | N/A |
| `AuditLog` | Configuration object, not metrics | N/A |
| `CIFSShare` | Configuration object, not metrics | N/A |
| `ExportRule` | Configuration object, not metrics | N/A |
| `Mediator` | MetroCluster only | N/A |
| `VolumeEfficiency` | Duplicate of AggregateEfficiency | N/A |

**Enabled objects:** 60+ REST, 20+ RestPerf, 12+ KeyPerf objects covering:
- Aggregates, Volumes, LUNs, Namespaces
- Nodes, Disks, Shelves, FRUs
- Quotas, Qtrees, SnapMirror, Snapshots
- Networking (LIFs, Ports, Routes)
- QoS Policies, Workloads
- Security, Licenses, Health
- Performance counters for all storage and network layers

### `full` (Use with Caution)
Enables **all** 70+ shipped templates, including the high-cardinality objects above. Only use `full` when:
- You explicitly need per-client or per-session metrics (e.g., chargeback, compliance)
- Your monitoring backend can handle 100k+ active time series
- You understand the storage, ingestion, and query performance costs

**Cardinality Impact Example:**
A 4-node cluster with 100 volumes and 1000 active NFS clients:
- `harvest_default`: ~15,000 time series
- `full`: ~50,000 time series (3.3x increase)

## Configuration

### Agent Config (`telegen-config.yaml`)
```yaml
storage:
  netapp_ontap:
    - name: prod-ontap-01
      address: 192.168.1.10
      username: admin
      password: netapp123
      coverage: harvest_default  # or "full"
```

### Defaults
- If `coverage` is omitted or empty: **defaults to `full`** for backward compatibility
- **Recommendation:** Explicitly set `coverage: harvest_default` for new deployments

## Template Resolution

### Catalog Loading
Each collector kind loads a default catalog:
- REST: `configs/netapp/rest/default.yaml`
- RestPerf: `configs/netapp/restperf/default.yaml`
- KeyPerf: (no catalog; probes counter tables)

Catalog files contain:
```yaml
collector: Rest

objects:
  Aggregate: aggr.yaml
  Volume: volume.yaml
# CIFSSession: cifs_session.yaml  # ← Commented = disabled in harvest_default
```

### Filtering Logic
```go
includeDisabled := c.Coverage == storagedef.CoverageFull || c.Coverage == ""
catalog := template.LoadCatalog(fsys, "rest", "default.yaml")
for objectName, templateFile := range catalog {
    if strings.HasPrefix(objectName, "#") && !includeDisabled {
        // Skip commented-out (disabled) objects
        continue
    }
    // Load and collect...
}
```

**Key Rule:** Template file names starting with `#` are treated as disabled.

## Version Fallback Removal (2026-08-13)

### Previous Behavior (Removed)
`probe.go:parseVersionFromFull()` silently fell back to `"9.12.0"` if version parsing failed, masking configuration/network issues.

### Current Behavior
Version parsing now returns empty string on failure, causing template resolution to fail **loudly** with a clear error:
```
ERROR: template not found for object 'volume' at version ''
```

**Rationale:** Fail-fast is preferable to silently using an arbitrary version that may:
- Load incompatible templates (wrong schema)
- Miss new counters/fields
- Export incorrect metric names

## Monitoring Best Practices

### Start with `harvest_default`
```yaml
coverage: harvest_default
```

### Enable `full` only if needed
```yaml
coverage: full
```

### Audit Cardinality
Use Prometheus queries to audit actual series counts:
```promql
count({job="telegen", __name__=~"netapp_.*"}) by (__name__)
```

### Watch for Cardinality Explosion
Symptoms:
- Prometheus ingestion lag
- Slow queries (especially for dashboards)
- OOM errors in Prometheus or exporters

If these occur, revert to `harvest_default` and selectively enable only the high-cardinality objects you truly need.

## Future Work

### Template-Level Cardinality Warnings
Enhance templates with `cardinality: high` metadata to warn operators at deploy time:
```yaml
name: CIFSSession
cardinality: high  # ← Proposed
counters:
  - ^^connected_time => connected_time
```

### Dynamic Sampling
Allow per-object sampling rates to reduce cardinality without disabling objects entirely:
```yaml
coverage: harvest_default
cardinality_overrides:
  CIFSSession:
    enabled: true
    sample_rate: 0.1  # Only 10% of CIFS sessions
```

## References

- Harvest Default Catalog: `harvest/conf/rest/default.yaml`
- Telegen Coverage Constants: `internal/storagedef/types.go` (`CoverageFull`, `CoverageHarvestDefault`)
- Collector Filtering: `internal/storage/netapp/rest/collector.go:55`, `restperf/collector.go:59`, `keyperf/collector.go:60`

---
*Document created: 2026-08-13*
*Author: Telegen NetApp Plugin Team*
