# NetApp ONTAP & E-Series Storage Collection

Telegen collects NetApp metrics and EMS events using Harvest-inspired YAML templates under `configs/netapp/`.

## Architecture

- **Rest** — inventory/config via public REST and `api/private/cli`
- **RestPerf** — performance via `api/cluster/counter/tables/...` with rate cooking
- **KeyPerf** — `statistics.*` on resource endpoints (ASA r2, GCNV, Volume)
- **EMS** — `api/support/ems/events` → OTLP logs (+ `ems_events` gauges)
- **E-Series** — SANtricity templates under `configs/netapp/eseries{,perf}`

Capability probe auto-selects RestPerf vs KeyPerf. Default `coverage: full` includes Harvest opt-in objects.

## Config

```yaml
storage:
  enabled: true
  collect_interval: 60s
  netapp_ontap:
    - name: ontap-prod
      address: https://cluster.example.com
      username: monitor
      password: ${NETAPP_PASSWORD}
      coverage: full
      collectors: [rest, restperf, keyperf, ems]
      ems:
        enabled: true
        resolve_after: 672h
  netapp_eseries:
    - name: eseries-prod
      address: https://eseries.example.com
      username: monitor
      password: ${NETAPP_ESERIES_PASSWORD}
```

Schema truth: `storage.netapp_ontap` / `storage.netapp_eseries` (not `collector.storage.netapp.targets`).

## Parity

Telegen covers the full Harvest ONTAP metric catalog (**1,558 families**),
including Aggregator/Max rollups, VolumeTop, LabelAgent status metrics, and
collector `metadata_*` / `poller_*` self-metrics.

```bash
make netapp-parity
# or with Harvest catalog:
HARVEST_ONTAP_METRICS_JSON=/path/to/harvest/mcp/metadata/ontap_metrics.json make netapp-parity
```

`configs/netapp/parity-allowlist.txt` must remain empty (comment-only). Template
provenance: see `configs/netapp/SOURCE.md`.

Data Studio query cookbook (PromQL / LogSQL): [NetApp ONTAP dashboards reference](../reference/netapp-ontap-dashboards.md).
