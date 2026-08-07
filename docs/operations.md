# Telegen Operations Contract

This document defines the runtime contract for operating `telegen` in production.

## Platform And Privileges

- **Minimum kernel:** Linux `4.18` or newer.
- **Required capabilities for eBPF runtime paths:** `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_ADMIN`.
- Startup preflight checks now validate kernel/capability requirements before pipeline startup, so unsupported environments fail fast with an actionable startup error instead of a later opaque verifier failure.

## Memory Sizing Guidance

- Configure `memoryLimitBytes` explicitly in production.
- Leaving `memoryLimitBytes` unset is discouraged because peak pressure then depends on workload burst shape and exporter outage duration.
- Start with a limit that leaves headroom for:
  - process baseline + eBPF/runtime overhead
  - short outage buffering
  - profiling and debug endpoints when enabled
- In containerized deployments, align `memoryLimitBytes` with pod/container memory limits and alert before the limit is reached.

## Network Ports

- `19090`: internal telemetry HTTP endpoint (metrics). When enabled, this also exposes pprof and `/debug/config`.
- `8080`: health endpoint (`/healthz` and `/readyz`).
- `9443`: kube-metrics endpoint.

## Internal Metrics Endpoint

- `ebpf.internal_metrics.prometheus.port: 0` means internal eBPF metrics are registered into the shared self-telemetry endpoint (`selfTelemetry.listen`) and exposed on `/metrics`.
- Setting `ebpf.internal_metrics.prometheus.port` to a non-zero value opens a dedicated Prometheus listener for internal metrics.
- Startup validation rejects collisions between `ebpf.internal_metrics.prometheus.port` and `selfTelemetry.listen`, `selfTelemetry.health_listen`, and `selfTelemetry.pprof_port` when pprof is enabled.

## Instance Lock Path

- `agent.instance_lock_path` defaults to `/var/run/telegen.pid`.
- Collector deployments with `readOnlyRootFilesystem: true` must provide a writable path and mount for the lock file.
- The Helm collector profile now renders `agent.instance_lock_path` and mounts writable storage at `/var/run` so lock acquisition succeeds.

## AWS IMDS Behavior

- On non-EC2 environments, the AWS metadata probe may be unavailable; this is treated as expected and logged at debug level.
- If you want to silence AWS SDK metadata probing entirely in non-AWS environments, set `AWS_EC2_METADATA_DISABLED=true` in the container environment.

## Collector Outage Behavior

After the Wave 2/3 hardening changes:

- Export retries use jittered, capped backoff to avoid synchronized reconnect storms.
- Queue and WAL paths are bounded; old/stale/corrupt replay segments are quarantined instead of replayed indefinitely.
- Backpressure can still cause drops once bounded buffers are exhausted.
- Expected recovery: once collector connectivity is restored, backlog drains progressively and exporters resume normal throughput without process restart.

## Shutdown And Grace Period

- Telegen shutdown paths are bounded with a `25s` timeout.
- Set `terminationGracePeriodSeconds` to at least `30s` (recommended `45s`) so queues/exporters can flush and instrumenter cleanup can complete.

## Alerting Metrics

Alert on sustained non-zero growth in:

- `*_agent_queue_dropped_total` (queue overflow/expiry drops)
- `*_agent_export_failures_total` (export failures)
- `*_agent_ringbuf_lost_total` (kernel ring buffer loss)
- `*_agent_recovered_panics_total` (panic recovery on hot paths)
- `telegen_metric_cardinality_overflow_total` (metric cardinality overflow)

Also track recovery signals (failure counters flattening and successful export throughput returning after outage).

## Support Bundle Procedure

Collect the following when opening support cases:

1. **Effective config snapshot:** run `telegen --dump-config` and attach the redacted output.
2. **Runtime config endpoint (if enabled):** capture `/debug/config`.
3. **pprof profiles from internal endpoint (`19090`)**:
   - `/debug/pprof/goroutine?debug=2`
   - `/debug/pprof/heap`
   - `/debug/pprof/profile?seconds=30`
4. **Health snapshots:** capture `/healthz` and `/readyz`.
5. **Recent logs and self-telemetry counters** around outage/failure windows.
