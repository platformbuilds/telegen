# Telegen

A unified telemetry agent for collecting and exporting metrics, traces, logs, and Java profiling data using OpenTelemetry and Prometheus protocols.

**One agent, many signals.** All signal types are config-driven pipelines:
- **Metrics:** Host metrics with Remote Write export
- **Traces:** eBPF-based distributed tracing with OTLP export
- **Logs:** File tailing with OTLP export
- **JFR:** Java Flight Recorder profiling converted to JSON for OTel ingestion
- **Grafana Dashboard:** RED + agent health with exemplar-ready panels
- **Helm Chart:** DaemonSet + Service + ServiceMonitor + RBAC

## Quick Start

```bash
go mod tidy
make build
./bin/telegen --config ./api/config.example.yaml
# optional: make bpf  # build CO-RE BPF .o files for ringbuf path
```

## Deploy with Helm
```bash
helm install telegen ./deployments/helm
```

## Docker
```bash
make docker
```

## Grafana
Import `dashboards/telegen-red-grafana.json` into Grafana. Panels include queue pressure, exporter failures, latency p90,
and request-rate placeholders. To enable exemplars (trace links), ensure Prometheus has exemplar storage enabled and your
OTLP traces include span IDs that your backend can reference.

## Configuration

All signal pipelines are enabled/disabled via config. See `api/config.example.yaml` for the full reference.

### JFR Pipeline

The JFR pipeline watches for Java Flight Recorder files and converts them to JSON for ingestion by OTel Collector's filelog receiver.

```yaml
pipelines:
  jfr:
    enabled: true
    input_dirs:                      # Directories to watch for .jfr files
      - "/var/log/jfr"
    recursive: true                  # Scan subdirectories (default: true)
    output_dir: "/var/log/jfr-json" # Where to write converted JSON files
    poll_interval: "5s"              # How often to scan for new files
    workers: 2                       # Number of parallel conversion workers
```

#### Architecture
```
Java App (JFR) → /var/log/jfr/*.jfr → Telegen JFR Pipeline → /var/log/jfr-json/*.json → OTel Collector → Backend
```

## AWS Metadata (optional)
When enabled, Telegen enriches traces, logs, and metrics with AWS resource attributes and labels using IMDSv2.

Config example:
```yaml
cloud:
  aws:
    enabled: true
    timeout: "200ms"           # per IMDS request
    refresh_interval: "15m"    # metadata cache refresh
    collect_tags: false        # opt-in; requires IMDS instance tags enabled
    tag_allowlist: []          # e.g., ["app_", "env"]
```
