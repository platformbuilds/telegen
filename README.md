# Telegen v3+ (parsers, CI, dashboards, Helm)

This drop adds:
- **Parser skeletons:** Cassandra CQL, Postgres Simple Query, Kafka detector.
- **Grafana dashboard:** RED + agent health with exemplar-ready panels.
- **GitHub Actions CI:** lint, test, govulncheck, BPF build, Docker image build, Helm lint.
- **Helm chart:** DaemonSet + Service + ServiceMonitor + RBAC.

## Quick start
```bash
go mod tidy
make build
./telegen --config ./api/config.example.yaml
# optional: make bpf  # build CO-RE BPF .o files for ringbuf path
```

## Deploy with Helm
```bash
helm install telegen ./deployments/helm
```

## Grafana
Import `dashboards/telegen-red-grafana.json` into Grafana. Panels include queue pressure, exporter failures, latency p90,
and request-rate placeholders. To enable exemplars (trace links), ensure Prometheus has exemplar storage enabled and your
OTLP traces include span IDs that your backend can reference.
