# Configuration

Complete guide to configuring Telegen for your environment.

## Configuration Philosophy

Telegen follows a **zero-config by default** approach. The only required setting is your OTLP endpoint—everything else is auto-discovered with sensible defaults.

```yaml
# Minimal configuration - just the endpoint!
otlp:
  endpoint: "otel-collector:4317"
```

## Common Exporter Pipeline

Telegen uses a unified **Common Exporter Pipeline** architecture. All signals
(kube_metrics, node_exporter, ebpf, jfr, logs) flow through a shared OTLP
exporter configured in `exports.otlp`. This provides:

- **Single connection** - Connection pooling for all signals
- **Consistent config** - TLS, compression, timeouts configured once
- **Simplified ops** - Change endpoint once, affects all signals

See {doc}`full-reference` for the complete architecture diagram.

## Configuration Methods

| Method | Priority | Use Case |
|--------|----------|----------|
| **Environment Variables** | Highest | Container deployments, secrets |
| **Config File** | Medium | Full configuration control |
| **Defaults** | Lowest | Zero-config deployments |

## Sections

```{toctree}
:maxdepth: 2

minimal-config
v3-pipeline
full-reference
agent-mode
collector-mode
environment-variables
```
