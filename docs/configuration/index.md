# Configuration

Complete guide to configuring Telegen for your environment.

## Configuration Philosophy

Telegen follows a **zero-config by default** approach. The only required setting is your OTLP endpoint—everything else is auto-discovered with sensible defaults.

```yaml
# Minimal configuration - just the endpoint!
otlp:
  endpoint: "otel-collector:4317"
```

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
full-reference
agent-mode
collector-mode
environment-variables
```
