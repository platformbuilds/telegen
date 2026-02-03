# Telegen Documentation

```{image} ../telegen.svg
:alt: Telegen Logo
:width: 200px
:align: center
```

**Telegen** is a zero-configuration observability agent that automatically discovers and instruments your entire infrastructure using eBPF. Deploy with a single command and get complete visibility across metrics, traces, logs, and profiles.

> *"Instrument everything. Configure nothing."*

---

## Key Features

::::{grid} 2
:gutter: 3

:::{grid-item-card} 🔍 Auto-Discovery
Automatically detects cloud providers, Kubernetes, databases, and runtimes without configuration.
:::

:::{grid-item-card} 📊 Distributed Tracing
eBPF-powered tracing for HTTP, gRPC, and database protocols without code changes.
:::

:::{grid-item-card} 🔥 Continuous Profiling
CPU, off-CPU, memory, and mutex profiling with flame graph generation.
:::

:::{grid-item-card} 🛡️ Security Observability
Syscall auditing, file integrity monitoring, and container escape detection.
:::

:::{grid-item-card} 🌐 Network Observability
DNS tracing, TCP metrics, XDP packet analysis, and service mesh integration.
:::

:::{grid-item-card} 📡 OpenTelemetry Native
100% OTel-compliant output via OTLP to any compatible backend.
:::

::::

---

## Quick Start

```bash
# Kubernetes (Helm)
helm install telegen oci://ghcr.io/platformbuilds/charts/telegen \
  --namespace telegen --create-namespace \
  --set otlp.endpoint="otel-collector:4317"
```

For Linux, see the {doc}`installation/linux` guide.

That's it! Telegen auto-discovers everything and starts collecting telemetry.

---

## Documentation

```{toctree}
:maxdepth: 2
:caption: Getting Started

getting-started/index
```

```{toctree}
:maxdepth: 2
:caption: Installation

installation/index
```

```{toctree}
:maxdepth: 2
:caption: Configuration

configuration/index
```

```{toctree}
:maxdepth: 2
:caption: Features

features/index
```

```{toctree}
:maxdepth: 2
:caption: Integrations

integrations/index
```

```{toctree}
:maxdepth: 2
:caption: Operations

operations/index
```

```{toctree}
:maxdepth: 2
:caption: Reference

reference/index
```

---

## Support

- **Documentation**: [telegen.mirastacklabs.ai](https://telegen.mirastacklabs.ai)
- **GitHub Issues**: [github.com/platformbuilds/telegen/issues](https://github.com/platformbuilds/telegen/issues)
- **Discussions**: [github.com/platformbuilds/telegen/discussions](https://github.com/platformbuilds/telegen/discussions)

## License

Telegen is released under the Apache 2.0 License.
