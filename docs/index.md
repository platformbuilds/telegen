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
eBPF-powered tracing for HTTP, gRPC, databases, messaging (Kafka, AMQP, STOMP), and RPC (Dubbo2, SunRPC) without code changes.
:::

:::{grid-item-card} 🔥 Continuous Profiling
CPU, off-CPU, memory, mutex, and wall-clock profiling with flame graph generation.
:::

:::{grid-item-card} 🛡️ Security Observability
Syscall auditing, file integrity monitoring, container escape detection, and file tailing with trace correlation.
:::

:::{grid-item-card} 🌐 Network Observability
DNS tracing, TCP metrics, XDP packet analysis, service mesh integration, and firewall infra collection (PAN-OS, FortiGate, Arista, Cisco ACI).
:::

:::{grid-item-card} 📡 OpenTelemetry Native
100% OTel-compliant output via OTLP to any compatible backend. Unified V3 pipeline with WAL queues and failover.
:::

:::{grid-item-card} 🤖 AI/ML Observability
GPU monitoring (NVIDIA NVML), LLM API tracing (OpenAI, Anthropic), CUDA kernel tracing, and token cost estimation.
:::

:::{grid-item-card} 🏗️ Infrastructure Collection
Storage arrays (NetApp ONTAP/E-Series, Dell, HPE, Pure), VMware vSphere, SNMP devices, and K8s metrics streaming.
:::

:::{grid-item-card} 📨 Messaging Protocols
Kafka, RabbitMQ/AMQP 0-9-1, AMQP 1.0, OpenWire, STOMP, NATS, MQTT — full OTel messaging semantics.
:::

:::{grid-item-card} 🔗 Go Channel Links
Go channel send/receive operations as span links for goroutine-level trace correlation.
:::

::::

---

## Quick Start

```bash
# Kubernetes (Helm)
helm install telegen oci://ghcr.io/mirastacklabs-ai/charts/telegen \
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
features/messaging-tracing
features/sunrpc-tracing
features/c-cpp-instrumentation
features/go-channel-events
features/kube-metrics
features/unified-pipeline
```

```{toctree}
:maxdepth: 2
:caption: Integrations

integrations/index
```

```{toctree}
:maxdepth: 2
:caption: Guides

guides/obi-lineage
guides/obi-attribute-parity
guides/v3-migration-phase0-baseline
guides/v3-migration-phase1-depmap
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
- **GitHub Issues**: [github.com/mirastacklabs-ai/telegen/issues](https://github.com/mirastacklabs-ai/telegen/issues)
- **Discussions**: [github.com/mirastacklabs-ai/telegen/discussions](https://github.com/mirastacklabs-ai/telegen/discussions)

## License

Telegen is released under the Apache 2.0 License.
