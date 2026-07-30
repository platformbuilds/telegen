# Telegen

**Unified eBPF-native observability agent** — zero-code instrumentation for every signal across every protocol. Metrics, traces, logs, profiles, security events, and infrastructure telemetry — one binary, zero config, enterprise global standard.

> *"Instrument everything. Configure nothing."*

---

## What Telegen Collects

Telegen auto-discovers and collects **five signal types** across **100+ protocols and platforms**:

| Signal | Sources | Export |
|--------|---------|--------|
| **Metrics** | Host (procfs), GPU (NVML), Node Exporter, K8s (streaming OTLP), SNMP, Storage arrays, Firewall/network infra, VMware vSphere | OTLP gRPC/HTTP, Prometheus Remote Write |
| **Traces** | eBPF (HTTP/1.x, HTTP/2, gRPC, TLS), Databases (PostgreSQL, MySQL, MongoDB, Redis, Oracle, MSSQL, Couchbase, DB2, Cassandra), Messaging (Kafka, RabbitMQ/AMQP 0-9-1, AMQP 1.0, OpenWire, STOMP, NATS, MQTT), RPC (Dubbo2, SunRPC), AI (CUDA, LLM APIs), DNS, TCP | OTLP gRPC/HTTP |
| **Logs** | File tailing (Docker/containerd/CRI-O parsers), K8s events as OTLP logs, vCenter events + state-change logs, NetApp EMS events, Security audit (execve, file integrity, container escape) | OTLP gRPC/HTTP |
| **Profiles** | Continuous profiling (CPU, off-CPU, memory alloc, mutex, wall-clock), JFR (Java Flight Recorder), Go goroutine profiling | OTLP Profiles, OTLP Logs (per-sample) |
| **Correlation** | Log-to-trace enrichment (trace_id injection), Go channel-link events (goroutine span links), signal metadata (`telegen.*` attributes) | Embedded in all signals |

---

## Protocol Coverage

Telegen instruments wire-level protocols at the kernel level using eBPF — no SDK, no sidecar, no code changes.

### Application Protocols

| Category | Protocols | Detection |
|----------|-----------|-----------|
| **HTTP/API** | HTTP/1.1, HTTP/2, gRPC, gRPC-C, TLS (libssl uprobes) | Generic tracer (kprobe) + Go uprobes |
| **Databases** | PostgreSQL v3, MySQL/MariaDB, MongoDB wire, Redis RESP, Oracle TNS/Net8, MSSQL TDS, Couchbase, IBM DB2 DRDA, Cassandra CQL v3-v5 | Generic tracer + Go uprobes |
| **Messaging** | Kafka, RabbitMQ/AMQP 0-9-1, AMQP 1.0, OpenWire/ActiveMQ, STOMP, NATS, MQTT | Generic tracer + Go uprobes |
| **RPC** | Dubbo2 (magic `0xDA 0xBB`), SunRPC/ONC RPC | Generic tracer |
| **AI/GPU** | CUDA kernel/memcpy/malloc, LLM API (OpenAI/Anthropic/Azure HTTP enrichment) | Generic tracer + `gpuevent` |
| **DNS** | DNS query/response (A, AAAA, CNAME, etc.) | Generic tracer |
| **Infrastructure** | SNMP v1/v2c/v3, VMware vCenter SOAP, NetApp ONTAP REST, Dell/HPE/Pure REST, PAN-OS, FortiOS, Arista CVP, Cisco ACI | Polling adapters (REST/SNMP/SOAP) |
| **Language-specific** | Go (net/http, gRPC, database/sql, go-redis, mongo-driver, kafka-go/sarama), Java (TLS, JFR), Node.js (HTTP), C/C++ (libpq, mysqlclient, FreeTDS via wire protocol) | Go uprobes + generic tracer |

### Messaging System Resolution

Telegen automatically resolves `messaging.system` OTel attributes:

| Protocol | Default System | Disambiguation Hints |
|----------|---------------|---------------------|
| AMQP 0-9-1 | RabbitMQ | Always RabbitMQ |
| AMQP 1.0 | ActiveMQ | `servicebus`/`azure-servicebus` → Azure Service Bus; `artemis`/`activemq`/`openwire`/`stomp` → ActiveMQ; `rabbit`/`beam.smp` → RabbitMQ; `qpid`/`solace` → JMS |
| OpenWire | ActiveMQ | Always ActiveMQ |
| STOMP | ActiveMQ | Same hint resolution as AMQP 1.0 |

---

## Infrastructure Collection

### Storage Arrays

| Vendor | Products | API | Capabilities |
|--------|----------|-----|-------------|
| **NetApp** | ONTAP | REST API | 65+ inventory objects, 54+ perf counter tables (NFSv3/v4/v4.1/v4.2, SMB/CIFS, iSCSI, FCP, NVMe/FC, NVMe/RDMA, NVMe/TCP, ONTAP S3), KeyPerf (ASA r2), EMS events (86 message types → OTLP logs), 1,558 Harvest-compatible metric families |
| **NetApp** | E-Series | SANtricity REST | 16 inventory objects + 9 performance objects |
| **Dell** | PowerStore, PowerScale | REST API | Capacity, performance, volumes, hardware |
| **HPE** | Primera, 3PAR | WSAPI | Array performance, CPGs, volumes, hosts |
| **Pure** | FlashArray, FlashBlade | REST API v2 | Performance and capacity |

### Network & Firewall Infrastructure

| Vendor | Platform | Collects |
|--------|----------|---------|
| **Arista** | CloudVision (CVP) | Inventory, interfaces, BGP, system |
| **Cisco** | ACI | Fabric health, node health, tenant health, interface stats |
| **Palo Alto** | PAN-OS | System, interfaces (API key or username/password) |
| **Fortinet** | FortiGate FortiOS | System, interfaces (Bearer token) |

### Virtualization

| Platform | Metrics | Logs | Details |
|----------|---------|------|---------|
| **VMware vSphere/vCenter** | 74 distinct metrics (host, VM, datastore, cluster, datacenter) | vCenter EventManager events, synthesized inventory state-change logs, alarm handling | govmomi-based, 7 collector types, event drain with watermarking |

### Kubernetes

| Signal | Mechanism | Details |
|--------|-----------|---------|
| **kube-state-metrics** | Streaming OTLP push | Configurable interval, batch size, flush timeout |
| **cadvisor** | Streaming OTLP push | Container-level CPU, memory, network, filesystem |
| **K8s events** | OTLP logs | Normal/Warning events, namespace filtering, buffer/flush config |
| **Signal metadata** | Auto-attached | `telegen.*` attributes via `sigdef.MetadataFieldsConfig` |

---

## AI/ML Workload Observability

| Capability | Mechanism | Details |
|------------|-----------|---------|
| **GPU monitoring** | NVML | Utilization, memory, power, temperature, clocks, PCIe, NVLink, ECC, MIG, per-process attribution |
| **LLM inference** | eBPF + HTTP enrichment | Token throughput, latency, TTFT, per-model cost estimation |
| **CUDA tracing** | eBPF (`gpuevent`) | Kernel launches, grid/block dimensions, memory ops (cudaMalloc/cudaMemcpy) as spans |
| **ML framework profiling** | eBPF | PyTorch, TensorFlow operation tracing |

---

## Deployment

### Helm (Kubernetes)

```bash
helm install telegen oci://ghcr.io/mirastacklabs-ai/charts/telegen \
  --namespace telegen --create-namespace \
  --set otlp.endpoint="otel-collector:4317"
```

### Docker

```bash
docker run -d --name telegen \
  --pid=host --privileged \
  -v /sys:/sys -v /proc:/proc \
  -v /var/lib/telegen:/var/lib/telegen \
  ghcr.io/mirastacklabs-ai/telegen:latest \
  --config /etc/telegen/config.yaml
```

### Bare Metal / VM

```bash
# Download binary
curl -L https://github.com/mirastacklabs-ai/telegen/releases/latest/download/telegen-linux-amd64 -o telegen
chmod +x telegen

# Minimal config — just the OTLP endpoint
cat > telegen.yaml <<EOF
otlp:
  endpoint: "otel-collector:4317"
EOF

./telegen --config telegen.yaml
```

### Multi-Architecture

| Architecture | Support |
|-------------|---------|
| `amd64` | Full (eBPF CO-RE + BPF objects) |
| `arm64` | Full (eBPF CO-RE + BPF objects) |

### Operation Modes

| Mode | Description |
|------|-------------|
| `agent` | eBPF-based host instrumentation (default) |
| `collector` | Remote polling only (storage, SNMP, firewall, vCenter) |
| `unified` | Both eBPF + remote polling in one process |

---

## Configuration

Telegen follows **zero-config by default**. The only required setting is your OTLP endpoint:

```yaml
# Minimal configuration
otlp:
  endpoint: "otel-collector:4317"
```

### Unified Pipeline Architecture

All signals flow through a single production pipeline:

```
eBPF Probes / Polling Adapters
        ↓
Ring Buffers (16 MB) + Large Buffers (MQ/HTTP)
        ↓
Protocol Parsers (frame decode → request.Span)
        ↓
Unified Pipeline (adapters → converters → integration)
        ↓
Persistent WAL Queues (per-signal, with replay)
        ↓
Multi-Endpoint Exporter (failover/fanout + circuit breaker)
        ↓
Shared OTLP Clients (gRPC-primary, HTTP fallback)
        ↓
Backend (OTel Collector, Prometheus, etc.)
```

Key pipeline features:
- **Adapter registry** — pluggable per-collector adapters (eBPF, JFR, file logs, host metrics, K8s, network flows, Kafka, security, GPU, database, log-trace correlation)
- **Converting pipeline** — `ebpf_profile→OTLP`, `security→OTLP`, `prometheus→OTLP`, `JFR→OTLP`, `GPU→OTLP`
- **Integration layer** — limits, transforms, PII redaction
- **Persistent WAL** — per-signal `queue.PersistentQueue` with replay workers
- **Multi-endpoint failover** — circuit-breaker semantics, fanout support
- **OBI bridge** — upstream `go.opentelemetry.io/obi` span batch ingestion
- **Shared OTLP clients** — `GetMetricsExporter`, `GetLogsLoggerProvider`, `GetTracesExporter`

---

## Java Profiling (eBPF Continuous Profiling)

Telegen includes production-ready eBPF continuous profiling with **symbol resolution for Java applications**. Native functions, kernel symbols, JIT-compiled Java methods, and Go functions are all resolved.

### Quick Start — IBM OpenJ9

```yaml
env:
- name: OPENJ9_JAVA_OPTIONS
  value: "-Xjit:perfTool"  # Enables perf map generation
```

### Quick Start — Oracle/OpenJDK HotSpot

```yaml
env:
- name: JAVA_TOOL_OPTIONS
  value: "-XX:+PreserveFramePointer -agentpath:/opt/perf-map/libperfmap.so"
```

### What Gets Resolved?

| Function Type | Status |
|--------------|--------|
| Native/C++ functions (libjvm.so, glibc, etc.) | Always works |
| Kernel functions (syscalls, page faults, etc.) | Always works |
| Go functions (pclntab-based) | Always works for Go binaries |
| Java JIT methods | Requires perf map configuration |
| C/C++ DB drivers (libpq, mysqlclient) | Auto-detected via wire protocol |

Without JIT perf maps, Java methods show as `[unresolved] 0x...` addresses.

---

## AWS Metadata (Optional)

Enriches traces, logs, and metrics with AWS resource attributes using IMDSv2:

```yaml
cloud:
  aws:
    enabled: true
    timeout: "200ms"
    refresh_interval: "15m"
    collect_tags: false
    tag_allowlist: []
```

---

## Grafana Dashboards

Pre-built dashboards are available in `dashboards/`:

| Dashboard | Panels | Description |
|-----------|--------|-------------|
| **telegen-red-grafana.json** | RED + agent health | Queue pressure, exporter failures, latency p90, request-rate |
| **NetApp ONTAP** | 43 panels, 6 dashboards | Fleet overview, node performance, capacity, volume/LUN performance, SnapMirror, EMS events |
| **VMware vCenter** | 44 panels, 5 dashboards | Fleet overview, host/ESXi performance, VM performance, datastore capacity, events & state changes |

---

## Quick Start (Development)

```bash
git clone https://github.com/mirastacklabs-ai/telegen.git
cd telegen
go mod tidy
make build
./bin/telegen --config ./api/config.example.yaml
# optional: make bpf  # build CO-RE BPF .o files for ringbuf path
```

---

## Documentation

Full documentation is available at [telegen.mirastacklabs.ai](https://telegen.mirastacklabs.ai) or in the `docs/` directory:

| Section | Description |
|---------|-------------|
| [Getting Started](docs/getting-started/) | Installation, architecture, quick start guides |
| [Configuration](docs/configuration/) | Full config reference, environment variables, pipeline modes |
| [Features](docs/features/) | Deep dives on tracing, profiling, storage, network, security |
| [Integrations](docs/integrations/) | Backend compatibility, OTel Collector setup |
| [Guides](docs/guides/) | OBI lineage, attribute parity, V3 migration |
| [Reference](docs/reference/) | Metrics catalog, signals reference, semantic conventions |

---

## Supported Platforms

| Platform | Requirements |
|----------|-------------|
| **Linux** | Kernel 4.18+ (eBPF CO-RE), 5.8+ (full capability set) |
| **Kubernetes** | 1.24+ (DaemonSet deployment) |
| **OpenShift** | 4.x+ (SCC, GPU Operator) |
| **Docker** | 20.10+ (with `--privileged` or appropriate capabilities) |
| **AWS ECS** | With GPU instance support |

---

## License

Telegen is released under the **Apache 2.0 License**.

---

## Links

- **Documentation**: [telegen.mirastacklabs.ai](https://telegen.mirastacklabs.ai)
- **GitHub**: [github.com/mirastacklabs-ai/telegen](https://github.com/mirastacklabs-ai/telegen)
- **Issues**: [github.com/mirastacklabs-ai/telegen/issues](https://github.com/mirastacklabs-ai/telegen/issues)
- **Discussions**: [github.com/mirastacklabs-ai/telegen/discussions](https://github.com/mirastacklabs-ai/telegen/discussions)
