# Telegen — Unified Observability for Global BFSI Enterprises

> *"Instrument everything. Configure nothing."*
> **One agent. Every signal. Zero code changes.**

---

## Executive Summary

Modern Banking, Financial Services, and Insurance (BFSI) infrastructure spans bare-metal trading engines, containerised micro-services, legacy middleware, network fabrics, and enterprise storage — all of which must be continuously observable, auditable, and secure. Telegen is an **eBPF-native, OpenTelemetry-first observability agent** that deploys with a single command and automatically surfaces metrics, distributed traces, logs, continuous profiles, and security events across your entire stack — without modifying a single line of application code.

Telegen eliminates the fragmented tooling landscape (APM agents, log shippers, network probes, SNMP collectors, storage adapters) with a single unified agent, reducing operational overhead and total cost of ownership while closing observability gaps that increase operational and compliance risk.

---

## The BFSI Observability Challenge

| Challenge | Industry Pain | How it Manifests |
|-----------|--------------|------------------|
| **Complex, heterogeneous infrastructure** | Mainframe + cloud + on-prem | Blind spots between tiers |
| **Latency-sensitive workloads** | Trading, payments, FX | Silent performance degradation |
| **Compliance & auditability** | SOX, PCI-DSS, DORA, MAS TRM | Incomplete audit trails |
| **Security & insider threat** | Privileged access, data exfiltration | No runtime syscall visibility |
| **Fragmented tooling** | 5–10 observability products | Alert fatigue, MTTR >60 min |
| **Change-averse operations** | No-touch production policy | SDKs rejected, agent sprawl |

Telegen solves all of the above with a **zero-code-change, kernel-level approach**.

---

## Product Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        TELEGEN AGENT                            │
│                                                                 │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────────────┐   │
│  │ eBPF Tracers │  │  Profiler   │  │  Security Monitor    │   │
│  │ HTTP/gRPC/DB │  │ CPU/Mem/    │  │  Syscall / FIM /     │   │
│  │ DNS/TCP/MQ   │  │ Off-CPU     │  │  Container Escape    │   │
│  └──────┬───────┘  └──────┬──────┘  └──────────┬───────────┘   │
│         │                 │                     │               │
│  ┌──────┴─────────────────┴─────────────────────┴───────────┐   │
│  │            Signal Correlation Layer                       │   │
│  │    (traces ↔ logs ↔ metrics ↔ profiles auto-linked)       │   │
│  └──────────────────────────┬────────────────────────────────┘   │
│                             │                                    │
│  ┌──────────────────────────▼────────────────────────────────┐   │
│  │           Unified OTLP Export Pipeline                    │   │
│  │        (metrics · traces · logs · profiles)               │   │
│  └──────────────────────────┬────────────────────────────────┘   │
└─────────────────────────────┼───────────────────────────────────┘
                              │  OTLP / gRPC / HTTP
                              ▼
             ┌────────────────────────────────┐
             │  OpenTelemetry Collector /      │
             │  Any OTLP-compatible Backend   │
             └────────────────────────────────┘
```

### Two Operating Modes

| | Agent Mode | Collector Mode |
|---|---|---|
| **Purpose** | Per-host / per-node observability | Remote device & infrastructure polling |
| **Transport** | eBPF kernel instrumentation | SNMP, REST APIs, Prometheus scraping |
| **Deployment** | DaemonSet (K8s), systemd (bare metal) | Deployment / StatefulSet, systemd |
| **Key use cases** | Application tracing, profiling, security | Network devices, storage arrays, legacy gear |

---

## Agent Mode — Feature Deep Dive

### 1. Zero-Configuration Auto-Discovery

Telegen auto-discovers your entire environment at startup — no inventory files, no configuration per service.

**Cloud Detection** (automatic metadata enrichment on every signal):

| Provider | Method | Metadata |
|----------|--------|----------|
| AWS | IMDSv2 | Instance ID, region, AZ, instance type, AMI |
| GCP | Metadata server | Instance ID, zone, machine type, project |
| Azure | IMDS | VM ID, location, VM size, subscription |
| Alibaba Cloud | Metadata service | Instance ID, region, zone |
| OpenStack / VMware | Keystone + hypervisor | Tenant, project, hypervisor type |

**Runtime Detection** (automatic instrumentation per process):

| Runtime | Detection | Auto-Instrumentation |
|---------|-----------|---------------------|
| Go | Binary symbols + goroutine patterns | HTTP, gRPC, databases, TLS plaintext |
| Java | JVM process + JFR integration | Full JVM tracing, heap profiling |
| Python | Interpreter detection | HTTP, database, asyncio |
| Node.js | V8 process patterns | HTTP, database, async |
| .NET | CoreCLR detection | HTTP, database, EF Core |
| Rust | Binary analysis | Network, syscalls |
| C/C++ | Binary analysis | Network, syscalls |

**Kubernetes Metadata** (automatically injected on all signals):
```
k8s.cluster.name, k8s.namespace.name, k8s.pod.name, k8s.pod.uid,
k8s.deployment.name, k8s.node.name, k8s.container.name
```

---

### 2. Distributed Tracing — eBPF, Zero-SDK

Telegen intercepts application traffic at the kernel level. No SDK. No restart. No code change. Traces are 100% OpenTelemetry-compliant (OTLP).

**Supported Protocols:**

| Protocol | Captured Attributes |
|----------|-------------------|
| **HTTP/1.1 & HTTP/2** | method, URL, route, status, request/response size, peer IP |
| **gRPC** | service, method, status code, peer details |
| **PostgreSQL** | SQL statement (sanitised), operation, table, row count, error codes |
| **MySQL / MariaDB** | SQL statement, affected rows, thread ID, Galera cluster |
| **MongoDB** | Operation, collection, aggregation pipeline |
| **Redis / Valkey** | Command, key (redactable), latency |
| **Cassandra / DSE** | CQL v3–v5, prepared statements, consistency level, batch |
| **Oracle DB** | TNS/Net8, SQL, PL/SQL, wait events |
| **SQL Server** | TDS, T-SQL, stored procedures |
| **Kafka** | Produce/consume spans, partition, offset, consumer group |
| **RabbitMQ / AMQP** | Exchange, routing key, consumer tag |
| **NATS** | Subject, reply-to, headers |

**Trace Context Propagation:**
- Extracts `traceparent` / `tracestate` from incoming requests
- Injects context into outgoing calls for cross-service correlation
- Works across encrypted TLS connections via Go TLS uprobe

> **BFSI relevance:** Every payment request, FX trade, or loan origination is traced end-to-end across 10s of micro-services — automatically. Latency outliers are pinpointed to the exact SQL query or API call without any developer effort.

---

### 3. Log Collection with Automatic Trace Correlation

Telegen provides native log collection with **zero-sidecar, eBPF-powered trace injection** — linking every log line to the distributed trace that produced it.

- Native parsers for Docker JSON, containerd, CRI-O
- Automatic Kubernetes metadata extraction from log paths
- Application-aware parsing: Spring Boot, Log4j, Logback, plain text
- eBPF `write()` syscall interception captures trace context at write time
- Time-windowed correlation cache: ±100ms tolerance — works for any log format
- Every log record carries `trace_id`, `span_id`, `trace_flags` in OTLP format

> **BFSI relevance:** Audit logs for transaction processing are automatically correlated to the trace, enabling instant root-cause analysis during incident response and satisfying regulatory requirements for full-stack audit trails.

---

### 4. Continuous Profiling — Always-On, Production-Safe

Low-overhead statistical profiling, correlated with traces and metrics. No sampling gaps, no manual trigger.

| Profile Type | What It Measures | Typical Use Case |
|--------------|-----------------|-----------------|
| **CPU** | On-CPU execution time | Identify hot code paths in payment processing |
| **Off-CPU** | Blocking / waiting time | Diagnose I/O-bound latency in DB calls |
| **Memory / Heap** | Allocation hotspots | Find memory leaks in long-running services |
| **Mutex / Lock** | Lock contention | Debug thread starvation in trading engines |
| **Goroutine** | Go goroutine stacks | Detect goroutine leaks |
| **Block** | Blocking sync operations | Find channel/semaphore bottlenecks |

- Default sampling: **99 Hz** (avoids aliasing with OS timers)
- Frame pointer + DWARF-based stack unwinding
- Profiles exported as pprof — compatible with Grafana Pyroscope, Google Cloud Profiler, Polar Signals
- All profiles automatically correlated with active spans

> **BFSI relevance:** Proactively identifies CPU/memory regressions before they breach SLA thresholds — critical for core banking and real-time payments systems.

---

### 5. Security Observability — Runtime Threat Detection

eBPF-based runtime security monitoring. Every privileged operation captured as an OpenTelemetry log with security-specific attributes, ready for SIEM ingestion.

**Security Event Coverage:**

| Event Type | Description | Severity |
|------------|-------------|----------|
| **Process Execution** | Every `execve` / `execveat` captured with full command line, user, PID | Info / Warning |
| **Privilege Escalation** | `setuid`, `setgid`, `setresuid` syscalls | Warning / Critical |
| **File Integrity Monitoring** | Changes to `/etc/passwd`, `/etc/shadow`, SSH keys, sudoers, crontabs, system binaries | Warning |
| **Kernel Module Load/Unload** | `init_module`, `finit_module`, `delete_module` | Critical |
| **Container Escape Detection** | Namespace operations, cgroup breakouts, privileged ops inside containers | Critical |
| **Suspicious Syscall Patterns** | `ptrace`, `open_by_handle_at`, abnormal `mount`/`socket` usage | Warning |
| **Network Security** | Unusual outbound connections, bind on privileged ports | Warning |

**BFSI-Aligned FIM Paths (pre-configured):**
- Authentication: `/etc/passwd`, `/etc/shadow`, `/etc/group`, sudoers
- SSH: `sshd_config`, all `~/.ssh` directories
- System config: `/etc/hosts`, `resolv.conf`, crontabs
- Binaries: `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`

> **BFSI relevance:** Directly addresses PCI-DSS Requirement 10 (audit logging), MAS TRM Section 9 (security monitoring), and SOC 2 CC6 controls. All events stream as OTLP logs to your SIEM without additional agents.

---

### 6. Network Observability

Deep network visibility using eBPF — no network taps, no span ports required.

**Capabilities:**

| Feature | What's Captured |
|---------|----------------|
| **DNS Tracing** | Query, response, answer records, latency, DNS server, process PID |
| **TCP Metrics** | RTT, retransmits, connections, bytes sent/received per flow |
| **HTTP/gRPC Tracing** | Full request/response details (covered in §2) |
| **Flow Tracking** | Connection topology: service-to-service dependency maps |
| **XDP Packet Analysis** | High-performance packet inspection at NIC driver level |
| **Service Mesh Integration** | Envoy, Istio, Linkerd — transparent sidecar visibility |

**TCP Metrics exposed per flow:**
```
tcp_rtt_us, tcp_retransmits_total, tcp_connections,
tcp_bytes_sent, tcp_bytes_received
```
All labelled with source/destination IP, port, and Kubernetes pod/service names.

> **BFSI relevance:** Detect East-West lateral movement, monitor inter-service dependencies for resilience planning, and identify network-layer performance degradation in real-time payments corridors.

---

### 7. Kubernetes-Native Metrics (Built-in kube-state-metrics + cAdvisor)

No separate `kube-state-metrics` or `cAdvisor` deployments needed. Telegen ships both as integrated components.

**kube-state-metrics equivalent:** ~200 metrics about Kubernetes object state
- Pods, deployments, DaemonSets, StatefulSets, CronJobs, PVCs, nodes
- Uses client-go informers; supports sharding via Jump Consistent Hash

**cAdvisor equivalent:** Container resource utilisation
- CPU, memory, network, filesystem per container
- Reads directly from cgroups v1/v2 — no kubelet dependency

> One DaemonSet replaces four separate components: APM agent + log shipper + kube-state-metrics + cAdvisor.

---

### 8. Node Exporter Fusion — Full Prometheus Compatibility

Telegen is a **drop-in replacement for Prometheus node_exporter**. Existing Grafana dashboards and Prometheus alert rules work without modification.

- 120+ system metrics in the `node_*` namespace
- All standard collectors: loadavg, cpu, meminfo, diskstats, filesystem, netdev, stat, and 45+ more
- Additional eBPF-enhanced metrics unavailable in stock node_exporter
- Exposes `/metrics` endpoint for Prometheus scraping

> **BFSI relevance:** Eliminates the need to run a separate node_exporter on every host, reducing the agent footprint while adding deeper observability.

---

### 9. AI/ML & GPU Observability

Purpose-built for financial institutions running AI workloads (fraud detection, risk models, LLM-powered servicing).

**NVIDIA GPU Metrics (via NVML):**

| Metric | Description |
|--------|-------------|
| `gpu_utilization_percent` | Compute utilisation per GPU |
| `gpu_memory_used_bytes` | VRAM used |
| `gpu_temperature_celsius` | Thermal monitoring |
| `gpu_power_usage_watts` | Power draw vs. limit |
| `gpu_pcie_tx/rx_bytes` | PCIe throughput |
| `gpu_process_memory_bytes` | Per-process GPU memory |

**AMD GPU:** Equivalent coverage via ROCm SMI.

**LLM Inference Metrics:**

| Metric | Description |
|--------|-------------|
| `llm_time_to_first_token_seconds` | TTFT — user experience indicator |
| `llm_tokens_per_second` | Throughput |
| `llm_queue_depth` | Request backpressure |
| `llm_kv_cache_usage_bytes` | Memory pressure in inference servers |
| `llm_request_duration_seconds` | End-to-end latency |

> **BFSI relevance:** As banks deploy LLM-powered virtual assistants, fraud detection models, and document intelligence, Telegen provides the observability layer for these GPU-resident workloads.

---

## Collector Mode — Feature Deep Dive

Collector mode is deployed separately to monitor infrastructure that cannot run an agent — network devices, storage arrays, and legacy appliances.

### 10. SNMP Receiver — Network Device Monitoring

| Capability | Details |
|-----------|---------|
| **Protocol versions** | SNMP v1, v2c, v3 |
| **Collection modes** | Polling + Trap receiver |
| **MIB support** | Standard MIBs (IF-MIB, HOST-RESOURCES-MIB) + custom vendor MIBs |
| **Auto-discovery** | CIDR-based network scanning for SNMP devices |
| **Security** | SNMPv3 authPriv with SHA-256 + AES-256 |

**Supported Auth / Privacy Protocols:**

| Auth | Privacy |
|------|---------|
| MD5, SHA, SHA-224, SHA-256 (recommended), SHA-384, SHA-512 | DES, AES-128, AES-192, AES-256 (recommended) |

> Covers Cisco, Juniper, Arista, F5, Palo Alto, and any RFC-compliant device — including legacy network infrastructure common in BFSI data centres.

---

### 11. Enterprise Storage Array Adapters

Purpose-built for BFSI storage environments. No agents on storage controllers.

| Vendor | Products | API |
|--------|----------|-----|
| **Dell** | PowerStore, PowerScale (Isilon) | REST API |
| **HPE** | Primera, 3PAR, Alletra | WSAPI |
| **Pure Storage** | FlashArray, FlashBlade | REST API v2 |
| **NetApp** | ONTAP (FAS/AFF), E-Series | ONTAP REST API |

**Sample Metrics per Adapter:**

- **Dell PowerStore:** Volume IOPS, read/write latency (μs), capacity utilisation, data reduction ratio, hardware health
- **HPE Primera:** CPG capacity, port bandwidth, node CPU, cache hit ratio, efficiency ratio
- **Pure Storage:** Array IOPS/bandwidth, data reduction, replication lag, hardware alerts
- **NetApp ONTAP:** Aggregate capacity, LUN performance, NFS/CIFS latency, SnapMirror lag, cluster health

> **BFSI relevance:** Core banking databases, trading data stores, and backup vaults run on enterprise storage. Telegen surfaces storage performance and capacity metrics into the same observability platform as application traces and logs — enabling full-stack incident correlation.

---

## Signal Unification — The Telegen Advantage

### Full Signal Coverage

| Signal | Source | Correlation |
|--------|--------|-------------|
| **Metrics** | eBPF + node exporter + kube-state + cAdvisor + storage + SNMP | Exemplars link to traces |
| **Distributed Traces** | eBPF (HTTP, gRPC, DB, MQ, DNS) | Parent-child spans, trace context propagation |
| **Logs** | Filelog + container runtimes + K8s events | `trace_id` / `span_id` injected automatically |
| **Profiles** | CPU, off-CPU, memory, mutex, goroutine | Correlated with active spans |
| **Security Events** | Syscall audit, FIM, container escape | Emitted as OTLP logs to SIEM |

### Feature Matrix

| Feature | Agent Mode | Collector Mode |
|---------|:----------:|:--------------:|
| Auto-Discovery (cloud, K8s, runtime) | ✅ | ❌ |
| Distributed Tracing (HTTP, gRPC) | ✅ | ❌ |
| Database Tracing (PG, MySQL, Oracle, MSSQL, Cassandra) | ✅ | ❌ |
| Message Queue Tracing (Kafka, AMQP, NATS) | ✅ | ❌ |
| Go TLS Plaintext Capture | ✅ | ❌ |
| Log Collection + Trace Enrichment | ✅ | ✅ |
| Continuous Profiling (CPU/memory/mutex) | ✅ | ❌ |
| Security Observability (syscall / FIM / escape) | ✅ | ❌ |
| Network Observability (DNS, TCP, XDP) | ✅ | ❌ |
| Connection Statistics & Service Topology | ✅ | ❌ |
| Kubernetes Metrics (kube-state + cAdvisor) | ✅ | ❌ |
| Node Exporter Fusion (120+ host metrics) | ✅ | ❌ |
| GPU / AI/ML Observability | ✅ | ❌ |
| SNMP Collection (v1/v2c/v3 + Traps) | ❌ | ✅ |
| Storage Array Adapters (Dell, HPE, Pure, NetApp) | ❌ | ✅ |

---

## OpenTelemetry Native — Vendor-Neutral by Design

Telegen is **100% OpenTelemetry compliant** for all four signal types. All data is exported via OTLP, eliminating vendor lock-in.

### Certified Backend Integrations

| Category | Backends |
|----------|---------|
| **All-in-one OTLP** | Grafana Cloud, Datadog, Dynatrace, Honeycomb, Lightstep |
| **Traces** | Jaeger, Zipkin, Tempo, AWS X-Ray, Azure Monitor |
| **Metrics** | Prometheus, Mimir, Thanos, VictoriaMetrics, InfluxDB |
| **Logs** | Loki, Elasticsearch/OpenSearch, Splunk, IBM QRadar, Microsoft Sentinel |
| **Profiles** | Grafana Pyroscope, Polar Signals, Google Cloud Profiler |
| **Collector** | OpenTelemetry Collector, Grafana Alloy, FluentBit |

All telemetry conforms to **OpenTelemetry Semantic Conventions**, ensuring consistent attribute naming and dashboard portability across backends.

---

## Deployment Options

### Kubernetes

```bash
helm install telegen oci://ghcr.io/mirastacklabs-ai/charts/telegen \
  --namespace telegen --create-namespace \
  --set otlp.endpoint="otel-collector:4317"
```

- DaemonSet for Agent mode; Deployment/StatefulSet for Collector mode
- Helm chart supports resource limits, tolerations, node selectors, PSPs/PSAs
- OpenShift-certified deployment available

### Linux (Bare Metal / VM / systemd)

```bash
curl -LO https://github.com/mirastacklabs-ai/telegen/releases/latest/telegen-linux-amd64.tar.gz
tar xzf telegen-linux-amd64.tar.gz && sudo mv telegen /usr/local/bin/
sudo systemctl enable --now telegen
```

### Containers (Docker / ECS / Fargate)

- Docker image available: `ghcr.io/mirastacklabs-ai/telegen`
- AWS ECS task definition templates provided
- Sidecar or standalone deployment patterns

### Kernel Requirements

| eBPF Feature | Minimum Kernel | Recommended |
|---|---|---|
| Core eBPF tracing | 4.18 | 5.8+ |
| Full feature set | 5.8 | 5.15+ (LTS) |
| XDP packet analysis | 4.8 | 5.15+ |

---

## Data Pipeline — Enterprise-Grade Controls

Telegen's internal pipeline includes controls critical for BFSI production environments:

| Control | Capability |
|---------|-----------|
| **Cardinality Limiting** | Per-metric series caps (default: 10,000 / global: 100,000) prevent cardinality explosions |
| **Rate Limiting** | Configurable per-signal rate caps (metrics, traces, logs per second) |
| **PII Redaction** | Automatic scan and redact of log bodies before export |
| **Attribute Limits** | Max resource attributes (128) and value size (4 KB) enforced |
| **Rule-Based Transforms** | OTTL-style transform rules: enrich, drop, rename attributes |
| **Hot Reload** | Configuration changes applied via `SIGHUP` — zero restart |
| **Graceful Shutdown** | 30-second drain timeout ensures no in-flight data is lost |
| **Persistent Queue** | Retry with exponential back-off; queue-based buffering |
| **Multi-Endpoint Failover** | Redundant OTLP endpoint configuration |

---

## Security & Compliance Positioning

| Framework | Telegen Coverage |
|-----------|-----------------|
| **PCI-DSS** | Req. 10 (audit logging), Req. 11 (network monitoring), syscall audit |
| **SOX** | Application change audit trail via process execution events and FIM |
| **MAS TRM** | Section 9 (security monitoring), Section 6 (capacity management) |
| **DORA (EU)** | Incident detection (MTTD), RCA support (traces + logs), ICT risk monitoring |
| **ISO 27001** | A.12.4 (logging), A.12.6 (vulnerability management) |
| **SOC 2 Type II** | CC6 (logical access), CC7 (system operations) |

**Deployment Security:**
- No outbound connections except OTLP to your designated collector
- Runs as a non-root process with `CAP_BPF` and `CAP_SYS_ADMIN` only
- TLS mutual authentication support on OTLP export
- Credentials injected via environment variables or Kubernetes Secrets — never in config files
- SNMPv3 with `authPriv` (SHA-256 + AES-256) for network devices

---

## Resource Footprint

| Deployment | CPU | Memory | Notes |
|------------|-----|--------|-------|
| Agent — minimal | 0.1 cores | 128 MB | Basic tracing + metrics |
| Agent — full features | 0.5 cores | 512 MB | All eBPF features enabled |
| Agent — high-volume trading | 1.0 cores | 1 GB | Large ring buffer (64 MB+) |
| Collector — SNMP | 0.2 cores | 256 MB | Per collector instance |
| Collector — storage | 0.3 cores | 384 MB | Per collector instance |

eBPF ring buffer is configurable from 4 MB (testing) to 256 MB (very high volume). The default 16 MB handles ~160,000 events before any backpressure.

---

## Why Telegen for BFSI

| | Traditional APM + Agents | Telegen |
|---|---|---|
| **Code changes required** | Yes — SDK per language | **None** |
| **Number of agents** | 4–6 per host | **1** |
| **Kernel-level visibility** | No | **Yes (eBPF)** |
| **Legacy application support** | Limited | **Full (protocol-level)** |
| **Signal correlation** | Manual / best-effort | **Automatic** |
| **OTLP compliance** | Partial | **100%** |
| **Storage array monitoring** | Separate tool | **Built-in** |
| **SNMP / network devices** | Separate tool | **Built-in** |
| **Security events to SIEM** | Separate HIDS | **Built-in** |
| **Vendor lock-in** | High | **None (OTel native)** |
| **Time to first trace** | Hours–Days | **< 5 minutes** |

---

## Getting Started

### Quickstart — Kubernetes

```bash
# 1. Add Telegen Helm chart
helm install telegen oci://ghcr.io/mirastacklabs-ai/charts/telegen \
  --namespace telegen \
  --create-namespace \
  --set otlp.endpoint="<your-otel-collector>:4317"

# 2. Verify deployment
kubectl get pods -n telegen

# 3. Traces, metrics, logs, and profiles begin flowing immediately
```

### Quickstart — Linux / Bare Metal

```bash
# Download and install
curl -LO https://github.com/mirastacklabs-ai/telegen/releases/latest/telegen-linux-amd64.tar.gz
tar xzf telegen-linux-amd64.tar.gz
sudo mv telegen /usr/local/bin/telegen

# Minimal configuration
cat > /etc/telegen/config.yaml <<EOF
telegen:
  mode: agent
otlp:
  endpoint: "otel-collector:4317"
EOF

# Start service
sudo systemctl enable --now telegen
```

---

## Contacts & Next Steps

| Step | Action |
|------|--------|
| **Technical Deep Dive** | Architecture walkthrough + live demo of traces, profiles, and security events |
| **Proof of Value** | 2-week PoV deployment on a non-production Kubernetes cluster |
| **Security Review** | Supply chain attestation, SBOM, CVE posture review |
| **Commercial Discussion** | Subscription model based on host count; volume tiers available |

---

*Telegen is developed by **Mirastack Labs** and is available as an open-core product with enterprise support, SLA guarantees, and professional services for regulated industries.*

*For product documentation, visit the [Telegen Docs](https://docs.mirastacklabs.ai/telegen). For enterprise enquiries, contact your Mirastack Labs account representative.*
