# Changelog

All notable changes to Telegen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.28] - 2026-07-30

### Added
- **NetApp ONTAP Harvest-Parity Collector** — Full ONTAP observability with 65+ inventory objects, 54+ performance counter tables, KeyPerf for ASA r2, EMS events (86 message types → OTLP logs), 1,558 Harvest-compatible metric families
- **NetApp E-Series Support** — SANtricity REST API collector (16 inventory + 9 performance objects)
- **VMware vSphere Enhancements** — 74 distinct metrics, vCenter EventManager events as OTLP logs, synthesized inventory state-change logs, alarm handling via `AlarmStatusChangedEvent` color mapping
- **Messaging Protocol Tracing** — AMQP 0-9-1 (RabbitMQ), AMQP 1.0 (ActiveMQ/Azure Service Bus), OpenWire (ActiveMQ), STOMP — full OTel messaging semantics with `messaging.system` resolution
- **SunRPC/ONC RPC Tracing** — NFS, mountd, nlockmgr procedures via eBPF
- **MSSQL/TDS Protocol Tracing** — SQL Server TDS protocol (v7.0+) with FreeTDS and Microsoft ODBC Driver support
- **Couchbase Tracing** — Memcached Binary Protocol + N1QL query parsing
- **C/C++ Application Instrumentation** — Auto-detection of libpq, libmysqlclient, FreeTDS, libclntsh with `process.language=cpp` attribution
- **Go Channel-Link Events** — eBPF uprobes on `runtime.chansend`/`runtime.chanrecv` with span link creation for goroutine-level trace correlation
- **LLM API Tracing (GenAI)** — eBPF-based HTTP enrichment for OpenAI, Anthropic, Azure APIs with token counting, cost estimation, TTFT capture
- **CUDA Kernel Tracing** — `cudaLaunchKernel`, `cudaMemcpy`, `cudaMalloc` as OTLP spans via `gpuevent` tracer
- **Kubernetes Metrics Streaming** — kube-state-metrics + cadvisor OTLP push (replaces Prometheus scraping), K8s events as OTLP logs
- **Firewall Infrastructure Collection** — Palo Alto PAN-OS, FortiGate FortiOS, Arista CloudVision, Cisco ACI via `netinfra` config block
- **Unified V3 Pipeline** — Single production pipeline with adapter registry, converting pipeline, integration layer (PII redaction), persistent WAL queues, multi-endpoint failover with circuit breakers
- **OBI Span Bridge** — Upstream `go.opentelemetry.io/obi` span batch ingestion with `forwardOBISpanBatch`
- **Signal Metadata** — `telegen.*` attributes (category, subcategory, source module, BPF component, collector type) auto-attached to all signals via `sigdef.SignalMetadata`
- **Dubbo2 Protocol Tracing** — Apache Dubbo2 RPC over TCP (magic `0xDA 0xBB`) with serialization format detection (Hessian2, FastJSON, etc.)
- **Persistent WAL Queues** — Per-signal `queue.PersistentQueue` with replay workers for reliability
- **Multi-Endpoint Exporter** — Failover/fanout with circuit-breaker semantics
- **Shared OTLP Clients** — gRPC-primary with HTTP fallback, exposed via `GetMetricsExporter`, `GetLogsLoggerProvider`, `GetTracesExporter`

### Changed
- **README.md** — Full rewrite covering all signals, protocols, infrastructure, deployment
- **Documentation** — Comprehensive update of all feature docs, reference pages, and index files
- **Signal Registry** — Exhaustive `SignalMetadata` catalog in `internal/sigdef/signal_registry.go` covering all signal types
- **Instrumentation Options** — Added `InstrumentationSunRPC`, `InstrumentationMSSQL`, `InstrumentationCouchbase` to bitmask
- **BPF Verifier CI Gate** — Added verifier CI job and BPF gate documentation
- **eBPF CO-RE BPF Objects** — Updated for all new protocol tracers

### Fixed
- **K8s Metrics Streaming** — Dedupe repeated HELP/TYPE headers before OTLP conversion, start OTLP streaming before provider startup
- **Go Tracer** — Skip unresolved Go uprobes and fall back to generic tracer
- **VMware vSphere** — Harden vSphere collection reliability and event fidelity
- **NetApp ONTAP** — Hotfix unsafe MQ kernel classifier
- **eBPF** — Shrink large-buffer scratch maps to fit per-CPU limit
- **Kafka Tracing** — Broaden Kafka detection and align telemetry config, restore broker Kafka server-span fallback
- **cadvisor** — Default omitted optional fields before validation, align remaining config keys to snake_case YAML

---

## [3.1.27] - 2026-07-28

### Fixed
- **CI** — Hard-fail only generictracer in BPF load gate
- **CI** — Pass full Go toolchain env through sudo for verifier
- **CI** — Preserve setup-go under sudo for verifier jobs
- **CI** — Run gotracer attach-emit smoke in a separate process

---

## [3.1.26] - 2026-07-25

### Fixed
- **eBPF** — Hotfix unsafe MQ kernel classifier

---

## [3.1.25] - 2026-07-23

### Added
- **AMQP Protocols** — RabbitMQ AMQP 0-9-1 and AMQP 1.0 tracing (feat-bugfix)

---

## [3.1.24] - 2026-07-20

### Fixed
- **K8s Metrics** — Dedupe repeated HELP/TYPE headers before OTLP conversion

---

## [3.1.23] - 2026-07-18

### Fixed
- **K8s Metrics** — Start OTLP streaming before provider startup

---

## [3.1.22] - 2026-07-15

### Fixed
- **K8s Metrics** — Stream kube metrics and events to OTLP
- **C/C++ Instrumentation** — Now instruments C and C++ applications using standard DB drivers

---

## [3.1.21] - 2026-07-12

### Fixed
- **Tracing** — Restore broker Kafka server-span fallback

---

## [3.1.20] - 2026-07-10

### Fixed
- **eBPF** — Shrink large-buffer scratch maps to fit per-CPU limit

---

## [3.1.19] - 2026-07-08

### Fixed
- **Release** — Regenerate eBPF artifacts in tagged images

---

## [3.1.18] - 2026-07-05

### Fixed
- **Tracing** — Broaden Kafka detection and align telemetry config

---

## [3.1.17] - 2026-07-03

### Fixed
- **eBPF** — Restore upi-sim trace export and discovery wiring

---

## [3.1.16] - 2026-07-01

### Fixed
- **cadvisor** — Default omitted optional fields before validation

---

## [3.1.15] - 2026-06-30

### Fixed
- **cadvisor** — Align remaining config keys to snake_case YAML

---

## [3.1.14] - 2026-06-28

### Fixed
- **Pipeline** — Restore k8s metrics and obiupstream release build

---

## [3.1.13] - 2026-06-25

### Fixed
- **Env Parse Crash** — Fix env parse crash and wire go channel-link events (#104)
- **Go Channel Events** — eBPF uprobes on `runtime.chansend`/`runtime.chanrecv` for span link creation

---

## [3.1.12] - 2026-06-23

### Changed
- **Release** — Use Docker Hub username secret for login

---

## [3.1.11] - 2026-06-20

### Fixed
- **Release** — Hardcode Docker Hub org auth and image targets

---

## [3.1.10] - 2026-06-18

### Fixed
- **Release** — Login to Docker Hub with org namespace

---

## [3.1.9] - 2026-06-15

### Fixed
- **Release** — Make GHCR visibility update best-effort

---

## [3.1.8] - 2026-06-12

### Changed
- **Release** — Stamp docker builds with explicit version metadata

---

## [3.1.7] - 2026-06-10

### Fixed
- **Release** — Publish release images to Docker Hub namespace

---

## [3.1.6] - 2026-06-08

### Fixed
- **Release** — Enforce public visibility for GHCR package

---

## [3.1.5] - 2026-06-05

### Fixed
- **Release** — Enforce public visibility for GHCR package

---

## [3.1.4] - 2026-06-03

### Fixed
- **eBPF** — Satisfy staticcheck in Dubbo2 frame handling

---

## [3.1.3] - 2026-06-01

### Fixed
- **eBPF Watcher** — Read process exit status from task_struct
- **VMware** — Harden vSphere collection reliability and event fidelity

---

## [2.10.1] - 2026-02-05

### Added

#### Native Log Collection Pipeline
- Native container runtime parsers: Docker JSON, containerd, CRI-O
- Automatic Kubernetes metadata extraction from log file paths
- Application-aware parsing: Spring Boot, Log4j, Logback, Python logging
- 100% OTLP-compliant log records with full semantic convention support

#### Log Trace Enrichment (eBPF)
- `log_enricher`: eBPF-based trace context capture at write syscall
- `LogTraceCorrelator`: Time-windowed correlation cache (100ms buckets, 30s TTL)
- JSON log injection: Direct trace_id/span_id injection into structured logs
- Plain-text log correlation: Links any log format to distributed traces

#### Non-Kubernetes Environment Support
- File path-based correlation for VMs and bare-metal deployments
- Dual correlation key support: `cid:<container_id>` (K8s) and `path:<file_path>` (non-K8s)
- Works with application logs in `/var/log/myapp/` or custom paths

### Documentation

- Added comprehensive Log Collection & Trace Enrichment guide
- Updated features index with log collection capabilities
- Added troubleshooting and performance tuning sections

---

## [1.1.0] - 2026-01-30

### Security

- Fixed 30 Dependabot security alerts by upgrading all dependencies
- Updated OpenTelemetry Collector components v1.49.0 → v1.50.0
- Updated Go crypto packages to latest secure versions

### Changed

- Upgraded OpenTelemetry SDK and exporters
  - `go.opentelemetry.io/otel/exporters/otlp/otlplog` v0.5.0 → v0.15.0
  - `go.opentelemetry.io/otel/log` v0.5.0 → v0.15.0
  - `go.opentelemetry.io/otel/sdk/log` v0.5.0 → v0.15.0
- Upgraded OpenTelemetry Collector to v0.144.0
- Upgraded AWS SDK v2 components to latest versions
- Upgraded Kubernetes client-go and controller-runtime to v0.23.1
- Upgraded Prometheus client to v0.309.1
- Upgraded MongoDB driver to v2.5.0
- Upgraded compression libraries (klauspost/compress, lz4)
- Upgraded gRPC gateway to v2.27.7
- Upgraded golang.org/x packages (crypto, net, text, term)

### Dependencies

Key dependency updates:
- `github.com/aws/aws-sdk-go-v2` v1.40.1 → v1.41.1
- `github.com/klauspost/compress` v1.18.2 → v1.18.3
- `github.com/pierrec/lz4/v4` v4.1.23 → v1.25
- `go.mongodb.org/mongo-driver/v2` v2.4.1 → v2.5.0
- `golang.org/x/crypto` v0.46.0 → v0.47.0
- `golang.org/x/net` v0.48.0 → v0.49.0
- `google.golang.org/genproto` updated to 2026-01-28 release
- `k8s.io/apiextensions-apiserver` v0.34.1 → v0.35.0
- `sigs.k8s.io/controller-runtime` v0.22.4 → v0.23.1

---

## [1.0.0] - 2026-01-30

### Added

#### Core Platform
- Zero-configuration deployment - just specify OTLP endpoint
- Dual deployment modes: Agent (local) and Collector (remote)
- OpenTelemetry-first output (OTLP/gRPC and OTLP/HTTP)
- Unified signal model: metrics, traces, logs, profiles
- Automatic signal correlation (trace_id/span_id in logs, exemplars)

#### Auto-Discovery Engine
- OS and architecture detection
- Cloud provider detection (AWS, GCP, Azure, Alibaba, Oracle, DigitalOcean)
- Private cloud support (OpenStack, VMware vSphere, Nutanix)
- Kubernetes metadata enrichment
- Runtime/language detection (Go, Java, Python, Node.js, .NET, Rust)
- Database and message queue auto-discovery
- Service classification and topology mapping

#### Continuous Profiling (12 Profile Types)
- CPU profiling via eBPF perf_event
- Off-CPU profiling via sched_switch
- Wall clock profiling
- Memory profiling (allocations, heap, RSS)
- Mutex contention profiling
- Block profiling
- Goroutine profiling (Go)
- Disk I/O profiling
- Network I/O profiling
- Exception/panic profiling
- Flame graph generation
- OTLP Profiles export

#### Security Observability
- Syscall auditing (execve, ptrace, setuid, mount, module loading)
- File integrity monitoring
- Container escape detection
- Capability tracking
- Configurable alerting with rate limiting
- OTLP Logs export

#### Network Deep Observability
- XDP packet tracing (L2-L4)
- TCP metrics (RTT, retransmits, congestion)
- DNS query/response tracing
- Protocol parsing (HTTP/1.1, HTTP/2, gRPC, WebSocket)
- TLS metadata extraction
- Service mesh integration (Istio, Linkerd, Cilium)
- VLAN and multicast/broadcast tracking

#### Database & Message Queue Tracing
- PostgreSQL wire protocol tracing
- MySQL/MariaDB protocol tracing
- Oracle TNS/Net8 tracing
- IBM DB2 DRDA tracing
- MongoDB wire protocol tracing
- Redis RESP tracing
- Kafka protocol tracing with consumer lag
- RabbitMQ AMQP tracing
- Query plan analysis (EXPLAIN)
- Prepared statement tracking

#### Infrastructure Adapters
- SNMP receiver (v1/v2c/v3, polling + traps)
- Dell storage (PowerStore, PowerScale)
- HPE storage (Primera, 3PAR)
- Pure Storage (FlashArray, FlashBlade)
- NetApp storage (ONTAP, E-Series)
- Network infrastructure (Cisco ACI, Arista CloudVision, Juniper Mist)

#### AI/ML Workload Observability
- NVIDIA GPU metrics via NVML
  - Utilization, memory, power, temperature, clocks
  - PCIe and NVLink throughput
  - MIG partition metrics
  - ECC error tracking
  - Per-process attribution
- LLM token tracking
  - Request/response token counting
  - Cost estimation with configurable rates
  - Latency percentiles per model
- ML framework profiling (PyTorch, TensorFlow)
- eBPF tracers for CUDA and LLM APIs

#### Analytics Engine
- Isolation Forest anomaly detection
- Trace anomaly detection
- 5-Why Root Cause Analysis engine
- Signal correlation
- Recommendation engine

#### Deployment
- Kubernetes DaemonSet manifests
- Helm chart with full templating
- OpenShift support (SCC, GPU Operator)
- Docker Compose
- AWS ECS (with GPU instance support)
- systemd service unit
- Multi-architecture support (amd64, arm64)

### Changed
- Complete rewrite from v0.x codebase
- Configuration schema redesigned for zero-config defaults
- All metrics renamed to follow OTel semantic conventions

### Removed
- Legacy configuration format (use migration tool)
- Prometheus-only export mode (now OTLP-first)

---

## [0.x.x] - Legacy

See legacy changelog in the `v0` branch.
