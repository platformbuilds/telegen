# Changelog

All notable changes to Telegen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
