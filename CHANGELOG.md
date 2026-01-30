# Changelog

All notable changes to Telegen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
