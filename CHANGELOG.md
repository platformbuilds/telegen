# Changelog

All notable changes to Telegen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`exports.include_signal_metadata` / `exports.metadata_fields`** — The signal-metadata surface documented in `docs/configuration/full-reference.md` and `docs/features/unified-pipeline.md` is now implemented. `cmd/telegen` publishes it via `sigdef.SetGlobalMetadataConfig` at startup, so the `telegen.*` attributes emitted by every collector are finally operator-controlled. Previously these keys were documented but absent from the config struct, which made any config using them fail to boot.
- **`exports.otlp.{grpc,http}.compression`** — Accepts `gzip` or `none`, matching the OpenTelemetry Collector convention. Supersedes the `gzip` boolean, which continues to work as a deprecated alias.
- **Shipped-config regression test** — `internal/config/shipped_configs_test.go` loads every config file and embedded ConfigMap block in the repo through `config.Load`, so a key that does not exist in the Go struct now fails `go test` rather than a customer's deployment.
- **NetApp ONTAP end-to-end test harness** — A fake filer drives the real collectors across six cluster shapes (RestPerf-capable at 9.9/9.14/9.16, KeyPerf fallback, ASA r2, GCNV) and asserts on what actually goes out and comes back. `TestEveryCatalogObjectResolves` resolves all 1,050 catalog-object × ONTAP-version pairs; `TestAllGeneratedURLsAreWellFormed` checks every emitted URL against ONTAP's query rules and enforces a per-shape request floor so a resolution regression cannot hide behind a clean defect count; `TestE2E_*` feeds ONTAP-shaped payloads through the whole pipeline and asserts on metric names, labels and type tolerance. `TestPluginCoverage` fails on any template plugin that is neither dispatched nor recorded in a shrink-only baseline of known gaps.

### Changed
- **OTLP export is now actually compressed.** `internal/exporters/otlp/otlp.go` never applied the `Gzip` field it declared, so all six SDK exporters and both Collector-standard exporters shipped uncompressed regardless of configuration. They now honour the configured codec. A config that sets neither `compression` nor `gzip` defaults to gzip, matching the intent previously hardcoded in `internal/pipeline/pipeline_core.go`. Set `compression: "none"` to restore the old on-the-wire behaviour.
- **`scripts/validate-configs.sh`** — Now covers `configs/*.yaml`, `deployments/kubernetes/collector-deployment.yaml`, local `custdeploy/` bundles, and telegen-shaped YAML fences in `docs/**`. Embedded-config extraction is indent-agnostic instead of assuming a two-space `config.yaml: |` key.

### Fixed
- **NetApp ONTAP: `^^` instance keys were not exported as labels.** A `^^` counter names the instance *and* is exported as a label — that is where `volume`, `svm`, `aggr`, `node` and `lun` come from. The collectors used it only to compose the internal instance key, so the primary identity was missing from nearly every Rest, KeyPerf and E-Series series: `volume_size` shipped without a `volume` label and every volume on the filer collapsed into one indistinguishable timeseries. Key ordering is now by display name as well, because a composed key has to agree between an object's primary query and its endpoint joins, and the two templates are free to declare their keys in different orders — a mismatch made the join silently drop every record. The four duplicated copies of this logic are now one `template.Partition`.
- **NetApp ONTAP: ASA r2 clusters collected almost nothing.** The `asar2` template tree is an overlay that redefines the handful of objects that differ on disaggregated hardware. Both Rest and KeyPerf treated it as a replacement: the catalog swapped wholesale and per-object resolution never fell back to the base tree. An ASA r2 filer therefore polled 3 Rest objects instead of ~68 and 1 KeyPerf object instead of 14. Catalogs now merge and template resolution falls back, taking a full ASA r2 collection from 6 requests to 103.
- **NetApp ONTAP: RestPerf labels and instance keys were read from the wrong place.** A counter-table row carries its identity in a `properties` array of `{name, value}` pairs, not as top-level fields. The collector looked for top-level fields, always missed, and then dumped every property as a label under a mangled name — a template declaring `^svm.name => svm` produced `svm_name`. Every RestPerf series was mislabelled and carried the full property set regardless of what the template asked for. Labels now resolve through the properties map and are keyed by the template's display name.
- **NetApp ONTAP: six RestPerf templates produced unlabelled series.** `fpolicy`, `fpolicy_server`, `fpolicy_svm`, `netstat`, `object_store_client_op` and `external_service_operation` declared their string properties as plain counters, so nothing marked an instance key or a label and their `export_options` named labels no counter produced. They now use `^^`/`^` markers.
- **NetApp ONTAP: mis-indented plugin rules were silently dropped.** Seven templates — inherited verbatim from Harvest — indent a `LabelAgent` rule level with the plugin name instead of under it, which YAML reads as two sibling keys. Dispatch now reattaches such an orphaned rule to the plugin it plainly belongs to, so the `split`, `split_regex` and `value_to_num` rules in `fcvi`, `lun`, `nic_common`, `wafl_comp_aggr_vol_bin`, `sensor` (9.10/9.12) and `clusterpeer` take effect. Plugin dispatch is now table-driven, and the `Vscan` plugin — which splits ONTAP's packed `node:svm:scanner` name into three labels — is implemented.
- **NetApp ONTAP: `security_audit_dest.yaml` exported a port number as a metric.** A stray `- port => port` counter, absent upstream, made `port` both an instance key and a gauge, colliding on the display name.
- **NetApp ONTAP: Harvest template directives leaked into the ONTAP `fields` query.** A `counters:` block may carry two directives — `hidden_fields:` and `filter:` — that configure the query rather than name counters. The template flattener treated them as nested counters, producing 84 phantom counters across 28 shipped templates and putting the literal strings `hidden_fields` and `filter` into `fields=`. ONTAP rejected each request with HTTP 400 (`The value "hidden_fields" is invalid for field "fields"`), which took down the whole object, not just the leaked field. Filter values containing quotes, such as `statistics.timestamp=!"-"`, additionally produced `The specified fields query contains an unmatched "`. Affected Rest objects included Aggregate, Volume, Qtree, Shelf, SnapMirror, Status, NetRoute, VolumeAnalytics, QuotaReport, Namespace, MetroclusterCheck and FCP.
- **NetApp ONTAP: hidden fields were never requested.** ONTAP omits fields marked hidden — and every metric derived from them — unless they are named explicitly in `fields`; `fields=*` does not expand to them. Because the directive was being consumed as a counter, no collector ever sent one. This silently zeroed the `space` metrics on aggregates, `health` on cluster status, `interfaces` on routes, `fabric` on FCP, and — most significantly — the entire `statistics` block that every KeyPerf metric is read from, so KeyPerf polled successfully while reporting nothing.
- **NetApp ONTAP: counters-block `filter` directives were dropped.** Rest, RestPerf and KeyPerf only applied the top-level `filter:` block. Queries went out unfiltered, so KeyPerf collected instances with no statistics (yielding bogus zero-rate samples) and objects such as Shelf, Quota, SnapMirror and QoS policy returned records their templates intend to exclude. Per-endpoint filters were dropped for the same reason.
- **NetApp ONTAP: a malformed counter path could take down an entire object.** Counter paths may carry gjson syntax — array selectors and multi-path braces — which is meaningful when reading a response but is not a field name. `netroute.yaml` sent `{interfaces` as a field and ONTAP rejected the request. Derived fields are now validated: a public query falls back to `fields=*` as Harvest does, and the private CLI passthrough, which does not accept `*`, drops only the offending field.
- **NetApp ONTAP: `max_records` was sent twice** when a template's filter set its own, as `volume_analytics.yaml` does. The filter's value now wins over the collector batch size.
- **NetApp ONTAP: `instance_add` on a join endpoint was parsed but ignored,** so an endpoint could never contribute instances the primary query did not return. Endpoint fills also no longer risk clearing labels set by the primary poll.
- **`deployments/kubernetes/configmap.yaml`** — The embedded config could not be parsed at all: the commented-out `pipeline:` example stopped being commented halfway through, leaving orphaned YAML under `selfTelemetry:`, and the `discovery:` key was commented out while its children stayed live under `ebpf:`. The old validator's error filter hid both.
- **`deployments/kubernetes/collector-deployment.yaml`** — The embedded `collector.yaml` was written against a `telegen:` / `collector:` schema that has never existed. Rewritten against the real `agent:` / `snmp_receiver:` / `storage:` keys.
- **`deployments/helm`** — `helm install` with default values rendered `selfTelemetry.listen: "::19090"`, because the template prefixed a colon onto a value that already carried one. The agent rejected the resulting config.
- **`configs/telegen-kafka-logs.yaml`** — Used field names the Kafka receiver does not define (`agent.environment`, `parser.extract_trace_context`, the `telemetry.emit_*` set, a nested `auth.sasl` block, `tls.enabled`, a boolean `error_backoff.jitter`) and placed `logs:` at the top level instead of under `pipelines:`.
- **`scripts/validate-configs.sh`** — Only reported errors whose text began with `line N:`, so whole-document failures such as YAML syntax errors were counted as passes. This is why the broken ConfigMap above survived CI.
- **`configs/telegen-full.yaml`** — 56 keys were either mis-nested (`internal_metrics`, `network`, `discovery`, `name_resolver`, `routes`, `filter`, and the three export sections belong under `ebpf:`) or misnamed (`tc_backend`, `bpf_fs`, `override_bpf_loop_enabled`, `cache_ttl`, `unmatch`). Sections that exist in no Go struct are now commented out with a `NOT IMPLEMENTED` marker rather than presented as working configuration.
- **Documentation YAML examples** — 105 YAML fences across 21 doc pages were rejected by `config.Load`. The recurring cause was an `agent:` wrapper around sections that are top-level (`ebpf`, `profiling`, `cloud`, `kubernetes`, `node_exporter`, `pipelines`), plus whole feature configs that no code reads. Examples for GPU/AI-ML collection, XDP, syscall auditing, file-integrity monitoring, container-escape detection, per-protocol database toggles, slow-query thresholds, TCP/packet sampling, and per-endpoint circuit-breaker tuning have been replaced with the real surface, or with an explicit statement that the feature is not configurable. Docs that legitimately describe a non-agent schema (Helm values) are skipped by name rather than silently passing.

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
