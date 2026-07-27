# Telegen Kafka / Redis / KeyDB tracing coverage

Static analysis confirming how Kafka and RESP-compatible stores (Redis, KeyDB, Valkey) are captured across languages, and what to check at runtime in `upi-sim`.

**Conclusion:** Kafka had a real source-level classifier gap. The eBPF Kafka classifier only recognized Metadata requests at API version 10-13, while `segmentio/kafka-go@v0.4.47` uses older Metadata versions (v8 in transport metadata structs, v1 in legacy conn path). Result: Kafka connections were never classified, so broker-side Kafka spans were missing even when Redis/KeyDB/MariaDB spans appeared.

---

## 1. Default instrumentation includes Kafka and Redis traces

`internal/obi/config.go:253-266` enables `InstrumentationRedis` and `InstrumentationKafka` in the default traces configuration alongside HTTP, gRPC, SQL, etc.

---

## 2. Generic (non-Go) tracer path — JVM, C/C++, and all non-Go runtimes

### Attachment

`internal/discover/attacher.go:202-206` routes `InstrumentableJava`, `InstrumentableJavaNative`, `InstrumentableGeneric`, C/C++-like generic types, Python, Ruby, Node, .NET, Rust, and PHP to `newGenericTracersGroup`.

`internal/discover/finder.go:149-153` defines `newGenericTracersGroup` → `generictracer.New(...)`.

`internal/tracers/generictracer/generictracer.go:62-75` implements the generic eBPF tracer (TC/socket hooks + userspace event processing).

### L7 wire-protocol classification (Kafka + Redis/KeyDB)

**eBPF inference (first pass):**

- `bpf/network/protocol_inference.h:98-102` — `infer_redis()` detects RESP framing (`*`, `+`, `-`, `:`, `$`).
- `bpf/network/protocol_inference.h:123+` — `infer_kafka()` detects Kafka wire protocol.
- `bpf/network/protocol_inference.h:328-333` — protocol dispatch includes Kafka; Redis is handled in the dedicated Redis path.

**Kernel classifier gate (Kafka-specific):**

- `bpf/generictracer/k_tracer.c:1155-1161` — Kafka classification is attempted via `is_kafka(...)`.
- `bpf/generictracer/protocol_kafka.h:150-188` (before fix) — request-header validation accepted only Metadata (`api_key=3`) with `api_version 10-13`.
- `bpf/generictracer/protocol_kafka.h:476-478` — only on successful validation is `ProtocolTypeKafka` written to `protocol_cache`.
- `bpf/generictracer/k_tracer_defs.h:32-63` — cached protocol type is reused for subsequent buffers on the same connection.

**Userspace transform (span construction):**

- `internal/ebpf/common/kafka_detect_transform.go:58-60` — `ProcessPossibleKafkaEvent` parses Kafka TCP payloads.
- `internal/ebpf/common/kafka_detect_transform.go:227-230` — sets `EventTypeKafkaClient` vs `EventTypeKafkaServer` from connection direction (`trace.Direction == 0` → server).
- `internal/ebpf/common/tcp_detect_transform.go:72-80` — Kafka path is taken when `event.ProtocolType == ProtocolTypeKafka`.
- `internal/ebpf/common/tcp_detect_transform.go:214-222,352-376` — SQL/Redis still have userspace heuristics even when kernel classification is not Kafka.
- `internal/ebpf/common/redis_detect_transform.go:34-40` — `isRedis()` / `isRedisOp()` validate RESP frames (covers Redis, KeyDB, Valkey — all RESP-compatible).
- `internal/ebpf/common/redis_detect_transform.go:231-234` — sets `EventTypeRedisClient` vs `EventTypeRedisServer` from direction.

**Server-side spans are language-independent:** broker (Kafka) and KeyDB/Redis server spans are produced when the **server process** is instrumented and plaintext L7 is visible on the socket. Direction bit selects server vs client span kind; the server binary language does not matter.

---

## 3. Go uprobe path — richer client spans

### Go-specific tracers

`internal/discover/finder.go:145-147` — `newGoTracersGroup` → `gotracer.New(...)`.

`internal/discover/attacher.go:177-201` — Go binaries with valid offsets use the Go tracer; otherwise fall back to generic instrumentation with a warning.

### Go Kafka client (Sarama)

`internal/ebpf/common/go_kafka_transform.go:15-28` — `ReadGoSaramaRequestIntoSpan` reads Go uprobe events and builds `EventTypeKafkaClient` spans via `GoKafkaSaramaToSpan`.

`bpf/gotracer/go_kafka_go.c` — BPF probes for Go Sarama client paths.

### Go Redis client

Go Redis clients are covered via Go uprobes in `bpf/gotracer/` (same pattern as other Go DB clients) **and** via generic TCP/RESP classification when uprobes are unavailable.

### `skip_go_specific_tracers` flag

`internal/appolly/services/criteria.go:95` — `SkipGoSpecificTracers bool` (`yaml:"skip_go_specific_tracers"`, env `OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS`).

`internal/discover/typer.go:248-253` — when Go offsets are missing and flag is false, logs a warning; process still gets generic instrumentation.

`internal/discover/typer.go:272-274` — when flag is true, skips Go offset inspection entirely.

`internal/discover/attacher.go:180-194` — forces generic tracer when flag is set, offsets are nil, or instrumentation error occurred.

**Default:** `skip_go_specific_tracers: false` (`deployments/helm/templates/_helpers.tpl:174`, `configs/telegen-full.yaml:491`).

With the default, Go apps prefer uprobes; Kafka/Redis traffic still appears via generic tracer on fallback.

---

## 4. Multi-language coverage matrix

| Runtime | Tracer attached | Kafka spans | Redis/KeyDB spans |
|---------|----------------|-------------|-------------------|
| Go (offsets found) | `gotracer` (+ generic fallback on error) | Go Sarama uprobes + generic TCP | Go uprobes + generic RESP |
| Go (no offsets / skip flag) | `generictracer` | Generic TCP Kafka parser | Generic RESP parser |
| JVM (Java / JavaNative) | `generictracer` | Generic TCP Kafka parser | Generic RESP parser |
| C/C++ / Generic | `generictracer` | Generic TCP Kafka parser | Generic RESP parser |
| Python, Ruby, Node, .NET, Rust, PHP | `generictracer` | Generic TCP Kafka parser | Generic RESP parser |

**Known limitation:** All generic L7 parsing requires **plaintext** wire protocol. TLS/SASL_SSL on Kafka or TLS on Redis/KeyDB prevents eBPF L7 classification (see H1 decision tree below).

---

## 4a. Kafka classifier gap and fix (root cause)

### Root cause

- Kafka classification depended on Metadata version 10-13 in kernel space (`bpf/generictracer/protocol_kafka.h:150-188`).
- There is no reliable userspace Kafka fallback comparable to SQL/Redis heuristics (`internal/ebpf/common/tcp_detect_transform.go:72-80`).
- `segmentio/kafka-go@v0.4.47` metadata structs cap at v8 (`/Users/aarvee/go/pkg/mod/github.com/segmentio/kafka-go@v0.4.47/protocol/metadata/metadata.go:9-25`) and legacy conn path emits metadata v1 (`/Users/aarvee/go/pkg/mod/github.com/segmentio/kafka-go@v0.4.47/conn.go:255,283`).

### Implemented fix

- Extend classifier constants and request validation in `bpf/generictracer/protocol_kafka.h`:
  - Added classification support constants for Produce/Fetch (`k_kafka_api_key_produce`, `k_kafka_api_key_fetch`) and version bounds (`k_kafka_max_produce_api_version`, `k_kafka_max_fetch_api_version`) at `bpf/generictracer/protocol_kafka.h:91-99`.
  - Replaced metadata-only request validation with per-API-key validation (Produce/Fetch/Metadata) at `bpf/generictracer/protocol_kafka.h:179-204`.
- This broadens classification to steady-state data-plane requests while keeping existing response correlation and message-size safeguards intact.

---

## 5. C3 — `db.system` refinement (cosmetic)

`internal/semconv/dbsystem_refine.go` — `ResolveDBSystemFromExecutableHints()` maps process/K8s hints to `keydb`, `valkey`, or `mariadb`.

`internal/appolly/app/request/span.go` — `RedisDBSystemName()` and refined `DBSystemName()` for MySQL family.

`pkg/export/otel/tracesgen/tracesgen.go:446-451` — Redis spans use `span.RedisDBSystemName()`.

Unit tests: `internal/semconv/dbsystem_refine_test.go`, `internal/appolly/app/request/span_dbsystem_test.go`.

---

## 6. H1 — Human runtime diagnostic runbook (`upi-sim`)

**Prerequisites:** C1 `values-agent.yaml` deployed; C2 chart re-vendored into mirastack and agent redeployed.

```sh
# 1) Did the agent discover/attach anything in upi-sim?
kubectl -n mirastack logs ds/telegen-agent | grep -iE "discovered|instrument|attach|upi-sim|kafka|keydb|redis"

# 2) Use safe startup debug logs only (avoid protocol hot-path printf):
#    OTEL_EBPF_LOG_LEVEL=debug
kubectl -n mirastack logs ds/telegen-agent | grep -iE "kafka|classify|protocol|correlation"

# 3) Do HTTP/gRPC spans from upi-sim reach the collector at all?
#    (check VictoriaTraces / mirastack UI for any upi-sim service spans)
```

### Decision tree (pick exactly one)

| Observation | Cause | Remediation |
|-------------|-------|-------------|
| No HTTP/gRPC spans AND logs show no `upi-sim` processes selected | **#1 K8s metadata / discovery** | C1 `openPorts` + `k8sNamespace` fallbacks should select processes. If still empty, verify Kubernetes decoration (`kubernetes.enable` in rendered config after C2 re-vendor). Re-run H1. |
| HTTP/gRPC spans appear, logs show NO kafka classification, traffic uses TLS/SASL_SSL | **#2 Encryption** | eBPF cannot parse encrypted L7. Use plaintext listeners or SDK instrumentation. No chart fix produces L7 spans. |
| HTTP/gRPC spans appear, logs show redis/kafka classified, but no spans exported | **Export / instrumentation list** | Confirm rendered `ebpf.otel_traces_export` and traces `instrumentations` include kafka/redis (fixed by C2 re-vendor). |
| Redis/SQL spans appear but Kafka missing for kafka-go clients | **#3 Kafka classifier version gate** | Ensure classifier includes Produce/Fetch and metadata classification is not restricted to v10-13 only. |

---

## 7. H2 — Human end-to-end validation

1. Redeploy `telegen-agent` with updated `values-agent.yaml` and re-vendored C2 chart.
2. Drive Kafka produce/consume and KeyDB `SET`/`GET` in `upi-sim`.
3. In VictoriaTraces / mirastack UI confirm:
   - Kafka spans with `messaging.*` attributes
   - KeyDB spans with `db.system=keydb` (or `redis` before C3 deploy)
4. Record pass/fail once. On failure, return to H1 decision tree — do not iterate blindly.

---

## 8. Deployment changes summary (this effort)

| Task | Repo | Change |
|------|------|--------|
| C1 | mirastack `values-agent.yaml` | `openPorts` fallbacks |
| C2 | telegen `deployments/helm/templates/_helpers.tpl` | Schema-correct `ebpf.tracer.*`, `ebpf.network`, `kubernetes:` block |
| C3 | telegen source | `db.system` refinement for KeyDB/Valkey/MariaDB |
| C4 | telegen source | Kafka classifier broadened to classify Produce/Fetch + relaxed metadata classification gate |
| Re-vendor | mirastack (human) | Update pinned telegen commit per `deployments/reference/kubernetes/helm/telegen/README.md` |
