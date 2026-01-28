# OpenTelemetry eBPF Instrumentation (OBI) - Engineering Documentation

> **Version:** 0.4.1  
> **Module:** `go.opentelemetry.io/obi`  
> **Go Version:** 1.25.6+  
> **Kernel Requirements:** Linux 5.8+ with BTF, or RHEL8/CentOS8 with kernel 4.18+ (backported eBPF)

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Project Structure](#project-structure)
4. [Core Components](#core-components)
   - [BPF Layer](#bpf-layer)
   - [Go Runtime Layer](#go-runtime-layer)
   - [Pipeline Architecture](#pipeline-architecture)
5. [Data Flow](#data-flow)
6. [eBPF Instrumentation](#ebpf-instrumentation)
   - [Tracer Types](#tracer-types)
   - [Protocol Support](#protocol-support)
   - [Probe Attachment](#probe-attachment)
7. [Process Discovery](#process-discovery)
8. [Context Propagation](#context-propagation)
9. [Exporters](#exporters)
10. [Kubernetes Integration](#kubernetes-integration)
11. [Configuration System](#configuration-system)
12. [Build System](#build-system)
13. [Testing Strategy](#testing-strategy)
14. [Performance Considerations](#performance-considerations)
15. [Security Model](#security-model)

---

## Executive Summary

### What is OBI?

**O**penTelemetry e-**B**PF **I**nstrumentation (OBI) is a zero-code, eBPF-based auto-instrumentation agent that provides application and network observability without requiring any code changes to target applications. It leverages Linux kernel eBPF technology to intercept and trace network requests at the kernel and user-space level, producing OpenTelemetry-compliant traces and metrics.

### Why eBPF?

1. **Zero-code instrumentation**: No SDK integration or code modification required
2. **Low overhead**: eBPF programs run in kernel space with minimal performance impact
3. **Language-agnostic**: Works with any language/runtime (Go, Node.js, Java, Ruby, Python, etc.)
4. **Production-safe**: Verified by the kernel before execution, cannot crash the system
5. **Deep visibility**: Access to kernel-level networking events not available to user-space agents

### What OBI is NOT

- **Not a replacement for SDK instrumentation**: Manual instrumentation provides finer granularity for internal service machinery
- **Not a full APM solution**: Focuses on incoming/outgoing service requests, not internal spans
- **Not cross-platform**: Linux-only due to eBPF requirements

---

## Architecture Overview

OBI operates as a daemon that:

1. **Discovers** processes matching configured criteria (by executable path, port, or Kubernetes metadata)
2. **Attaches** eBPF programs to kernel and user-space probe points
3. **Collects** telemetry data from eBPF ring buffers
4. **Transforms** raw events into OpenTelemetry spans and metrics
5. **Exports** telemetry to configured backends (OTLP, Prometheus)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              User Space (OBI Agent)                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────┐   ┌─────────────────┐ │
│  │   Process    │──▶│   Trace      │──▶│   Transform  │──▶│    Exporters    │ │
│  │   Discovery  │   │   Attacher   │   │   Pipeline   │   │  (OTEL/Prom)    │ │
│  └──────────────┘   └───────────────┘   └──────────────┘   └─────────────────┘ │
│         │                  │                   ▲                               │
│         ▼                  ▼                   │                               │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────┐                       │
│  │     K8s      │   │   eBPF Map   │   │  Ring Buffer │                       │
│  │   Informer   │   │  Management  │   │   Reader     │                       │
│  └──────────────┘   └───────────────┘   └──────────────┘                       │
│                            │                   ▲                               │
└────────────────────────────┼───────────────────┼───────────────────────────────┘
                             │                   │
─────────────────────────────┼───────────────────┼────────────────────────────────
                             ▼                   │
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Kernel Space (eBPF)                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                           eBPF Programs                                      ││
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           ││
│  │  │  kprobes    │ │  uprobes    │ │  tracepoints│ │   TC/XDP    │           ││
│  │  │ (syscalls)  │ │ (user libs) │ │  (sched)    │ │  (network)  │           ││
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘           ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                           eBPF Maps                                          ││
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐               ││
│  │  │ Ring Buffer│ │ Hash Maps  │ │ LRU Cache  │ │ Per-CPU    │               ││
│  │  │  (events)  │ │ (tracking) │ │ (protocol) │ │   Arrays   │               ││
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘               ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
opentelemetry-ebpf-instrumentation/
├── bpf/                          # eBPF C code
│   ├── bpfcore/                  # libbpf CO-RE headers (vmlinux, helpers)
│   ├── common/                   # Shared C headers (protocol types, connection info)
│   ├── generictracer/            # Generic (kprobe-based) tracer for all languages
│   ├── gotracer/                 # Go-specific uprobes tracer
│   ├── tctracer/                 # Traffic Control (TC) based context propagation
│   ├── tpinjector/               # Traceparent injection via sockmap/sk_msg
│   ├── netolly/                  # Network observability eBPF programs
│   ├── gpuevent/                 # GPU/CUDA instrumentation
│   ├── logenricher/              # Log-trace correlation
│   ├── maps/                     # Shared eBPF map definitions
│   ├── pid/                      # PID filtering and namespace handling
│   └── logger/                   # BPF debug logging
│
├── cmd/
│   ├── ebpf-instrument/          # Main binary entry point
│   └── k8s-cache/                # Kubernetes metadata cache service
│
├── pkg/
│   ├── obi/                      # Core configuration and OS checks
│   ├── appolly/                  # Application observability pipeline
│   │   ├── app/                  # Request/span data structures
│   │   ├── discover/             # Process discovery and attachment
│   │   ├── services/             # Service matching criteria
│   │   └── traces/               # Trace decoration
│   ├── ebpf/                     # eBPF program loading and management
│   │   ├── common/               # Shared Go types matching BPF
│   │   └── tcmanager/            # TC program attachment
│   ├── export/                   # Telemetry exporters
│   │   ├── otel/                 # OpenTelemetry traces/metrics
│   │   ├── prom/                 # Prometheus metrics
│   │   └── attributes/           # Attribute selection and mapping
│   ├── kube/                     # Kubernetes informers and metadata
│   ├── netolly/                  # Network observability (flows)
│   ├── pipe/                     # Pipeline framework (swarm pattern)
│   ├── transform/                # Data transformation nodes
│   ├── filter/                   # Attribute-based filtering
│   ├── config/                   # Configuration types
│   └── internal/                 # Internal packages
│       ├── ebpf/                 # Generated eBPF bindings
│       ├── goexec/               # Go binary analysis (DWARF, offsets)
│       ├── java/                 # Java agent integration
│       └── nodejs/               # Node.js detection
│
├── configs/offsets/              # Pre-computed struct offsets for libraries
├── devdocs/                      # Developer documentation
└── internal/test/                # Integration tests
```

---

## Core Components

### BPF Layer

The BPF layer consists of C programs compiled to eBPF bytecode. These are organized by tracer type:

#### Common Headers (`bpf/common/`)

| File | Purpose |
|------|---------|
| `common.h` | Base includes, constants (buffer sizes, max lengths) |
| `http_types.h` | HTTP request trace structures, HTTP/2 definitions |
| `connection_info.h` | IPv4/IPv6 connection tuple (src/dst addr:port) |
| `tp_info.h` | Trace propagation info (trace_id, span_id, flags) |
| `tracing.h` | Trace correlation logic, epoch-based cleanup |
| `protocol_defs.h` | Protocol type enum (HTTP, gRPC, SQL, Redis, etc.) |
| `sql.h` | SQL protocol detection structures |

#### Key Data Structures

```c
// Connection identification (from connection_info.h)
typedef struct connection_info {
    u8 s_addr[16];     // Source IP (v4 in last 4 bytes for IPv4)
    u8 d_addr[16];     // Destination IP
    u16 s_port;        // Source port
    u16 d_port;        // Destination port
} connection_info_t;

// HTTP request trace event (from common.h)
typedef struct http_request_trace {
    u8 type;                           // Event type
    u16 status;                        // HTTP status code
    unsigned char method[METHOD_MAX_LEN];
    unsigned char path[PATH_MAX_LEN];
    unsigned char host[HOST_MAX_LEN];
    u64 start_monotime_ns;             // Request start
    u64 end_monotime_ns;               // Response end
    s64 content_length;
    tp_info_t tp;                      // Trace context
    connection_info_t conn;            // Connection tuple
    pid_info pid;                      // Process info
} http_request_trace_t;

// Trace propagation info (from tp_info.h)
typedef struct tp_info {
    u8 trace_id[16];   // W3C trace-id (128-bit)
    u8 span_id[8];     // W3C span-id (64-bit)
    u8 parent_id[8];   // Parent span-id
    u64 ts;            // Timestamp for correlation
    u8 flags;          // Sampling flags
} tp_info_t;
```

### Go Runtime Layer

#### Main Entry Point (`cmd/ebpf-instrument/main.go`)

```go
func main() {
    // 1. Validate OS support (kernel version, BTF, capabilities)
    obi.CheckOSSupport()
    
    // 2. Load configuration from file/env
    config := loadConfig(configPath)
    
    // 3. Validate configuration
    config.Validate()
    
    // 4. Start instrumentation pipeline
    instrumenter.Run(ctx, config)
}
```

#### Instrumenter Package (`pkg/instrumenter/`)

The instrumenter orchestrates two observability modes:

1. **Application Observability (AppO11y)**: Traces and metrics for application requests
2. **Network Observability (NetO11y)**: Network flow metrics

```go
func Run(ctx context.Context, cfg *obi.Config) error {
    ctxInfo := BuildCommonContextInfo(ctx, cfg)
    
    g, ctx := errgroup.WithContext(ctx)
    
    if cfg.Enabled(obi.FeatureAppO11y) {
        g.Go(func() error { return setupAppO11y(ctx, ctxInfo, cfg) })
    }
    
    if cfg.Enabled(obi.FeatureNetO11y) {
        g.Go(func() error { return setupNetO11y(ctx, ctxInfo, cfg) })
    }
    
    return g.Wait()
}
```

### Pipeline Architecture

OBI uses a **swarm** pattern for its processing pipeline—a directed acyclic graph (DAG) of processing nodes connected by typed message queues.

#### Swarm Pattern (`pkg/pipe/swarm/`)

```go
// Instancer builds a pipeline from registered nodes
type Instancer struct {
    nodes []instancerNode
}

// Add registers a node with the pipeline
func (s *Instancer) Add(provider InstanceFunc, opts ...Option)

// Instance creates the runnable pipeline
func (s *Instancer) Instance(ctx context.Context) (*Runner, error)
```

#### Message Queues (`pkg/pipe/msg/`)

Type-safe, buffered channels with configurable timeout and panic-on-timeout behavior:

```go
type Queue[T any] struct {
    ch          chan T
    sendTimeout time.Duration
    panicOnFull bool
}
```

---

## Data Flow

### Application Observability Pipeline

```
ProcessWatcher ──▶ WatcherKubeEnricher ──▶ CriteriaMatcher ──▶ ExecTyper
     │                    │                      │                │
     │                    │                      │                ▼
     │                    │                      │          ContainerDBUpdater
     │                    │                      │                │
     │                    │                      │                ▼
     ▼                    ▼                      ▼           TraceAttacher
 [Process Events]   [K8s Enriched]        [Matched]              │
                                                                  ▼
                                                         eBPF Tracers (per exec)
                                                                  │
                                                                  ▼
                                                         Ring Buffer Reader
                                                                  │
                                                                  ▼
                                                         traces.ReadDecorator
                                                                  │
                                                                  ▼
                                                              Routes
                                                                  │
                                                                  ▼
                                                         KubernetesDecorator
                                                                  │
                                                                  ▼
                                                           NameResolver
                                                                  │
                                                                  ▼
                                                         AttributesFilter
                                                                  │
                              ┌─────────────────┬───────────────┬─┴─────────────────┐
                              ▼                 ▼               ▼                   ▼
                       OTEL Traces      OTEL Metrics     Prometheus         TracePrinter
```

### Request Span Structure (`pkg/appolly/app/request/span.go`)

```go
type Span struct {
    Type          EventType      // HTTP, GRPC, SQL, Redis, Kafka, etc.
    Method        string         // HTTP method or RPC method
    Path          string         // URL path or statement
    Route         string         // Matched route pattern
    Status        int            // Response status code
    ContentLength int64          // Request body size
    Start         int64          // Start timestamp (monotonic)
    End           int64          // End timestamp (monotonic)
    
    // Connection info
    Peer          string         // Peer address
    PeerPort      int            // Peer port
    Host          string         // Host/server address
    HostPort      int            // Host port
    
    // Trace context
    TraceID       trace.TraceID  // W3C trace-id
    SpanID        trace.SpanID   // W3C span-id
    ParentSpanID  trace.SpanID   // Parent span-id
    Flags         uint8          // Trace flags
    
    // Service attribution
    Service       *svc.Attrs     // Service metadata
    
    // PID info
    Pid           PidInfo        // Host PID, User PID, Namespace
}
```

### Event Types

```go
const (
    EventTypeHTTP            // Server HTTP request
    EventTypeGRPC            // Server gRPC request
    EventTypeHTTPClient      // Client HTTP request
    EventTypeGRPCClient      // Client gRPC request
    EventTypeSQLClient       // Database query
    EventTypeRedisClient     // Redis command
    EventTypeKafkaClient     // Kafka produce
    EventTypeKafkaServer     // Kafka consume
    EventTypeMQTTClient      // MQTT publish
    EventTypeMQTTServer      // MQTT subscribe
    EventTypeMongoClient     // MongoDB operation
    EventTypeDNS             // DNS query
    EventTypeGPUKernelLaunch // CUDA kernel
    // ... and more
)
```

---

## eBPF Instrumentation

### Tracer Types

OBI uses multiple tracer types to cover different instrumentation scenarios:

#### 1. Generic Tracer (`bpf/generictracer/`)

Kernel-level tracing using kprobes on system calls:

```c
// File: k_tracer.c

// Accept syscall - track incoming connections
SEC("kprobe/security_socket_accept")
int BPF_KPROBE(obi_kprobe_security_socket_accept, struct socket *sock)

SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(obi_kretprobe_sys_accept4, s32 fd)

// Connect syscall - track outgoing connections
SEC("kprobe/sys_connect")
int BPF_KPROBE(obi_kprobe_sys_connect)

SEC("kprobe/tcp_connect")
int BPF_KPROBE(obi_kprobe_tcp_connect, struct sock *sk)

// Send/receive - protocol detection and tracing
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(obi_kprobe_tcp_sendmsg, struct sock *sk)

SEC("kprobe/tcp_recvmsg")
int BPF_KRETPROBE(obi_kretprobe_tcp_recvmsg)
```

**Protocols handled:**
- HTTP/1.x, HTTP/2, gRPC
- MySQL, PostgreSQL
- Redis, Kafka, MongoDB, MQTT
- Generic SQL (heuristic detection)

#### 2. Go Tracer (`bpf/gotracer/`)

User-space probes (uprobes) for Go-specific instrumentation:

```c
// File: go_nethttp.c

// net/http.(*ServeMux).ServeHTTP
SEC("uprobe/ServeHTTP")
int obi_uprobe_ServeHTTP(struct pt_regs *ctx)

// net/http.(*Transport).RoundTrip
SEC("uprobe/RoundTrip")
int obi_uprobe_RoundTrip(struct pt_regs *ctx)

// File: go_grpc.c
SEC("uprobe/grpc_server_handleStream")
int obi_uprobe_grpc_server_handleStream(struct pt_regs *ctx)

// File: go_sql.c
SEC("uprobe/database_sql_query")
int obi_uprobe_database_sql_query(struct pt_regs *ctx)
```

**Why Go-specific uprobes?**

Go's runtime differs significantly from C-based runtimes:
- Goroutine-based concurrency (not thread-based)
- Non-standard ABI (arguments in registers/stack differ by version)
- Custom memory allocator
- Interfaces with dynamic dispatch

The Go tracer extracts offsets from DWARF debug info or uses pre-computed offset tables.

#### 3. TC Tracer (`bpf/tctracer/`)

Traffic Control (TC) programs for network-level context propagation:

```c
// File: tctracer.c

SEC("classifier/tc_egress")
int obi_tc_egress(struct __sk_buff *skb)

SEC("classifier/tc_ingress")
int obi_tc_ingress(struct __sk_buff *skb)
```

Injects trace context into IP options (IPv4) or Destination Options (IPv6).

#### 4. TP Injector (`bpf/tpinjector/`)

Socket-level context propagation via sockmap and sk_msg programs:

- Injects `Traceparent:` HTTP header
- Injects TCP options (kind 25)
- Handles BPF_SOCK_OPS for connection tracking

### Protocol Support

| Protocol | Detection | Tracer | Notes |
|----------|-----------|--------|-------|
| HTTP/1.x | Keyword matching | Generic/Go | `GET`, `POST`, `HTTP/1.` |
| HTTP/2 | Preface matching | Generic/Go | `PRI * HTTP/2.0\r\n\r\nSM` |
| gRPC | HTTP/2 + content-type | Generic/Go | Via HTTP/2 frame parsing |
| MySQL | Packet structure | Generic | Command packet detection |
| PostgreSQL | Message format | Generic | Startup/query messages |
| Redis | RESP protocol | Generic | `*n\r\n$...\r\n` format |
| Kafka | API keys | Generic | Request header parsing |
| MongoDB | Wire protocol | Generic | OpCode detection |
| MQTT | Fixed header | Generic | CONNECT, PUBLISH, etc. |

### Probe Attachment

The `pkg/ebpf/instrumenter.go` manages probe attachment:

```go
type instrumenter struct {
    offsets     *goexec.Offsets    // Go struct member offsets
    exe         *link.Executable   // Target ELF
    closables   []io.Closer        // Cleanup handles
    modules     map[uint64]struct{} // Loaded modules
    metrics     imetrics.Reporter
    processName string
}

// Attach uprobes
func (i *instrumenter) goprobes(p Tracer) error {
    goProbes := p.GoProbes()
    i.gatherGoOffsets(goProbes)
    closers, err := i.instrumentProbes(i.exe, goProbes)
    // ...
}

// Attach kprobes
func (i *instrumenter) kprobes(p KprobesTracer) error {
    for kfunc, kprobes := range p.KProbes() {
        err := i.kprobe(kfunc, kprobes)
        // ...
    }
}
```

---

## Process Discovery

### Discovery Pipeline (`pkg/appolly/discover/`)

```go
// finder.go
type ProcessFinder struct {
    cfg              *obi.Config
    ctxInfo          *global.ContextInfo
    tracesInput      *msg.Queue[[]request.Span]
    ebpfEventContext *ebpfcommon.EBPFEventContext
}

func (pf *ProcessFinder) Start(ctx context.Context) (<-chan Event[*ebpf.Instrumentable], error) {
    // Pipeline stages:
    // 1. ProcessWatcher - monitors /proc for new processes
    // 2. WatcherKubeEnricher - adds Kubernetes metadata
    // 3. CriteriaMatcher - filters by configured criteria
    // 4. ExecTyper - determines executable type (Go, generic, etc.)
    // 5. ContainerDBUpdater - updates container metadata
    // 6. TraceAttacher - attaches eBPF programs
}
```

### Process Watching

Two modes:

1. **Polling** (`watcher_proc_linux.go`): Periodic `/proc` scanning
2. **Inotify** (`watcher_proc.go`): Event-based using inotify watches on `/proc`

### Executable Type Detection (`typer.go`)

```go
type Instrumentable struct {
    Type           InstrumentableType  // Go, Generic, NodeJS, etc.
    FileInfo       *exec.FileInfo
    ChildPids      []uint32            // Container child processes
    Offsets        *goexec.Offsets     // Go struct offsets (if Go)
    InstrumentedLibs  map[string]struct{}  // SSL libs, etc.
}

type InstrumentableType uint8

const (
    InstrumentableGo       // Go binary (has Go runtime symbols)
    InstrumentableGeneric  // Generic ELF (C, Rust, etc.)
    InstrumentableNodeJS   // Node.js process
    InstrumentableJava     // JVM process
    InstrumentableRuby     // Ruby process
)
```

### Matching Criteria (`pkg/appolly/services/`)

```go
type DiscoveryConfig struct {
    // Glob-based executable matching
    Instrument GlobDefinitionCriteria
    
    // Regex-based service exclusion
    ExcludeServices RegexDefinitionCriteria
    
    // Default exclusions (system namespaces, observability tools)
    DefaultExcludeServices RegexDefinitionCriteria
    
    // Minimum process age before instrumentation
    MinProcessAge time.Duration
}
```

---

## Context Propagation

OBI supports distributed tracing context propagation through multiple mechanisms:

### Configuration

```yaml
ebpf:
  context_propagation: "headers,tcp"  # Options: headers, tcp, ip, all, disabled
```

### Propagation Layers

1. **HTTP Headers (L7)**: `Traceparent:` header injection
2. **TCP Options (L4)**: Custom TCP option (kind 25)
3. **IP Options (L3)**: IPv4/IPv6 Destination Options

### Execution Flow

```
                              Egress Flow
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────┐│
│   │   uprobes   │───▶│   sk_msg    │───▶│   kprobes   │───▶│    TC    ││
│   │ (Go/SSL)    │    │ (tpinjector)│    │(tcp_sendmsg)│    │ (egress) ││
│   └─────────────┘    └─────────────┘    └─────────────┘    └──────────┘│
│         │                  │                  │                  │     │
│         ▼                  ▼                  ▼                  ▼     │
│   [Create trace]    [HTTP headers]    [Protocol detect]  [IP options] │
│   [Set valid=1]     [TCP options]     [Reuse if set]     [If needed]  │
│                     [Set written=1]                                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

                              Ingress Flow
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   ┌──────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐│
│   │    TC    │───▶│   sk_msg    │───▶│   kprobes   │───▶│   uprobes   ││
│   │(ingress) │    │ (tpinjector)│    │(tcp_recvmsg)│    │ (Go/SSL)    ││
│   └──────────┘    └─────────────┘    └─────────────┘    └─────────────┘│
│        │                │                  │                  │        │
│        ▼                ▼                  ▼                  ▼        │
│   [Extract IP]   [Extract TCP]      [Extract HTTP]    [Application]   │
│   [Store map]    [Store map]        [Store map]       [Last wins]     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Mutual Exclusion

The `written` flag in `outgoing_trace_map` ensures only one injection method is used per request:

```c
typedef struct tp_info_pid {
    tp_info_t tp;        // Trace context
    u32 pid;             // Process ID
    u8 req_type;         // EVENT_HTTP_CLIENT, etc.
    u8 valid;            // Set by uprobes
    u8 written;          // Set when injection complete
} tp_info_pid_t;
```

---

## Exporters

### OpenTelemetry Exporter (`pkg/export/otel/`)

Supports both traces and metrics export via OTLP:

```go
// traces.go
type tracesOTELReceiver struct {
    cfg                otelcfg.TracesConfig
    is                 instrumentations.InstrumentationSelection
    spanMetricsEnabled bool
    attributeCache     *expirable2.LRU[svc.UID, []attribute.KeyValue]
}

// metrics.go
type MetricsReporter struct {
    cfg              *otelcfg.MetricsConfig
    exporter         sdkmetric.Exporter
    reporters        otelcfg.ReporterPool[*svc.Attrs, *Metrics]
}
```

#### Configuration

```yaml
otel_traces_export:
  endpoint: "localhost:4317"
  protocol: "grpc"          # grpc, http/protobuf
  instrumentations:
    - http
    - grpc
    - sql

otel_metrics_export:
  endpoint: "localhost:4317"
  interval_ms: 60000
  histogram_aggregation: "explicit_bucket_histogram"
  instrumentations:
    - all
```

#### Metrics Emitted

| Metric | Type | Description |
|--------|------|-------------|
| `http.server.request.duration` | Histogram | Server-side HTTP latency |
| `http.client.request.duration` | Histogram | Client-side HTTP latency |
| `rpc.server.duration` | Histogram | gRPC server latency |
| `rpc.client.duration` | Histogram | gRPC client latency |
| `db.client.operation.duration` | Histogram | Database query latency |
| `messaging.publish.duration` | Histogram | Message publish latency |
| `messaging.process.duration` | Histogram | Message processing latency |

### Prometheus Exporter (`pkg/export/prom/`)

Exposes metrics via HTTP endpoint:

```go
type PrometheusEndpoint struct {
    cfg                *PrometheusConfig
    httpRequestDuration *Expirer[prometheus.Observer]
    httpClientDuration  *Expirer[prometheus.Observer]
    grpcServerDuration  *Expirer[prometheus.Observer]
}
```

#### Configuration

```yaml
prometheus_export:
  port: 8080
  path: "/metrics"
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
  ttl: 5m                   # Metric expiration for unused labels
```

#### Metric Expiration

The `Expirer` wrapper automatically removes metrics that haven't been updated within the TTL:

```go
type Expirer[T prometheus.Metric] struct {
    entries *expire.ExpiryMap[*MetricEntry[T]]
    wrapped *prometheus.MetricVec
}
```

---

## Kubernetes Integration

### Metadata Provider (`pkg/kube/`)

```go
type MetadataProvider struct {
    metadata     *Store           // Pod/ReplicaSet/Deployment cache
    informer     meta.Notifier    // K8s informer events
    clusterName  string           // Auto-detected or configured
    cfg          *MetadataConfig
}

type MetadataConfig struct {
    Enable              kubeflags.EnableFlag  // true, false, autodetect
    KubeConfigPath      string                // Path to kubeconfig
    SyncTimeout         time.Duration         // Informer sync timeout
    ResyncPeriod        time.Duration         // Periodic resync
    ResourceLabels      ResourceLabels        // Label -> attribute mapping
    MetaCacheAddr       string                // External cache address
    RestrictLocalNode   bool                  // Only local node pods
}
```

### Auto-detection

```go
func (mp *MetadataProvider) IsKubeEnabled() bool {
    switch mp.cfg.Enable {
    case kubeflags.EnabledTrue:
        return true
    case kubeflags.EnabledAutodetect:
        // Try loading kubeconfig
        _, err := loadKubeConfig(mp.cfg.KubeConfigPath)
        return err == nil
    default:
        return false
    }
}
```

### Default Exclusions

System namespaces are excluded by default:

```go
var k8sDefaultNamespacesGlob = services.NewGlob(
    "{kube-system,kube-node-lease,local-path-storage,grafana-alloy," +
    "cert-manager,monitoring,gke-*,gatekeeper-system}")
```

### Resource Labels

Map Kubernetes labels to OpenTelemetry attributes:

```yaml
attributes:
  kubernetes:
    resource_labels:
      service.name:
        - "app.kubernetes.io/name"
        - "app"
      service.namespace:
        - "app.kubernetes.io/part-of"
```

---

## Configuration System

### Configuration Loading (`pkg/obi/config.go`)

Configuration is loaded from multiple sources with priority:

1. Environment variables (`OTEL_EBPF_*`, `OTEL_*`)
2. YAML configuration file
3. Default values

```go
func LoadConfig(reader io.Reader) (*Config, error) {
    cfg := DefaultConfig
    
    // 1. Load from YAML if provided
    if reader != nil {
        yaml.NewDecoder(reader).Decode(&cfg)
    }
    
    // 2. Override with environment variables
    env.Parse(&cfg)
    
    // 3. Validate
    cfg.Validate()
    
    return &cfg, nil
}
```

### Key Configuration Sections

```go
type Config struct {
    // eBPF tracer settings
    EBPF config.EBPFTracer
    
    // Network observability
    NetworkFlows NetworkConfig
    
    // Attribute filtering
    Filters filter.AttributesConfig
    
    // OpenTelemetry export
    OTELMetrics otelcfg.MetricsConfig
    Traces      otelcfg.TracesConfig
    
    // Prometheus export
    Prometheus prom.PrometheusConfig
    
    // Process discovery
    Discovery services.DiscoveryConfig
    
    // Data transformation
    Routes       *transform.RoutesConfig
    NameResolver *transform.NameResolverConfig
    Attributes   Attributes
}
```

### eBPF Configuration

```go
type EBPFTracer struct {
    BpfDebug             bool          // Enable BPF debug output
    BatchLength          int           // Traces per batch
    BatchTimeout         time.Duration // Batch timeout
    HTTPRequestTimeout   time.Duration // Request timeout
    TrackRequestHeaders  bool          // Parse Traceparent header
    ContextPropagation   ContextPropagationMode
    TCBackend            TCBackend     // tc, tcx, auto
    HeuristicSQLDetect   bool          // SQL auto-detection
    InstrumentGPU        bool          // CUDA instrumentation
}
```

---

## Build System

### Makefile Targets

```makefile
# Development workflow
make docker-generate    # Generate eBPF bindings in Docker
make compile            # Build Go binary
make dev                # docker-generate + compile

# Quality
make fmt                # Format Go code
make lint               # Run golangci-lint
make clang-tidy         # Lint C code
make clang-format       # Format C code

# Testing
make test               # Unit tests
make integration-test   # Integration tests
make oats-test          # OpenTelemetry Agent Test Suite
```

### eBPF Code Generation

The `bpf2go` tool from cilium/ebpf generates Go bindings:

```makefile
$(TOOLS)/bpf2go: PACKAGE=github.com/cilium/ebpf/cmd/bpf2go

# In pkg/internal/ebpf/generictracer/generictracer.go:
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/generictracer/generictracer.c
```

### Docker Build

```dockerfile
# Multi-stage build
FROM ghcr.io/open-telemetry/obi-generator AS builder

# Copy source and generate eBPF bindings
COPY bpf/ bpf/
RUN /generate.sh && make compile

# Final image (scratch-based for minimal footprint)
FROM scratch
COPY --from=builder /src/bin/ebpf-instrument .
```

---

## Testing Strategy

### Unit Tests

Located alongside source files (`*_test.go`):

```bash
make test
```

### Integration Tests

Located in `internal/test/integration/`:

```bash
make integration-test      # Standard integration tests
make integration-test-k8s  # Kubernetes-specific tests
```

Uses:
- `testcontainers-go` for containerized test environments
- `e2e-framework` for Kubernetes tests

### OpenTelemetry Agent Test Suite (OATS)

Validates OBI output against expected telemetry:

```bash
make oats-test
```

---

## Performance Considerations

### eBPF Overhead

1. **Ring Buffer sizing**: Configured via `wakeup_len`—higher values batch more events but add latency
2. **Map sizing**: LRU caches have fixed sizes (configurable via `*_cache_size` options)
3. **PID filtering**: Bloom filter-like structure minimizes map lookups

```c
// Efficient PID lookup using bit segments
const maxConcurrentPids = 3001
const primeHash = 192053

func pidSegmentBit(k uint64) (uint32, uint32) {
    h := uint32(k % primeHash)
    segment := h / 64
    bit := h & 63
    return segment, bit
}
```

### User-Space Overhead

1. **Batch processing**: Spans are batched before forwarding to reduce allocations
2. **LRU caches**: Attribute caches avoid repeated computation
3. **Metric expiration**: TTL-based cleanup prevents unbounded memory growth

### Configuration Tuning

```yaml
ebpf:
  batch_length: 100        # Spans per batch
  batch_timeout: 1s        # Max batch wait
  wakeup_len: 0            # 0 = wake on every event

otel_metrics_export:
  interval_ms: 60000       # 1-minute aggregation
  reporters_cache_len: 256 # Per-service reporter cache
  ttl: 5m                  # Metric series TTL
```

---

## Security Model

### Required Capabilities

OBI requires elevated privileges for eBPF operations:

| Capability | Purpose |
|------------|---------|
| `CAP_SYS_ADMIN` or `CAP_BPF` | Load eBPF programs |
| `CAP_NET_ADMIN` | TC program attachment |
| `CAP_SYS_PTRACE` | Read process memory (uprobes) |
| `CAP_PERFMON` | Performance monitoring events |
| `CAP_SYS_RESOURCE` | Increase rlimits for maps |

### Enforcement

```go
func CheckOSCapabilities(cfg *Config) error {
    // Check for required capabilities
    // Return error if not present and EnforceSysCaps=true
}
```

### Deployment Modes

1. **Privileged container**: Full access, simplest setup
2. **Specific capabilities**: Minimal required caps
3. **Host network**: Required for TC/network instrumentation

---

## Appendix: Key Interfaces

### Tracer Interface

```go
type Tracer interface {
    Load() (*ebpf.CollectionSpec, error)
    Constants() map[string]any
    BpfObjects() any
    GoProbes() map[string][]*ebpfcommon.ProbeDesc
    AddCloser(...io.Closer)
    Run(ctx context.Context, eventContext *ebpfcommon.EBPFEventContext, out *msg.Queue[[]request.Span])
}

type KprobesTracer interface {
    Tracer
    KProbes() map[string]ebpfcommon.ProbeDesc
}
```

### Event Context

```go
type EBPFEventContext struct {
    EBPFMaps map[string]*ebpf.Map  // Shared maps
    MapsLock sync.Mutex
}
```

### Service Filter

```go
type ServiceFilter interface {
    CurrentPIDs(pidType PIDType) map[uint32]map[uint32]struct{}  // namespace -> PIDs
    AllowPID(pid uint32, ns uint32, pidType PIDType)
    BlockPID(pid uint32, ns uint32, pidType PIDType)
}
```

---

## References

- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/)
- [cilium/ebpf Go Library](https://github.com/cilium/ebpf)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [OBI Pipeline Map](./devdocs/pipeline-map.md)
- [Context Propagation Details](./devdocs/context-propagation.md)
