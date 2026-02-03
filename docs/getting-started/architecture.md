# Architecture Overview

Deep dive into Telegen's internal architecture.

## High-Level Architecture

```{mermaid}
graph TB
    subgraph "Telegen Agent"
        AD[Auto-Discovery Engine]
        ET[eBPF Tracers]
        AE[Analytics Engine]
        
        AD --> SC[Signal Correlation Layer]
        ET --> SC
        AE --> SC
        
        SC --> EP[OTLP Export Pipeline]
    end
    
    EP --> OC[OTel Collector]
```

### Component Overview

| Component | Description |
|-----------|-------------|
| **Auto-Discovery Engine** | Detects OS, cloud, K8s, databases, runtimes |
| **eBPF Tracers** | Kernel-level instrumentation for traces, metrics |
| **Analytics Engine** | Topology discovery, signal correlation |
| **Signal Correlation Layer** | Links traces, metrics, logs, profiles |
| **OTLP Export Pipeline** | Exports all signals via OTLP |

---

## Data Flow

```{mermaid}
sequenceDiagram
    participant K as Kernel
    participant E as eBPF Programs
    participant R as Ring Buffer
    participant A as Agent
    participant C as Correlator
    participant O as OTLP Exporter
    participant B as Backend

    K->>E: System events
    E->>R: Write events
    R->>A: Read events
    A->>C: Enrich & correlate
    C->>O: Batch signals
    O->>B: Export OTLP
```

---

## eBPF Tracer Architecture

### Tracer Types

```{mermaid}
graph LR
    subgraph "Network Tracers"
        HTTP[HTTP/gRPC Tracer]
        DNS[DNS Tracer]
        TCP[TCP Metrics]
        XDP[XDP Packet Tracer]
    end
    
    subgraph "Application Tracers"
        DB[Database Tracer]
        MQ[Message Queue Tracer]
        GO[Go Tracer]
    end
    
    subgraph "System Tracers"
        PROF[CPU Profiler]
        SEC[Security Monitor]
        FILE[File I/O Tracer]
    end
```

### eBPF Maps

| Map Type | Purpose | Size |
|----------|---------|------|
| **Ring Buffer** | Event streaming to user space | 16 MB |
| **LRU Hash** | Flow tracking, connection state | 1M entries |
| **Per-CPU Array** | Statistics, counters | Per-CPU |
| **Stack Trace** | Profiling stacks | 64K entries |

---

## Pipeline Architecture

### Signal Processing Pipeline

```{mermaid}
graph LR
    I[Ingestion] --> P[Processing]
    P --> E[Enrichment]
    E --> B[Batching]
    B --> X[Export]
    
    subgraph Processing
        P1[Filtering]
        P2[Sampling]
        P3[Aggregation]
    end
    
    subgraph Enrichment
        E1[Cloud Metadata]
        E2[K8s Labels]
        E3[Process Info]
    end
```

### Export Pipeline

All signals are exported via OTLP:

```yaml
# Export configuration
otlp:
  endpoint: "otel-collector:4317"
  protocol: "grpc"  # or "http"
  compression: "gzip"
  
  # Per-signal configuration
  traces:
    enabled: true
    batch_size: 512
  metrics:
    enabled: true
    batch_size: 1000
  logs:
    enabled: true
    batch_size: 1000
  profiles:
    enabled: true
    batch_size: 100
```

---

## Memory Architecture

### Buffer Management

```{mermaid}
graph TB
    subgraph "Kernel Space"
        RB[Ring Buffer 16MB]
        PB[Perf Buffer 8KB/CPU]
    end
    
    subgraph "User Space"
        EQ[Event Queue]
        TQ[Trace Queue 256MB]
        MQ[Metrics Queue 128MB]
        LQ[Logs Queue 256MB]
    end
    
    RB --> EQ
    PB --> EQ
    EQ --> TQ
    EQ --> MQ
    EQ --> LQ
```

### Memory Limits

| Component | Default | Configurable |
|-----------|---------|--------------|
| Ring Buffer | 16 MB | Yes |
| Trace Queue | 256 MB | Yes |
| Metrics Queue | 128 MB | Yes |
| Logs Queue | 256 MB | Yes |
| Stack Maps | 8 MB | No |

---

## Security Model

### Required Capabilities

| Capability | Purpose |
|------------|---------|
| `SYS_ADMIN` | eBPF program loading |
| `SYS_PTRACE` | Process inspection |
| `BPF` | BPF operations (kernel 5.8+) |
| `PERFMON` | Performance monitoring (kernel 5.8+) |
| `NET_ADMIN` | Network namespace access |
| `DAC_READ_SEARCH` | File system traversal |

### Privilege Separation

```{mermaid}
graph TB
    subgraph "Privileged (root)"
        BPF[BPF Program Loader]
        MAPS[Map Manager]
    end
    
    subgraph "Unprivileged"
        PROC[Event Processor]
        EXPORT[Exporter]
        API[HTTP API]
    end
    
    BPF --> MAPS
    MAPS --> PROC
    PROC --> EXPORT
    PROC --> API
```

---

## High Availability

### DaemonSet Mode

- Runs on every node
- Node-local data collection
- No single point of failure
- Automatic pod recreation

### Collector Mode (HA)

```{mermaid}
graph TB
    subgraph "Collector Pods (replicas=2)"
        C1[Collector 1]
        C2[Collector 2]
    end
    
    subgraph "Target Sharding"
        T1[Targets 1-50]
        T2[Targets 51-100]
    end
    
    T1 --> C1
    T2 --> C2
    
    C1 --> OC[OTel Collector]
    C2 --> OC
```

---

## Performance Characteristics

### Overhead

| Metric | Typical | Maximum |
|--------|---------|---------|
| CPU | <1% | 2% |
| Memory | 256 MB | 1 GB |
| Network | <1 MB/s | 10 MB/s |

### Throughput

| Signal | Events/sec | Notes |
|--------|------------|-------|
| Traces | 10,000 | With sampling |
| Metrics | 100,000 | Aggregated |
| Logs | 50,000 | With filtering |
| Profiles | 100 | Per second |

---

## Next Steps

- {doc}`../installation/index` - Installation guides
- {doc}`../configuration/index` - Configuration reference
