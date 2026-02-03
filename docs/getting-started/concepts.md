# Core Concepts

Understanding Telegen's architecture and terminology.

## Deployment Modes

Telegen operates in two distinct modes:

### Agent Mode

**Agent mode** is for local host/container observability. Deploy directly on each node you want to monitor.

```{mermaid}
graph LR
    A[Host/Container] --> B[Telegen Agent]
    B --> C[eBPF Instrumentation]
    B --> D[Process Discovery]
    B --> E[Log Collection]
    C --> F[OTLP Export]
    D --> F
    E --> F
    F --> G[OTel Collector]
```

**Capabilities:**
- eBPF-based kernel instrumentation
- Process discovery and runtime detection
- Continuous profiling (CPU, memory, mutex)
- GPU/CUDA monitoring
- Local log collection
- Container and Kubernetes enrichment

**Deployment:** DaemonSet (Kubernetes), systemd service (bare metal)

### Collector Mode

**Collector mode** is for remote device monitoring. Deploy on a separate node to collect telemetry from remote systems.

```{mermaid}
graph LR
    A[Network Devices] -->|SNMP| B[Telegen Collector]
    C[Storage Arrays] -->|REST API| B
    D[Cloud APIs] -->|HTTPS| B
    B --> E[OTLP Export]
    E --> F[OTel Collector]
```

**Capabilities:**
- SNMP polling and trap receiver (v1/v2c/v3)
- Storage array metrics (Dell, HPE, Pure, NetApp)
- Cloud/infrastructure API polling
- Database metrics receivers

**Deployment:** Deployment/StatefulSet (Kubernetes), systemd service (bare metal)

---

## Signal Types

Telegen produces four signal types, all in OpenTelemetry format:

| Signal | Description | Use Case |
|--------|-------------|----------|
| **Metrics** | Time-series numerical data | Dashboards, alerting |
| **Traces** | Distributed request flows | Latency analysis, debugging |
| **Logs** | Structured event records | Debugging, auditing |
| **Profiles** | CPU/memory stack samples | Performance optimization |

### Signal Correlation

All signals are automatically correlated:

- **Logs** include `trace_id` and `span_id`
- **Metrics** include exemplars linking to trace samples
- **Profiles** are correlated with active spans

---

## Auto-Discovery

Telegen automatically detects and enriches telemetry with:

### Cloud Detection

| Provider | Detection Method |
|----------|------------------|
| AWS | IMDSv2 (169.254.169.254) |
| GCP | Metadata server |
| Azure | IMDS |
| Alibaba | Metadata service |
| Oracle | IMDS |
| DigitalOcean | Metadata service |
| OpenStack | Keystone + env vars |
| VMware | Hypervisor detection |

### Runtime Detection

| Runtime | Detection Method |
|---------|------------------|
| Go | Binary symbols, runtime headers |
| Java | JVM process, JFR |
| Python | Interpreter process |
| Node.js | V8 engine detection |
| .NET | CoreCLR detection |

### Database Detection

| Database | Detection Method |
|----------|------------------|
| PostgreSQL | Port 5432, protocol detection |
| MySQL | Port 3306, protocol detection |
| Redis | Port 6379, RESP protocol |
| MongoDB | Port 27017, wire protocol |
| Kafka | Port 9092, broker detection |

---

## eBPF Programs

Telegen uses eBPF (Extended Berkeley Packet Filter) for kernel-level instrumentation:

```{mermaid}
graph TB
    subgraph Kernel
        A[eBPF Programs]
        B[kprobes/uprobes]
        C[Tracepoints]
        D[XDP]
    end
    subgraph "User Space"
        E[Telegen Agent]
        F[Ring Buffer]
    end
    A --> B
    A --> C
    A --> D
    B --> F
    C --> F
    D --> F
    F --> E
```

### eBPF Program Types Used

| Type | Purpose |
|------|---------|
| **kprobe** | Kernel function tracing |
| **uprobe** | User-space function tracing |
| **tracepoint** | Kernel tracepoint hooks |
| **perf_event** | CPU profiling |
| **XDP** | High-performance packet processing |
| **tc** | Traffic control for egress |

---

## Resource Attributes

Telegen follows OpenTelemetry semantic conventions for resource attributes:

```yaml
# Automatically added to all signals
resource:
  service.name: "my-service"
  service.namespace: "production"
  host.name: "node-1"
  host.arch: "amd64"
  os.type: "linux"
  cloud.provider: "aws"
  cloud.region: "us-east-1"
  k8s.namespace.name: "default"
  k8s.pod.name: "my-pod-abc123"
  k8s.node.name: "node-1"
```

---

## Next Steps

- {doc}`architecture` - Deep dive into architecture
- {doc}`../configuration/index` - Configuration options
