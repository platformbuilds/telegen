# Distributed Tracing

Telegen provides zero-configuration distributed tracing using eBPF.

## Overview

Telegen automatically traces:

- **HTTP/HTTPS** - All HTTP/1.1 and HTTP/2 traffic
- **gRPC** - All gRPC calls
- **Database queries** - PostgreSQL, MySQL, MongoDB, Redis
- **Message queues** - Kafka, RabbitMQ
- **Internal function calls** - For supported runtimes

No code changes or SDK integration required.

---

## How It Works

```{mermaid}
flowchart TB
    subgraph Kernel["Linux Kernel"]
        K["eBPF Programs"]
    end
    
    subgraph App["Application"]
        A["HTTP Handler"]
        B["gRPC Client"]
        C["DB Query"]
    end
    
    subgraph Telegen["Telegen Agent"]
        T["Trace Correlator"]
        E["OTLP Exporter"]
    end
    
    K -->|"Intercept"| A
    K -->|"Intercept"| B
    K -->|"Intercept"| C
    A --> K
    B --> K
    C --> K
    K --> T
    T --> E
    E -->|"OTLP"| OC["OTel Collector"]
```

### Trace Context Propagation

Telegen automatically extracts and propagates trace context:

1. **Incoming requests** - Extract `traceparent`/`tracestate` from headers
2. **Outgoing requests** - Inject trace context into outgoing calls
3. **Cross-service correlation** - Link spans across service boundaries

---

## Protocol Support

### HTTP Tracing

```yaml
# Automatically captured for every HTTP request
span:
  name: "GET /api/users/{id}"
  kind: SERVER
  attributes:
    http.method: GET
    http.url: "https://api.example.com/api/users/123"
    http.route: "/api/users/{id}"
    http.status_code: 200
    http.request_content_length: 0
    http.response_content_length: 1234
    http.user_agent: "curl/7.88.0"
    net.peer.ip: "10.0.1.50"
    net.peer.port: 45678
    net.host.ip: "10.0.1.100"
    net.host.port: 8080
```

### gRPC Tracing

```yaml
span:
  name: "/users.UserService/GetUser"
  kind: SERVER
  attributes:
    rpc.system: grpc
    rpc.service: users.UserService
    rpc.method: GetUser
    rpc.grpc.status_code: 0
    net.peer.ip: "10.0.1.50"
    net.peer.port: 45678
```

### Database Tracing

```yaml
span:
  name: "SELECT users"
  kind: CLIENT
  attributes:
    db.system: postgresql
    db.name: mydb
    db.user: appuser
    db.statement: "SELECT * FROM users WHERE id = $1"
    db.operation: SELECT
    db.sql.table: users
    net.peer.ip: "10.0.2.100"
    net.peer.port: 5432
```

### Message Queue Tracing

```yaml
# Kafka produce
span:
  name: "orders send"
  kind: PRODUCER
  attributes:
    messaging.system: kafka
    messaging.destination.name: orders
    messaging.kafka.partition: 3
    messaging.kafka.message.offset: 12345
    messaging.message.payload_size_bytes: 256

# Kafka consume
span:
  name: "orders receive"
  kind: CONSUMER
  attributes:
    messaging.system: kafka
    messaging.destination.name: orders
    messaging.kafka.consumer.group: order-processor
    messaging.kafka.partition: 3
    messaging.kafka.message.offset: 12345
```

---

## Runtime-Specific Tracing

### Go Applications

Telegen traces Go applications at the runtime level:

- **Goroutine tracking** - Track execution across goroutines
- **HTTP handlers** - `net/http`, Gin, Echo, Chi, Fiber
- **gRPC** - All gRPC calls
- **Database drivers** - `database/sql`, pgx, go-redis

### Java Applications

Integration with JFR (Java Flight Recorder):

- **Method tracing** - Hot methods and stack traces
- **GC events** - Garbage collection correlation
- **Lock contention** - Synchronized blocks and locks
- **Thread events** - Thread creation, blocking

### Python Applications

- **ASGI/WSGI** - FastAPI, Django, Flask
- **asyncio** - Async operation tracking
- **Database** - psycopg2, SQLAlchemy, pymongo

### Node.js Applications

- **HTTP** - Express, Fastify, Koa
- **Async hooks** - Promise and callback tracking
- **Database** - pg, mysql2, mongodb, redis

---

## Trace Correlation

### Automatic Signal Linking

Telegen automatically correlates:

```{mermaid}
flowchart LR
    subgraph Request["Single Request"]
        T["Trace\n(span_id: abc123)"]
        M["Metrics\n(labeled: span_id=abc123)"]
        L["Logs\n(trace_id, span_id)"]
        P["Profile\n(span_id: abc123)"]
    end
    
    T --- M
    T --- L
    T --- P
```

### Log Correlation

Logs are automatically enriched with trace context:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "message": "User created successfully",
  "trace_id": "a1b2c3d4e5f6789012345678",
  "span_id": "abc123def456",
  "service.name": "user-service",
  "k8s.pod.name": "user-service-xyz"
}
```

### Metric Exemplars

Metrics include exemplars linking to traces:

```yaml
http_server_duration:
  type: histogram
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
  exemplars:
    - value: 0.045
      trace_id: "a1b2c3d4e5f6789012345678"
      span_id: "abc123def456"
```

---

## Configuration

### Basic Configuration

```yaml
otlp:
  endpoint: "otel-collector:4317"
  traces:
    enabled: true
    sample_rate: 1.0  # 100% sampling
```

### Sampling

```yaml
otlp:
  traces:
    enabled: true
    # Sample 10% of traces
    sample_rate: 0.1
    
    # Head-based sampling (default)
    sampler: parent_based_traceidratio
```

### Network Filtering

```yaml
agent:
  ebpf:
    network:
      enabled: true
      http: true
      grpc: true
      
      # Exclude noisy endpoints
      exclude_paths:
        - "/health"
        - "/healthz"
        - "/ready"
        - "/metrics"
      
      # Exclude by port
      exclude_ports:
        - 22    # SSH
        - 2379  # etcd
```

### Database Query Settings

```yaml
agent:
  database:
    # Capture full query text
    capture_queries: true
    
    # Sanitize sensitive data
    sanitize_queries: true
    
    # Max query length
    max_query_length: 1024
    
    # Capture query parameters
    capture_parameters: false  # Privacy consideration
```

---

## Span Enrichment

### Automatic Enrichment

All spans are automatically enriched with:

| Attribute | Source |
|-----------|--------|
| `service.name` | Discovery or config |
| `service.version` | Binary analysis |
| `host.name` | System |
| `k8s.pod.name` | Kubernetes |
| `cloud.region` | Cloud metadata |
| `process.pid` | System |

### Custom Attributes

Add custom attributes via environment variables:

```yaml
# Kubernetes deployment
env:
  - name: OTEL_RESOURCE_ATTRIBUTES
    value: "team=platform,cost_center=engineering"
```

---

## Performance Impact

Telegen is designed for minimal overhead:

| Metric | Overhead |
|--------|----------|
| **Latency** | < 100μs per request |
| **CPU** | < 1% additional |
| **Memory** | ~50MB for trace buffers |
| **Network** | Compressed OTLP batches |

### Optimizations

- **Ring buffers** - Efficient kernel-to-userspace transfer
- **Batching** - Spans batched before export
- **Compression** - gzip compression by default
- **Sampling** - Configurable head-based sampling

---

## Troubleshooting

### Missing Traces

1. **Check eBPF status**:
   ```bash
   # Verify eBPF programs loaded
   bpftool prog list | grep telegen
   ```

2. **Check OTLP connectivity**:
   ```bash
   # Verify endpoint is reachable
   curl -v http://otel-collector:4317
   ```

3. **Check sampling rate**:
   ```yaml
   otlp:
     traces:
       sample_rate: 1.0  # Ensure 100% for debugging
   ```

### Missing Span Correlation

1. **Verify trace context propagation**:
   - Check incoming requests have `traceparent` header
   - Verify W3C Trace Context format

2. **Check time synchronization**:
   - Ensure NTP is configured
   - Spans may appear out of order with clock drift

---

## Next Steps

- {doc}`continuous-profiling` - Link profiles to traces
- {doc}`database-tracing` - Deep database tracing
- {doc}`../configuration/agent-mode` - Trace configuration options
