# Network Observability

Telegen provides deep network observability using eBPF.

## Overview

Network observability includes:

- **DNS tracing** - Query/response correlation
- **TCP metrics** - RTT, retransmits, connection tracking
- **HTTP/gRPC tracing** - Request/response details
- **Flow tracking** - Connection topology
- **XDP packet analysis** - High-performance packet inspection

---

## DNS Tracing

### What's Captured

| Field | Description |
|-------|-------------|
| **Query** | Domain name, type (A, AAAA, CNAME) |
| **Response** | Answer records, response code |
| **Latency** | Query-to-response time |
| **Server** | DNS server address |

### Sample Event

```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "attributes": {
    "dns.question.name": "api.example.com",
    "dns.question.type": "A",
    "dns.response_code": "NOERROR",
    "dns.answers": ["10.0.1.100", "10.0.1.101"],
    "dns.latency_ms": 2.5,
    "net.peer.ip": "10.0.0.2",
    "net.peer.port": 53,
    "process.pid": 12345,
    "k8s.pod.name": "my-app-xyz"
  }
}
```

### Configuration

```yaml
agent:
  network:
    dns:
      enabled: true
      capture_queries: true
      capture_responses: true
      
      # Capture query/response content
      capture_content: true
```

---

## TCP Metrics

### Metrics Collected

| Metric | Description |
|--------|-------------|
| `tcp_rtt_us` | Round-trip time in microseconds |
| `tcp_retransmits` | Packet retransmission count |
| `tcp_connections` | Connection count |
| `tcp_bytes_sent` | Bytes transmitted |
| `tcp_bytes_received` | Bytes received |

### Connection Tracking

```yaml
# Metrics example
tcp_rtt_us{
  src_ip="10.0.1.50",
  dst_ip="10.0.2.100",
  dst_port="5432",
  k8s_src_pod="api-server",
  k8s_dst_service="postgres"
} 1250

tcp_retransmits_total{
  src_ip="10.0.1.50",
  dst_ip="10.0.2.100",
  dst_port="5432"
} 3
```

### Configuration

```yaml
agent:
  network:
    tcp:
      enabled: true
      rtt: true
      retransmits: true
      connection_tracking: true
      
      # Flow sampling (1 in N connections)
      sample_rate: 1  # Capture all
```

---

## HTTP/gRPC Tracing

### HTTP Details

| Field | Description |
|-------|-------------|
| `http.method` | GET, POST, PUT, DELETE, etc. |
| `http.url` | Full request URL |
| `http.route` | Matched route pattern |
| `http.status_code` | Response status |
| `http.request_content_length` | Request body size |
| `http.response_content_length` | Response body size |

### gRPC Details

| Field | Description |
|-------|-------------|
| `rpc.system` | grpc |
| `rpc.service` | Service name |
| `rpc.method` | Method name |
| `rpc.grpc.status_code` | gRPC status code |

### Configuration

```yaml
agent:
  ebpf:
    network:
      enabled: true
      http: true
      grpc: true
      
      # URL/path filtering
      exclude_paths:
        - "/health"
        - "/healthz"
        - "/ready"
        - "/metrics"
        - "/favicon.ico"
      
      # Capture request/response headers
      capture_headers:
        - "content-type"
        - "user-agent"
        - "x-request-id"
```

---

## Service Topology

Telegen automatically builds a service dependency map:

```{mermaid}
flowchart LR
    subgraph External
        LB["Load Balancer"]
    end
    
    subgraph Cluster["Kubernetes Cluster"]
        FE["Frontend"]
        API["API Gateway"]
        US["User Service"]
        OS["Order Service"]
        PG["PostgreSQL"]
        RD["Redis"]
        KF["Kafka"]
    end
    
    LB -->|HTTP| FE
    FE -->|HTTP| API
    API -->|gRPC| US
    API -->|gRPC| OS
    US -->|SQL| PG
    OS -->|SQL| PG
    API -->|TCP| RD
    OS -->|Produce| KF
```

### Topology Data

```yaml
topology:
  nodes:
    - id: "api-gateway"
      type: "service"
      attributes:
        k8s.deployment: "api-gateway"
        k8s.namespace: "default"
    
    - id: "user-service"
      type: "service"
      attributes:
        k8s.deployment: "user-service"
        k8s.namespace: "default"
  
  edges:
    - source: "api-gateway"
      target: "user-service"
      attributes:
        protocol: "grpc"
        requests_per_second: 150
        avg_latency_ms: 12
        error_rate: 0.01
```

---

## XDP Packet Analysis

For high-performance packet inspection at the NIC level:

### Configuration

```yaml
agent:
  network:
    xdp:
      enabled: true
      
      # Sample rate (1 in N packets)
      sample_rate: 1000  # 0.1% of packets
      
      # Interfaces to attach
      interfaces:
        - eth0
        - eth1
      
      # Packet filters
      filters:
        # Only specific ports
        ports:
          - 80
          - 443
          - 8080
        
        # Only specific protocols
        protocols:
          - tcp
          - udp
```

### Use Cases

- **DDoS detection** - High packet rate anomalies
- **Protocol analysis** - Non-HTTP traffic inspection
- **Network debugging** - Low-level packet issues

---

## Network Metrics

### RED Metrics (Rate, Errors, Duration)

```promql
# Request rate by service
sum(rate(http_server_requests_total[5m])) by (service_name)

# Error rate
sum(rate(http_server_requests_total{status_code=~"5.."}[5m])) 
/ sum(rate(http_server_requests_total[5m]))

# Latency percentiles
histogram_quantile(0.99, 
  sum(rate(http_server_duration_bucket[5m])) by (le, service_name)
)
```

### Connection Metrics

```promql
# Active connections by service pair
telegen_tcp_connections{state="established"}

# Connection errors
sum(rate(telegen_tcp_connection_errors_total[5m])) by (error_type)

# Retransmit rate
sum(rate(telegen_tcp_retransmits_total[5m])) 
/ sum(rate(telegen_tcp_segments_total[5m]))
```

### DNS Metrics

```promql
# DNS query rate
sum(rate(telegen_dns_queries_total[5m])) by (domain)

# DNS latency
histogram_quantile(0.95, 
  sum(rate(telegen_dns_latency_bucket[5m])) by (le)
)

# DNS errors
sum(rate(telegen_dns_queries_total{response_code!="NOERROR"}[5m]))
```

---

## Interface Filtering

Control which network interfaces are monitored:

```yaml
agent:
  network:
    # Include specific interfaces
    interfaces:
      - eth0
      - ens5
    
    # Or exclude interfaces
    exclude_interfaces:
      - lo        # Loopback
      - docker0   # Docker bridge
      - veth*     # Container veths
```

---

## Port Filtering

Focus on specific ports:

```yaml
agent:
  ebpf:
    network:
      # Only trace these ports
      include_ports:
        - 80
        - 443
        - 8080
        - 3000
        - 5432
        - 6379
      
      # Or exclude ports
      exclude_ports:
        - 22    # SSH
        - 2379  # etcd
        - 2380  # etcd peer
```

---

## Network Security

### Suspicious Connection Detection

```yaml
agent:
  network:
    security:
      enabled: true
      
      # Detect connections to unusual ports
      suspicious_ports:
        - 4444   # Common reverse shell
        - 31337  # Elite port
      
      # Detect connections to external IPs
      external_connection_alerts: true
      
      # Known bad IP lists
      blocklists:
        - "/etc/telegen/ip-blocklist.txt"
```

### Example Alert

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "WARNING",
  "body": "Suspicious outbound connection to known bad IP",
  "attributes": {
    "network.event_type": "suspicious_connection",
    "net.peer.ip": "198.51.100.50",
    "net.peer.port": 4444,
    "process.pid": 12345,
    "process.executable.path": "/tmp/shell",
    "k8s.pod.name": "compromised-pod"
  }
}
```

---

## Performance Considerations

### Overhead

| Feature | CPU Impact | Memory Impact |
|---------|------------|---------------|
| TCP metrics | ~0.5% | 10MB |
| DNS tracing | ~0.2% | 5MB |
| HTTP tracing | ~1% | 20MB |
| XDP (sampled) | ~0.1% | 5MB |

### Reducing Overhead

```yaml
agent:
  network:
    # Reduce ring buffer size
    ring_buffer_size: 8388608  # 8MB instead of 16MB
    
    # Increase sampling
    tcp:
      sample_rate: 10  # 1 in 10 connections
    
    # Limit captured data
    http:
      max_body_capture: 0  # Don't capture bodies
      max_headers: 5       # Limit headers
```

---

## Best Practices

### 1. Filter Noisy Traffic

Exclude health checks and internal traffic:

```yaml
agent:
  ebpf:
    network:
      exclude_paths:
        - "/health*"
        - "/ready*"
        - "/metrics"
      exclude_ports:
        - 2379  # etcd
        - 10250 # kubelet
```

### 2. Use Appropriate Sampling

For high-traffic environments:

```yaml
agent:
  network:
    tcp:
      sample_rate: 100  # 1% of connections
    xdp:
      sample_rate: 10000  # 0.01% of packets
```

### 3. Monitor Key Services

Focus on critical paths:

```yaml
agent:
  network:
    include_ports:
      - 80    # HTTP
      - 443   # HTTPS
      - 5432  # PostgreSQL
      - 6379  # Redis
```

---

## Messaging Protocols

Telegen captures tracing data for AMQP 0-9-1, CQL (Cassandra), and NATS at the eBPF level — no SDK instrumentation or configuration changes required.

---

### AMQP 0-9-1 Tracing

AMQP 0-9-1 is the wire protocol used by RabbitMQ and other brokers. Telegen captures publish and consume operations at the channel level.

#### What's Captured

| Field | Description |
|-------|-------------|
| `messaging.system` | `rabbitmq` |
| `messaging.operation` | `publish` or `process` |
| `messaging.destination.name` | Exchange name |
| `messaging.rabbitmq.destination.routing_key` | Routing key |
| `messaging.client_id` | AMQP channel ID |
| `net.peer.ip` / `net.peer.port` | Broker address |

#### Sample Span

```json
{
  "name": "orders.created publish",
  "kind": "PRODUCER",
  "duration_ms": 0.8,
  "attributes": {
    "messaging.system": "rabbitmq",
    "messaging.operation": "publish",
    "messaging.destination.name": "events",
    "messaging.rabbitmq.destination.routing_key": "orders.created",
    "net.peer.ip": "10.0.2.50",
    "net.peer.port": 5672
  }
}
```

#### Configuration

```yaml
agent:
  network:
    protocols:
      amqp:
        enabled: true
        capture_routing_key: true
```

---

### CQL (Cassandra) Tracing

Telegen parses the Cassandra Query Language binary protocol (CQL v3–v5) to capture query statements, keyspaces, batch operations, and prepared statement execution.

See {doc}`database-tracing` for the full Cassandra tracing reference.

---

### NATS Tracing

NATS is a lightweight, text-based publish/subscribe messaging system. Telegen captures PUB, MSG, and subscription operations from the NATS wire protocol.

#### What's Captured

| Field | Description |
|-------|-------------|
| `messaging.system` | `nats` |
| `messaging.operation` | `publish` or `process` |
| `messaging.destination.name` | Subject name |
| `net.peer.ip` / `net.peer.port` | NATS server address |

#### Sample Span

```json
{
  "name": "sensor.readings publish",
  "kind": "PRODUCER",
  "duration_ms": 0.2,
  "attributes": {
    "messaging.system": "nats",
    "messaging.operation": "publish",
    "messaging.destination.name": "sensor.readings",
    "net.peer.ip": "10.0.3.10",
    "net.peer.port": 4222
  }
}
```

#### Configuration

```yaml
agent:
  network:
    protocols:
      nats:
        enabled: true
        capture_subject: true
```

---

## Connection Statistics

Telegen tracks byte-level connection statistics via TCP close events, providing a low-overhead measure of throughput per connection without full payload capture.

### Metrics Emitted

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen.connection.bytes_sent` | Counter | src, dst, port | Bytes sent per connection lifetime |
| `telegen.connection.bytes_received` | Counter | src, dst, port | Bytes received per connection lifetime |

These metrics are emitted when a TCP connection closes and complement the per-request span data produced by the protocol parsers.

### Configuration

```yaml
agent:
  ebpf:
    conn_stats:
      enabled: true
```

---

## Next Steps

- {doc}`database-tracing` - Deep database network tracing
- {doc}`security-observability` - Network security events
- {doc}`../configuration/agent-mode` - Network configuration
