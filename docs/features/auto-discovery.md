# Auto-Discovery

Telegen automatically discovers your infrastructure, cloud environment, and running applications.

## Overview

When Telegen starts, it automatically:

1. **Detects cloud provider** - AWS, GCP, Azure, etc.
2. **Discovers Kubernetes metadata** - Pods, services, namespaces
3. **Identifies application runtimes** - Go, Java, Python, Node.js
4. **Maps network topology** - Services, connections, dependencies

No configuration required.

---

## Cloud Detection

Telegen queries cloud metadata services to identify the environment:

| Provider | Detection Method | Metadata Collected |
|----------|------------------|-------------------|
| **AWS** | IMDS v1/v2 | Instance ID, region, AZ, instance type, AMI |
| **GCP** | Metadata server | Instance ID, zone, machine type, project |
| **Azure** | IMDS | VM ID, location, VM size, subscription |
| **DigitalOcean** | Metadata service | Droplet ID, region, size |
| **Alibaba Cloud** | Metadata service | Instance ID, region, zone |

### Example AWS Metadata

```yaml
# Automatically added to all telemetry
cloud.provider: aws
cloud.platform: aws_ec2
cloud.account.id: "123456789012"
cloud.region: us-east-1
cloud.availability_zone: us-east-1a
host.id: i-0abc123def456
host.type: m5.xlarge
host.image.id: ami-0abc123
```

### Example Kubernetes Metadata

```yaml
# Automatically added when running in K8s
k8s.cluster.name: production
k8s.namespace.name: default
k8s.pod.name: my-app-xyz123
k8s.pod.uid: a1b2c3d4-e5f6-7890-abcd-ef1234567890
k8s.deployment.name: my-app
k8s.node.name: ip-10-0-1-100.ec2.internal
k8s.container.name: app
```

---

## Runtime Detection

Telegen identifies running application runtimes through process analysis:

| Runtime | Detection Method | Auto-Instrumentation |
|---------|------------------|---------------------|
| **Go** | Binary analysis, goroutine patterns | ✅ HTTP, gRPC, database |
| **Java** | JVM process, JFR integration | ✅ Full JVM tracing |
| **Python** | Interpreter detection | ✅ HTTP, database, asyncio |
| **Node.js** | V8 process patterns | ✅ HTTP, database, async |
| **.NET** | CoreCLR detection | ✅ HTTP, database, EF Core |
| **Ruby** | Interpreter detection | ⚠️ Partial support |
| **Rust** | Binary analysis | ✅ Full tracing |
| **C/C++** | Binary analysis | ✅ Network, syscalls |

### Example Runtime Metadata

```yaml
# Automatically detected for a Go service
process.runtime.name: go
process.runtime.version: go1.21.5
process.executable.name: api-server
process.executable.path: /app/api-server
process.pid: 12345
process.command_line: /app/api-server --port=8080
```

---

## Database Detection

Telegen identifies database connections and auto-traces queries:

| Database | Detection | Tracing Support |
|----------|-----------|-----------------|
| **PostgreSQL** | Port 5432, wire protocol | ✅ Queries, latency, errors |
| **MySQL** | Port 3306, wire protocol | ✅ Queries, latency, errors |
| **MongoDB** | Port 27017, wire protocol | ✅ Operations, aggregations |
| **Redis** | Port 6379, RESP protocol | ✅ Commands, latency |
| **Elasticsearch** | Port 9200, HTTP | ✅ Queries, bulk ops |

---

## Message Queue Detection

| Queue | Detection | Tracing Support |
|-------|-----------|-----------------|
| **Kafka** | Port 9092, protocol | ✅ Produce, consume, lag |
| **RabbitMQ** | Port 5672, AMQP | ✅ Publish, consume |
| **Redis Pub/Sub** | Port 6379, RESP | ✅ Publish, subscribe |
| **NATS** | Port 4222 | ✅ Publish, subscribe |

---

## Service Discovery

Telegen builds a topology map of all services:

```{mermaid}
flowchart LR
    subgraph Discovery["Auto-Discovery"]
        A["Frontend\n(Node.js)"]
        B["API Gateway\n(Go)"]
        C["Order Service\n(Java)"]
        D["User Service\n(Python)"]
        E["PostgreSQL"]
        F["Redis"]
        G["Kafka"]
    end
    
    A -->|HTTP| B
    B -->|gRPC| C
    B -->|gRPC| D
    C -->|SQL| E
    D -->|SQL| E
    B -->|Commands| F
    C -->|Produce| G
```

### Service Metadata

```yaml
# Automatically generated service topology
service.name: order-service
service.version: 1.2.3
service.namespace: production
service.instance.id: order-service-abc123

# Detected dependencies
dependencies:
  - service: postgres
    type: database
    protocol: postgresql
  - service: kafka
    type: message_queue
    protocol: kafka
  - service: user-service
    type: service
    protocol: grpc
```

---

## Configuration

### Enabling/Disabling Discovery

```yaml
agent:
  discovery:
    enabled: true
    interval: 30s
    
    # What to discover
    detect_cloud: true
    detect_kubernetes: true
    detect_runtimes: true
    detect_databases: true
    detect_message_queues: true
```

### Cloud-Specific Settings

```yaml
cloud:
  aws:
    enabled: true
    timeout: 200ms
    refresh_interval: 15m
    collect_tags: true
    tag_allowlist:
      - "app_*"
      - "env"
      - "team"
      - "cost_center"
  
  gcp:
    enabled: true
    timeout: 200ms
    refresh_interval: 15m
  
  azure:
    enabled: true
    timeout: 200ms
    refresh_interval: 15m
```

### Kubernetes Settings

```yaml
agent:
  kubernetes:
    enabled: true
    
    # Metadata to collect
    pod_metadata: true
    node_metadata: true
    service_metadata: true
    
    # Label filtering
    label_allowlist:
      - "app.kubernetes.io/*"
      - "helm.sh/*"
      - "app"
      - "version"
      - "team"
    
    # Namespace filtering
    namespace_include: []  # Empty = all
    namespace_exclude:
      - kube-system
      - kube-public
      - kube-node-lease
```

---

## Resource Attributes

All discovered metadata is attached as OpenTelemetry resource attributes:

### Cloud Attributes (Semantic Conventions)

| Attribute | Description |
|-----------|-------------|
| `cloud.provider` | Cloud provider (aws, gcp, azure) |
| `cloud.platform` | Platform (aws_ec2, gcp_compute_engine) |
| `cloud.region` | Cloud region |
| `cloud.availability_zone` | Availability zone |
| `cloud.account.id` | Account/project ID |
| `host.id` | Instance ID |
| `host.type` | Instance type |

### Kubernetes Attributes

| Attribute | Description |
|-----------|-------------|
| `k8s.cluster.name` | Cluster name |
| `k8s.namespace.name` | Namespace |
| `k8s.pod.name` | Pod name |
| `k8s.pod.uid` | Pod UID |
| `k8s.deployment.name` | Deployment name |
| `k8s.replicaset.name` | ReplicaSet name |
| `k8s.node.name` | Node name |
| `k8s.container.name` | Container name |

### Process Attributes

| Attribute | Description |
|-----------|-------------|
| `process.pid` | Process ID |
| `process.executable.name` | Executable name |
| `process.executable.path` | Full path |
| `process.command_line` | Command line |
| `process.runtime.name` | Runtime (go, java, python) |
| `process.runtime.version` | Runtime version |

---

## Best Practices

### 1. Use Label Allowlists

Avoid collecting unnecessary labels that increase cardinality:

```yaml
agent:
  kubernetes:
    label_allowlist:
      - "app"
      - "version"
      - "team"
    # NOT: "*" (collects everything)
```

### 2. Set Reasonable Timeouts

Fast timeouts prevent slow cloud APIs from blocking:

```yaml
cloud:
  aws:
    timeout: 200ms  # Quick timeout
    refresh_interval: 15m  # Cache results
```

### 3. Exclude System Namespaces

Reduce noise from infrastructure components:

```yaml
agent:
  kubernetes:
    namespace_exclude:
      - kube-system
      - kube-public
      - monitoring
      - logging
```

---

## Next Steps

- {doc}`distributed-tracing` - How auto-discovered services are traced
- {doc}`../configuration/agent-mode` - Full agent configuration
