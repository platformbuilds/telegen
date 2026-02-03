# Semantic Conventions

OpenTelemetry semantic conventions used by Telegen.

## Overview

Telegen follows [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/concepts/semantic-conventions/) for consistent attribute naming across traces, metrics, and logs.

---

## Resource Attributes

Resource attributes describe the entity producing telemetry.

### Service

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `service.name` | string | Service name | `my-api` |
| `service.namespace` | string | Service namespace | `production` |
| `service.version` | string | Service version | `1.2.3` |
| `service.instance.id` | string | Instance ID | `pod-abc123` |

### Host

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `host.name` | string | Hostname | `node-1` |
| `host.id` | string | Host ID | `i-1234567890abcdef0` |
| `host.type` | string | Host type | `n1-standard-4` |
| `host.arch` | string | Architecture | `amd64` |
| `host.image.name` | string | OS image name | `ubuntu-22.04` |
| `host.image.version` | string | OS image version | `22.04.3` |

### Operating System

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `os.type` | string | OS type | `linux` |
| `os.description` | string | OS description | `Ubuntu 22.04.3 LTS` |
| `os.name` | string | OS name | `Ubuntu` |
| `os.version` | string | OS version | `22.04.3` |

### Process

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `process.pid` | int | Process ID | `12345` |
| `process.executable.name` | string | Executable name | `python` |
| `process.executable.path` | string | Executable path | `/usr/bin/python` |
| `process.command` | string | Command | `python app.py` |
| `process.command_line` | string | Full command line | `python app.py --port=8080` |
| `process.owner` | string | Process owner | `appuser` |
| `process.runtime.name` | string | Runtime | `python` |
| `process.runtime.version` | string | Runtime version | `3.11.4` |

### Container

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `container.name` | string | Container name | `my-container` |
| `container.id` | string | Container ID | `abc123...` |
| `container.runtime` | string | Container runtime | `containerd` |
| `container.image.name` | string | Image name | `my-app` |
| `container.image.tag` | string | Image tag | `v1.2.3` |

### Kubernetes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `k8s.pod.name` | string | Pod name | `my-pod-abc123` |
| `k8s.pod.uid` | string | Pod UID | `550a8ab5-...` |
| `k8s.namespace.name` | string | Namespace | `default` |
| `k8s.node.name` | string | Node name | `node-1` |
| `k8s.node.uid` | string | Node UID | `12345-...` |
| `k8s.deployment.name` | string | Deployment | `my-deployment` |
| `k8s.replicaset.name` | string | ReplicaSet | `my-rs-abc123` |
| `k8s.statefulset.name` | string | StatefulSet | `my-ss` |
| `k8s.daemonset.name` | string | DaemonSet | `my-ds` |
| `k8s.job.name` | string | Job | `my-job` |
| `k8s.cronjob.name` | string | CronJob | `my-cronjob` |
| `k8s.container.name` | string | Container name | `app` |
| `k8s.cluster.name` | string | Cluster name | `prod-cluster` |

### Cloud

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `cloud.provider` | string | Cloud provider | `aws`, `gcp`, `azure` |
| `cloud.account.id` | string | Account ID | `123456789012` |
| `cloud.region` | string | Region | `us-east-1` |
| `cloud.availability_zone` | string | AZ | `us-east-1a` |
| `cloud.platform` | string | Platform | `aws_eks` |

---

## HTTP Span Attributes

### Client Spans

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `http.request.method` | string | HTTP method | `GET` |
| `url.full` | string | Full URL | `https://api.example.com/users` |
| `url.path` | string | URL path | `/users` |
| `url.query` | string | Query string | `page=1&limit=10` |
| `url.scheme` | string | URL scheme | `https` |
| `server.address` | string | Server hostname | `api.example.com` |
| `server.port` | int | Server port | `443` |
| `http.response.status_code` | int | Status code | `200` |
| `network.protocol.version` | string | HTTP version | `1.1` |
| `user_agent.original` | string | User agent | `curl/8.0.1` |

### Server Spans

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `http.request.method` | string | HTTP method | `POST` |
| `url.path` | string | URL path | `/api/users` |
| `url.query` | string | Query string | `id=123` |
| `url.scheme` | string | URL scheme | `https` |
| `http.route` | string | Route template | `/api/users/{id}` |
| `http.response.status_code` | int | Status code | `201` |
| `http.request.body.size` | int | Request body size | `1024` |
| `http.response.body.size` | int | Response body size | `256` |
| `client.address` | string | Client IP | `10.0.0.1` |
| `client.port` | int | Client port | `54321` |

---

## gRPC Span Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `rpc.system` | string | RPC system | `grpc` |
| `rpc.service` | string | Service name | `mypackage.MyService` |
| `rpc.method` | string | Method name | `MyMethod` |
| `rpc.grpc.status_code` | int | gRPC status | `0` |
| `rpc.grpc.request.metadata.<key>` | string | Request metadata | |
| `rpc.grpc.response.metadata.<key>` | string | Response metadata | |

---

## Database Span Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `db.system` | string | Database system | `postgresql` |
| `db.connection_string` | string | Connection string | (redacted) |
| `db.user` | string | Database user | `appuser` |
| `db.name` | string | Database name | `mydb` |
| `db.statement` | string | SQL statement | `SELECT * FROM users` |
| `db.operation` | string | Operation | `SELECT` |
| `db.sql.table` | string | Table name | `users` |
| `server.address` | string | Server hostname | `db.example.com` |
| `server.port` | int | Server port | `5432` |

### Database System Values

| Value | Database |
|-------|----------|
| `postgresql` | PostgreSQL |
| `mysql` | MySQL |
| `mongodb` | MongoDB |
| `redis` | Redis |
| `elasticsearch` | Elasticsearch |
| `cassandra` | Cassandra |
| `mssql` | Microsoft SQL Server |
| `oracle` | Oracle |

---

## Messaging Span Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `messaging.system` | string | Messaging system | `kafka` |
| `messaging.destination.name` | string | Topic/queue | `orders` |
| `messaging.destination.kind` | string | Destination kind | `topic` |
| `messaging.operation` | string | Operation | `publish`, `receive` |
| `messaging.message.id` | string | Message ID | `msg-123` |
| `messaging.message.body.size` | int | Body size | `512` |
| `messaging.kafka.partition` | int | Partition | `3` |
| `messaging.kafka.offset` | int | Offset | `12345` |
| `messaging.kafka.consumer_group` | string | Consumer group | `order-processor` |

---

## Network Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `network.transport` | string | Transport | `tcp`, `udp` |
| `network.type` | string | Network type | `ipv4`, `ipv6` |
| `network.protocol.name` | string | Protocol | `http` |
| `network.protocol.version` | string | Protocol version | `1.1` |
| `network.peer.address` | string | Peer address | `10.0.0.1` |
| `network.peer.port` | int | Peer port | `8080` |
| `network.local.address` | string | Local address | `192.168.1.1` |
| `network.local.port` | int | Local port | `54321` |

---

## Exception Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `exception.type` | string | Exception type | `java.lang.NullPointerException` |
| `exception.message` | string | Exception message | `Object is null` |
| `exception.stacktrace` | string | Stack trace | (multiline) |
| `exception.escaped` | boolean | Escaped scope | `true` |

---

## Span Status

| Status | Code | Description |
|--------|------|-------------|
| `Unset` | 0 | Default, not set |
| `Ok` | 1 | Successful |
| `Error` | 2 | Error occurred |

---

## Span Kind

| Kind | Description | Example |
|------|-------------|---------|
| `INTERNAL` | Internal operation | Business logic |
| `SERVER` | Server-side request | HTTP server handler |
| `CLIENT` | Client-side request | HTTP client call |
| `PRODUCER` | Message producer | Kafka producer |
| `CONSUMER` | Message consumer | Kafka consumer |

---

## Metric Semantic Conventions

### HTTP Metrics

| Metric | Type | Unit | Description |
|--------|------|------|-------------|
| `http.server.request.duration` | Histogram | s | Server request duration |
| `http.server.active_requests` | UpDownCounter | {request} | Active requests |
| `http.server.request.body.size` | Histogram | By | Request body size |
| `http.server.response.body.size` | Histogram | By | Response body size |
| `http.client.request.duration` | Histogram | s | Client request duration |

### RPC Metrics

| Metric | Type | Unit | Description |
|--------|------|------|-------------|
| `rpc.server.duration` | Histogram | ms | Server call duration |
| `rpc.client.duration` | Histogram | ms | Client call duration |

### Database Metrics

| Metric | Type | Unit | Description |
|--------|------|------|-------------|
| `db.client.connections.usage` | UpDownCounter | {connection} | Connections |
| `db.client.connections.max` | UpDownCounter | {connection} | Max connections |

---

## Log Semantic Conventions

### Severity Levels

| Level | Number | Description |
|-------|--------|-------------|
| TRACE | 1 | Fine-grained debug |
| DEBUG | 5 | Debug information |
| INFO | 9 | Informational |
| WARN | 13 | Warning |
| ERROR | 17 | Error |
| FATAL | 21 | Fatal error |

### Common Log Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `log.file.name` | string | Log file name |
| `log.file.path` | string | Log file path |
| `log.iostream` | string | stdout/stderr |
| `log.record.uid` | string | Unique log ID |

---

## Telegen-Specific Attributes

In addition to OTel conventions, Telegen adds:

| Attribute | Type | Description |
|-----------|------|-------------|
| `telegen.version` | string | Telegen version |
| `telegen.ebpf.program` | string | eBPF program name |
| `telegen.discovery.source` | string | Discovery source |
| `telegen.profile.type` | string | Profile type |

---

## Best Practices

1. **Use standard conventions** - Prefer OTel conventions over custom attributes
2. **Add context** - Include relevant resource attributes
3. **Low cardinality** - Avoid high-cardinality values in metric labels
4. **Sensitive data** - Don't include PII or secrets in attributes
5. **Consistent naming** - Follow snake_case for custom attributes

---

## Next Steps

- {doc}`metrics-reference` - Available metrics
- {doc}`../features/distributed-tracing` - Tracing details
- [OTel Semantic Conventions](https://opentelemetry.io/docs/concepts/semantic-conventions/)
