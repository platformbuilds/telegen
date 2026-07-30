# Features

Detailed guides for Telegen's observability features.

## Overview

Telegen provides comprehensive observability through:

- **eBPF-based instrumentation** - Zero-code, kernel-level collection
- **Automatic discovery** - Cloud, Kubernetes, runtime detection
- **Full-stack correlation** - Traces, metrics, logs, profiles linked automatically
- **Unified pipeline** - Single V3 pipeline with WAL queues, failover, circuit breakers

## Feature Categories

### Core Observability

```{toctree}
:maxdepth: 1

auto-discovery
distributed-tracing
log-collection
continuous-profiling
kube-metrics
```

### Messaging & RPC

```{toctree}
:maxdepth: 1

messaging-tracing
sunrpc-tracing
```

### Security & Network

```{toctree}
:maxdepth: 1

security-observability
network-observability
```

### Infrastructure

```{toctree}
:maxdepth: 1

database-tracing
snmp-receiver
storage-adapters
```

### Language-Specific

```{toctree}
:maxdepth: 1

c-cpp-instrumentation
go-channel-events
```

### Specialized

```{toctree}
:maxdepth: 1

aiml-observability
node-exporter-fusion
unified-pipeline
```

## Feature Matrix

| Feature | Agent Mode | Collector Mode | Requires |
|---------|------------|----------------|----------|
| **Auto-Discovery** | ✅ | ❌ | eBPF |
| **Distributed Tracing** | ✅ | ❌ | eBPF |
| **Log Collection** | ✅ | ✅ | Filesystem |
| **Log Trace Enrichment** | ✅ | ❌ | eBPF |
| **Continuous Profiling** | ✅ | ❌ | eBPF |
| **Security Monitoring** | ✅ | ❌ | eBPF |
| **Network Observability** | ✅ | ❌ | eBPF |
| **Database Tracing** | ✅ | ❌ | eBPF |
| **Cassandra/CQL Tracing** | ✅ | ❌ | eBPF |
| **MSSQL/TDS Tracing** | ✅ | ❌ | eBPF |
| **Couchbase Tracing** | ✅ | ❌ | eBPF |
| **C/C++ Instrumentation** | ✅ | ❌ | eBPF |
| **Messaging Tracing (AMQP 0-9-1)** | ✅ | ❌ | eBPF |
| **Messaging Tracing (AMQP 1.0)** | ✅ | ❌ | eBPF |
| **Messaging Tracing (OpenWire/STOMP)** | ✅ | ❌ | eBPF |
| **SunRPC Tracing** | ✅ | ❌ | eBPF |
| **Dubbo2 Tracing** | ✅ | ❌ | eBPF |
| **NATS Tracing** | ✅ | ❌ | eBPF |
| **Kafka Consumer Groups** | ✅ | ❌ | eBPF |
| **Go Channel-Link Events** | ✅ | ❌ | eBPF uprobes |
| **Connection Statistics** | ✅ | ❌ | eBPF |
| **Go TLS Plaintext Capture** | ✅ | ❌ | eBPF uprobes |
| **gRPC-C Tracing** | ✅ | ❌ | eBPF uprobes |
| **SNMP Collection** | ❌ | ✅ | Network access |
| **Storage Monitoring** | ❌ | ✅ | API credentials |
| **NetApp E-Series** | ❌ | ✅ | API credentials |
| **Firewall Infra (PAN-OS/FortiGate)** | ❌ | ✅ | Network access |
| **K8s Metrics Streaming** | ✅ | ✅ | K8s API |
| **K8s Events as Logs** | ✅ | ✅ | K8s API |
| **AI/ML Observability** | ✅ | ❌ | eBPF + GPU |
| **LLM API Tracing** | ✅ | ❌ | eBPF |
| **CUDA Tracing** | ✅ | ❌ | eBPF |
| **Node Exporter Fusion** | ✅ | ❌ | eBPF |
| **Unified Pipeline** | ✅ | ✅ | Shared OTLP |
