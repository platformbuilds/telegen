# Features

Detailed guides for Telegen's observability features.

## Overview

Telegen provides comprehensive observability through:

- **eBPF-based instrumentation** - Zero-code, kernel-level collection
- **Automatic discovery** - Cloud, Kubernetes, runtime detection
- **Full-stack correlation** - Traces, metrics, logs, profiles linked automatically

## Feature Categories

### Core Observability

```{toctree}
:maxdepth: 1

auto-discovery
distributed-tracing
log-collection
continuous-profiling
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

### Specialized

```{toctree}
:maxdepth: 1

aiml-observability
node-exporter-fusion
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
| **SNMP Collection** | ❌ | ✅ | Network access |
| **Storage Monitoring** | ❌ | ✅ | API credentials |
| **AI/ML Observability** | ✅ | ❌ | eBPF + GPU |
| **Node Exporter Fusion** | ✅ | ❌ | eBPF |
