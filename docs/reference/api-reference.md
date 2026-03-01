# API Reference

REST API endpoints exposed by Telegen.

## Overview

Telegen exposes a REST API for health checks, metrics, and status information. By default, the API listens on port `19090`.

```yaml
self_telemetry:
  listen: ":19090"
```

---

## Health Endpoints

### GET /healthz

Liveness probe endpoint.

**Response:**

```json
{
  "status": "ok"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Healthy |
| 503 | Unhealthy |

**Example:**

```bash
curl http://localhost:19090/healthz
```

---

### GET /ready

Readiness probe endpoint.

**Response:**

```json
{
  "status": "ready",
  "checks": {
    "ebpf": "ok",
    "otlp": "ok",
    "discovery": "ok"
  }
}
```

**Failed Check Response:**

```json
{
  "status": "not_ready",
  "checks": {
    "ebpf": "ok",
    "otlp": "failed: connection refused",
    "discovery": "ok"
  }
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Ready |
| 503 | Not ready |

**Example:**

```bash
curl http://localhost:19090/ready
```

---

## Metrics Endpoint

### GET /metrics

Prometheus metrics endpoint.

**Response:** Prometheus text format

```text
# HELP telegen_spans_collected_total Total spans collected
# TYPE telegen_spans_collected_total counter
telegen_spans_collected_total 12345

# HELP telegen_process_resident_memory_bytes Memory usage
# TYPE telegen_process_resident_memory_bytes gauge
telegen_process_resident_memory_bytes 134217728
...
```

**Content-Type:** `text/plain; version=0.0.4`

**Example:**

```bash
curl http://localhost:19090/metrics
```

---

## Status Endpoints

### GET /status

Detailed status information.

**Response:**

```json
{
  "version": "3.0.0",
  "commit": "abc1234",
  "built": "2024-01-15T10:00:00Z",
  "uptime": "24h15m30s",
  "mode": "agent",
  "host": {
    "name": "node-1",
    "os": "linux",
    "arch": "amd64",
    "kernel": "5.15.0-91-generic"
  },
  "ebpf": {
    "enabled": true,
    "programs_loaded": 15,
    "maps_created": 25,
    "ringbuf_size": 16777216
  },
  "profiling": {
    "enabled": true,
    "sample_rate": 99,
    "profiles_collected": 1234
  },
  "export": {
    "endpoint": "otel-collector:4317",
    "connected": true,
    "last_export": "2024-01-15T10:30:00Z",
    "spans_exported": 123456,
    "metrics_exported": 789012
  },
  "discovery": {
    "kubernetes": true,
    "docker": true,
    "pods_discovered": 45,
    "containers_discovered": 78
  }
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Success |

**Example:**

```bash
curl http://localhost:19090/status
```

---

### GET /status/ebpf

eBPF-specific status.

**Response:**

```json
{
  "enabled": true,
  "programs": [
    {
      "name": "trace_http_request",
      "type": "kprobe",
      "attached": true,
      "id": 123
    },
    {
      "name": "trace_tcp_connect",
      "type": "tracepoint",
      "attached": true,
      "id": 124
    }
  ],
  "maps": [
    {
      "name": "connection_map",
      "type": "hash",
      "entries": 1234,
      "max_entries": 100000
    }
  ],
  "ringbuf": {
    "size": 16777216,
    "events_received": 1234567,
    "events_lost": 0
  }
}
```

**Example:**

```bash
curl http://localhost:19090/status/ebpf
```

---

### GET /status/export

Export status.

**Response:**

```json
{
  "endpoint": "otel-collector:4317",
  "protocol": "grpc",
  "tls": false,
  "compression": "gzip",
  "connected": true,
  "last_export": "2024-01-15T10:30:00Z",
  "last_error": null,
  "queues": {
    "traces": {
      "size": 128,
      "capacity": 10000,
      "exported": 123456,
      "dropped": 0
    },
    "metrics": {
      "size": 64,
      "capacity": 5000,
      "exported": 789012,
      "dropped": 0
    },
    "logs": {
      "size": 256,
      "capacity": 10000,
      "exported": 456789,
      "dropped": 0
    }
  }
}
```

**Example:**

```bash
curl http://localhost:19090/status/export
```

---

### GET /status/discovery

Discovery status.

**Response:**

```json
{
  "kubernetes": {
    "enabled": true,
    "connected": true,
    "cluster": "prod-cluster",
    "namespace": "monitoring",
    "pods_watched": 145,
    "services_watched": 32
  },
  "docker": {
    "enabled": true,
    "connected": true,
    "containers": 12
  },
  "cloud": {
    "provider": "aws",
    "region": "us-east-1",
    "instance_id": "i-1234567890abcdef0"
  },
  "discovered_services": [
    {
      "name": "frontend",
      "namespace": "default",
      "instances": 3,
      "ports": [80, 443]
    },
    {
      "name": "api",
      "namespace": "default",
      "instances": 2,
      "ports": [8080]
    }
  ]
}
```

**Example:**

```bash
curl http://localhost:19090/status/discovery
```

---

## Configuration Endpoint

### GET /config

Current configuration (sanitized).

**Response:**

```json
{
  "mode": "agent",
  "otlp": {
    "endpoint": "otel-collector:4317",
    "insecure": true,
    "compression": "gzip"
  },
  "agent": {
    "ebpf": {
      "enabled": true,
      "network": {
        "enabled": true
      }
    },
    "profiling": {
      "enabled": true,
      "sample_rate": 99
    }
  }
}
```

**Note:** Sensitive values (passwords, tokens) are redacted.

**Example:**

```bash
curl http://localhost:19090/config
```

---

## Debug Endpoints

These endpoints are available when debug mode is enabled.

### GET /debug/pprof/

Go pprof endpoints.

**Available Profiles:**

| Path | Description |
|------|-------------|
| `/debug/pprof/` | Index |
| `/debug/pprof/heap` | Heap profile |
| `/debug/pprof/goroutine` | Goroutine stacks |
| `/debug/pprof/threadcreate` | Thread creation |
| `/debug/pprof/block` | Blocking profile |
| `/debug/pprof/mutex` | Mutex contention |
| `/debug/pprof/profile` | CPU profile |
| `/debug/pprof/trace` | Execution trace |

**Examples:**

```bash
# CPU profile (30 seconds)
curl http://localhost:19090/debug/pprof/profile?seconds=30 > cpu.pprof

# Heap profile
curl http://localhost:19090/debug/pprof/heap > heap.pprof

# Goroutine stacks
curl http://localhost:19090/debug/pprof/goroutine?debug=2

# Analyze with go tool
go tool pprof cpu.pprof
```

---

### GET /debug/vars

Runtime variables (expvar).

**Response:**

```json
{
  "cmdline": ["telegen", "--config", "/etc/telegen/config.yaml"],
  "memstats": {
    "Alloc": 12345678,
    "TotalAlloc": 987654321,
    "Sys": 23456789,
    "NumGC": 123
  }
}
```

**Example:**

```bash
curl http://localhost:19090/debug/vars
```

---

## Admin Endpoints

### POST /admin/reload

Reload configuration.

**Request:** None

**Response:**

```json
{
  "status": "ok",
  "message": "Configuration reloaded"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Invalid configuration |
| 500 | Reload failed |

**Example:**

```bash
curl -X POST http://localhost:19090/admin/reload
```

---

### POST /admin/flush

Flush all queues.

**Response:**

```json
{
  "status": "ok",
  "flushed": {
    "traces": 128,
    "metrics": 64,
    "logs": 256
  }
}
```

**Example:**

```bash
curl -X POST http://localhost:19090/admin/flush
```

---

## Authentication

When authentication is enabled:

```yaml
self_telemetry:
  auth:
    enabled: true
    bearer_token: "${API_TOKEN}"
```

Include the token in requests:

```bash
curl -H "Authorization: Bearer ${API_TOKEN}" http://localhost:19090/status
```

---

## Rate Limiting

The API may be rate-limited:

```yaml
self_telemetry:
  rate_limit:
    enabled: true
    requests_per_second: 100
```

When rate limited, the API returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1
```

---

## CORS

For browser access, CORS can be enabled:

```yaml
self_telemetry:
  cors:
    enabled: true
    allowed_origins:
      - "http://localhost:3000"
```

---

## Error Responses

### Standard Error Format

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {
    "field": "additional context"
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `invalid_request` | Malformed request |
| `not_found` | Resource not found |
| `unauthorized` | Authentication required |
| `forbidden` | Permission denied |
| `internal_error` | Server error |
| `service_unavailable` | Temporarily unavailable |

---

## API Versioning

Current API version: **v1**

The API is currently unversioned. Future breaking changes will introduce versioned paths:

```
/api/v1/status
/api/v2/status
```

---

## OpenAPI Specification

OpenAPI spec is available at:

```bash
curl http://localhost:19090/openapi.json
```

---

## Next Steps

- {doc}`cli-reference` - CLI commands
- {doc}`metrics-reference` - Metrics details
- {doc}`../operations/monitoring` - Monitoring Telegen
