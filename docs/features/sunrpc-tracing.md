# SunRPC (ONC RPC) Tracing

Telegen provides eBPF-based tracing for SunRPC / ONC RPC (Open Network Computing Remote Procedure Call), the protocol used by NFS, NIS, and many legacy Unix services.

---

## Overview

SunRPC is detected at the wire level using generic TCP/UDP tracing. Telegen captures:

- **Program ID** and **procedure number**
- **Version** of the RPC program
- **Service name** resolution (from known program ID mappings)
- **Call/reply** matching for latency measurement

---

## Protocol Details

SunRPC uses a fixed 28-byte header for calls and 24-byte header for replies (XID + message type + RPC version + program/version/procedure + credentials + verifier).

| Field | Size | Description |
|-------|------|-------------|
| `xid` | 4 bytes | Transaction ID (call/reply match) |
| `type` | 4 bytes | Call (0) or Reply (1) |
| `rpcvers` | 4 bytes | RPC version (2) |
| `prog` | 4 bytes | Program number |
| `vers` | 4 bytes | Program version |
| `proc` | 4 bytes | Procedure number |
| `cred` | 8+ bytes | Authentication credentials |
| `verf` | 8+ bytes | Verifier |

---

## Detected Program IDs

Telegen resolves common program IDs to service names:

| Program ID | Service |
|-----------|---------|
| `100000` | portmapper |
| `100003` | NFS |
| `100005` | mountd |
| `100021` | nlockmgr |
| `100024` | status |
| `100011` | rquotad |
| `100017` | rexd |
| `100018` | sprayd |
| `100020` | llockmgr |
| `100026` | bootparam |
| `100029` | yppasswdd |
| `100033` | ypbind |
| `100034` | ypserv |

---

## Span Details

### SunRPC Client Span

```yaml
span:
  name: "SUNRPC 100003.3.GETATTR"
  kind: CLIENT
  duration_ms: 1.2
  attributes:
    rpc.system: "sunrpc"
    rpc.service: "nfs"
    rpc.method: "GETATTR"
    rpc.program: 100003
    rpc.program_version: 3
    rpc.procedure: 1
    net.peer.ip: "10.0.1.100"
    net.peer.port: 2049
```

### SunRPC Server Span

When both client and server are on the same host (or server is instrumented), Telegen also generates a `SpanKindServer` span.

---

## Configuration

SunRPC tracing is controlled via the instrumentation filter:

```yaml
exports:
  otlp:
    instrumentation:
      sunrpc: true   # Enable SunRPC tracing (default: false)
```

SunRPC tracing is **disabled by default** because it generates high-volume spans for chatty NFS workloads. Enable only when NFS/RPC observability is needed.

---

## Integration

SunRPC tracing integrates with the existing instrumentation pipeline:

- `InstrumentationSunRPC` flag in `pkg/export/instrumentations/instr_options.go`
- `EventTypeSunRPCClient` / `EventTypeSunRPCServer` in `internal/appolly/app/request/span.go`
- `acceptSpan` in `pkg/export/otel/tracesgen/tracesgen.go` routes SunRPC spans through the full OTLP export path

---

## Limitations

- SunRPC over **UDP** is not yet supported (TCP only)
- **Fragmentation** (sunrpc fragment header bit) is handled but reassembly of large fragmented calls is best-effort
- **Authentication** (AUTH_UNIX, AUTH_GSS) credentials are not decoded — only the credential flavor is captured
- **NFSv4 compound operations** are captured at the RPC layer; individual operations within the compound are not yet parsed

---

## Related Features

- **NFS tracing** — SunRPC tracing enables NFS procedure-level observability. For NFS-specific metrics (v3/v4 ops, latency), see the NetApp ONTAP performance counters and the generic NFS tracing in network observability.
- **Network observability** — SunRPC calls are also visible in TCP flow metrics (bytes, RTT, retransmits).
