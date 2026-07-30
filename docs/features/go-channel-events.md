# Go Channel-Link Events

Telegen can capture Go channel send/receive operations as **span links**, connecting producer and consumer goroutines in distributed tracing. This provides end-to-end visibility across goroutine boundaries without any code changes.

---

## Overview

Go channels are the primary synchronization mechanism in Go programs. When a goroutine sends on a channel and another receives, there is no automatic trace linkage — the producer and consumer spans are disconnected.

Telegen solves this by:

1. **Capturing channel operations** via eBPF uprobes on Go runtime internals
2. **Extracting channel metadata** (hchan struct address, element size, buffer state)
3. **Creating span links** that connect the send operation to the receive operation

---

## How It Works

### eBPF Uprobe Capture

Telegen attaches uprobes to Go runtime functions:

- `runtime.chansend` — channel send operation
- `runtime.chanrecv` — channel receive operation

These uprobes capture:
- The `hchan` struct pointer (unique per channel instance)
- Whether the channel is buffered or unbuffered
- Whether the operation blocked (channel contention)
- Goroutine ID of the sender/receiver

### Goexec Offset Resolution

Go binaries store struct member offsets in the `runtime._hchan` type. Telegen uses `internal/goexec/offsets.go` to resolve:

- `hchan.buf` — buffer pointer
- `hchan.elemsize` — element size
- `hchan.recvq` / `hchan.sendq` — wait queues

These offsets are resolved at startup by parsing the Go binary's type information.

### Span Link Creation

When a send and receive on the same `hchan` address are detected within a time window:

1. The send span is enriched with a **span link** pointing to the receiving goroutine's span (or vice versa)
2. Both spans carry the `hchan` address as a link attribute for correlation
3. Channel contention (blocked send/receive) is recorded as a span event

---

## Configuration

Go channel-link events are enabled via the Go tracer configuration:

```yaml
agent:
  gotracer:
    enabled: true
    channel_link_events: true   # Enable channel-link span links
    # Optional: time window for matching send/receive (default 100ms)
    channel_link_window: "100ms"
```

---

## Span Attributes

### Channel-Link Span Link

```yaml
span:
  name: "goroutine.channel.send"
  kind: INTERNAL
  attributes:
    go.channel.hchan: "0x7f8a40001234"   # hchan struct address
    go.channel.buffered: true
    go.channel.blocked: false
  links:
    - trace_id: "abc123..."
      span_id: "def456..."
      attributes:
        go.channel.operation: "receive"
        go.channel.goroutine: 42
```

### Channel Contention Event

When a channel operation blocks (no buffer space or no ready receiver):

```yaml
span_events:
  - name: "channel.blocked"
    attributes:
      go.channel.hchan: "0x7f8a40001234"
      go.channel.operation: "send"
      go.channel.wait_ns: 1500000   # 1.5ms wait time
```

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **Go binary** | Must be a standard Go binary (not stripped of symbols) |
| **Go version** | Go 1.18+ (tested up to Go 1.22) |
| **Symbol resolution** | `runtime.chansend` and `runtime.chanrecv` symbols must be present |
| **Permissions** | `SYS_PTRACE` capability or equivalent for uprobe attachment |

---

## Limitations

- **Stripped binaries** — If the Go binary is stripped (no symbol table), uprobes cannot attach. Use `go build -ldflags="-s -w"` only when channel tracing is not needed.
- **Best-effort matching** — Span link matching uses a time window and hchan address. In high-throughput scenarios with channel reuse, links may be approximate.
- **Cross-pod correlation** — Channel links only work within a single process. Cross-pod Go channel communication (via network) is traced at the HTTP/gRPC layer, not the channel layer.
- **Third-party Go libraries** — Channel operations inside vendored or third-party code are captured as long as they use the standard `runtime.chansend`/`runtime.chanrecv` paths.

---

## Troubleshooting

### Channel events not appearing

1. Verify the Go tracer is enabled: `gotracer.enabled: true`
2. Check that the Go binary has symbols: `nm <binary> | grep chansend`
3. Check agent logs for uprobe attachment errors: `journalctl -u telegen | grep gotracer`

### Incorrect span links

Channel link matching is best-effort. If you see incorrect links, try increasing the `channel_link_window` to account for longer goroutine scheduling delays.

---

## Related Features

- **Go application tracing** — Go channel events complement HTTP/gRPC/SQL tracing for complete goroutine-level observability
- **Continuous profiling** — Go channel contention events can be correlated with CPU profiling data to identify blocking channels
- **eBPF runtime sources** — Channel events are part of the unified V3 pipeline's eBPF signal sources
