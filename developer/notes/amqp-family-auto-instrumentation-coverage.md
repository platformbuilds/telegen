# AMQP-family auto-instrumentation coverage

This note captures the current implementation coverage for AMQP-family broker tracing in Telegen.

## Protocol coverage

- **AMQP 0-9-1**
  - Kernel detection: frame-header classifier in eBPF (`is_amqp`).
  - Userspace parsing: method-frame parser with class/method-aware destination extraction.
  - Operation mapping: `publish`, `receive`, `settle`, `create`, `process`.
  - Settle destination recovery: per-connection/per-channel LRU cache.
- **AMQP 1.0**
  - Kernel detection: protocol header + performative descriptor classifier (`is_amqp1`).
  - Userspace parsing: frame header + performatives (`attach`, `transfer`, `disposition`, `flow`, `detach`).
  - Link-address recovery: attach-populated LRU keyed by `(conn, channel, handle, role)`.
- **OpenWire**
  - Kernel detection: ActiveMQ magic / command signature classifier (`is_openwire`).
  - Userspace parsing: `WireFormatInfo`, `ProducerInfo`, `ConsumerInfo`, `Message`, `MessageAck`.
  - Destination cache: producer/consumer destination LRU for `Message` / `MessageAck`.
- **STOMP**
  - Kernel detection: closed command-set line matcher (`is_stomp`).
  - Userspace parsing: strict frame parser (LF + CRLF support, header unescape, null terminator).
  - Near-miss rejection: non-command uppercase text buffers are explicitly rejected.

## Shared MQ large-buffer path

- New shared eBPF large-buffer constant: `mq_buffer_size`.
- New shared scratch arena: `mq_large_buffers`.
- Protocols using this arena: AMQP 0-9-1, AMQP 1.0, OpenWire, STOMP.
- Configuration key: `ebpf.buffer_sizes.mq`.

## Semantic conventions and span mapping

- Raw protocol verb is preserved as `messaging.operation.name` (for example `basic.publish`, `amqp1.transfer`, `openwire.message`, `stomp.send`).
- Normalized operation type is stored in `messaging.operation.type`.
- `messaging.system` is refined by process + container + port hints:
  - RabbitMQ, ActiveMQ, Azure Service Bus, JMS.

## Current limits

- Small in-kernel capture windows still apply (request/response fixed buffer caps).
- Full payload reconstruction depends on MQ large-buffer capture.
- AMQP Go uprobe coverage currently targets:
  - `github.com/rabbitmq/amqp091-go`
  - `github.com/streadway/amqp`
- Other language-specific client internals rely on TCP protocol parsing.

## Validation checklist

- Unit tests exist for:
  - AMQP 0-9-1 parser/transform behavior
  - AMQP 1.0 parser + transform + cache behavior
  - OpenWire parser + transform + destination caches
  - STOMP parser + transform + near-miss rejection
  - Kernel-hint vs fallback userspace parity for AMQP events
