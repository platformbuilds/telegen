# AMQP-family final handoff checklist

This handoff note lists the post-implementation validation that must be run by a human operator before merge/release.

## 1) Docker image build

Run a clean local image build from repository root:

```bash
docker build -t telegen:amqp-family-local .
```

Optional runtime smoke:

```bash
docker run --rm --privileged --pid=host --network=host \
  -v /sys:/sys:ro \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  telegen:amqp-family-local --help
```

## 2) BPF verifier gate

Before any `release/mark-v*` tag, the CI `verifier` job must be green. The **hard** gate is:

1. **generictracer** bare load (`TestLoadAllTracerBpfObjects/generictracer`) — catches MQ/AMQP kernel-classifier verifier rejects.
2. **gotracer attach+emit** (`TestGoTracerAttachAndEmitHTTP`) — catches the 3.1.26 Go blackout class (loads fine, never emits).

Local convenience (Docker, privileged):

```bash
make verifier-check
```

A clean `docker build` does **not** imply loadability — the verifier is a load-time kernel check, not a compile-time check. The `verifier-check` target depends on `docker-generate` so it can never test stale bytecode.

**Load success is not enough.** A clean BPF load does **not** imply attachment or span emission. Unresolved optional Go uprobes (e.g. `amqp091`) must be `Skip`'d; the attach+emit smoke is mandatory.

Other tracers in `TestLoadAllTracerBpfObjects` (gotracer/gpuevent/logenricher/…) use bare `LoadBpfObjects` without the production `resolveMaps` / constant-rewrite path and may soft-skip on ubuntu-latest (CO-RE / pin / MaxEntries). That soft path is **advisory** until those loads use the production Init path. The `obi-smoke` OTLP forward smoke remains a `docker` job blocker.

The AMQP 0-9-1 large-buffer path is capped at `K_TCP_MAX_LEN` (256 bytes) when the kernel cannot hint the protocol type. This is a known caveat tracked for Phase C.

## 3) Real-broker protocol verification matrix

### RabbitMQ (AMQP 0-9-1)

- Publish and consume a message through exchange + routing key.
- Verify spans contain:
  - `messaging.system=rabbitmq`
  - `messaging.operation.type` transitions (`publish`, `receive`, `settle`)
  - `messaging.operation.name` values such as `basic.publish`, `basic.deliver`, `basic.ack`/`basic.nack`
  - `messaging.destination.name` populated on publish and recovered on settle.

### ActiveMQ Artemis (AMQP 1.0 + STOMP)

- AMQP 1.0 flow: `attach -> transfer -> disposition`.
- Verify spans contain:
  - AMQP 1.0 operation names (`amqp1.attach`, `amqp1.transfer`, `amqp1.disposition`)
  - destination resolution for `transfer` and `disposition` via link-address cache.
- STOMP flow: `SEND`, `SUBSCRIBE`, `MESSAGE`, `ACK`/`NACK`.
- Verify STOMP operation names (`stomp.send`, `stomp.subscribe`, `stomp.message`, `stomp.ack`/`stomp.nack`).

### ActiveMQ Classic (OpenWire)

- Producer + consumer flow that emits `ProducerInfo`, `Message`, and `MessageAck`.
- Verify spans contain:
  - `messaging.system=activemq`
  - `messaging.operation.name` values (`openwire.producer_info`, `openwire.message`, `openwire.message_ack`)
  - destination recovery on ack path.

## 4) Kernel hint and fallback parity

- Execute one run with normal protocol hints.
- Execute one run where userspace heuristic parsing is forced/observed for the same traffic shape.
- Compare spans for equivalent operation typing and destination extraction.

## 5) Config and limits checks

- Confirm `ebpf.buffer_sizes.mq` is accepted by all deployment configs.
- Confirm no `capture_routing_key` option is used anywhere in runtime config.
- Validate expected truncation behavior for very large payloads and that large-buffer capture is effective when `mq` buffer size is non-zero.
