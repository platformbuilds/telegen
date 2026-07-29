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

## 2) Real-broker protocol verification matrix

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

## 3) Kernel hint and fallback parity

- Execute one run with normal protocol hints.
- Execute one run where userspace heuristic parsing is forced/observed for the same traffic shape.
- Compare spans for equivalent operation typing and destination extraction.

## 4) Config and limits checks

- Confirm `ebpf.buffer_sizes.mq` is accepted by all deployment configs.
- Confirm no `capture_routing_key` option is used anywhere in runtime config.
- Validate expected truncation behavior for very large payloads and that large-buffer capture is effective when `mq` buffer size is non-zero.
