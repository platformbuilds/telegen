# Docker Installation

Deploy Telegen using Docker or Docker Compose.

## Prerequisites

- Docker 20.10+
- Linux host with kernel 4.18+ (for eBPF)
- Root/sudo access

---

## Quick Start

### Single Container (Agent Mode)

```bash
docker run -d --name telegen \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys:/sys:ro \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e TELEGEN_OTLP_ENDPOINT=otel-collector:4317 \
  ghcr.io/platformbuilds/telegen:latest
```

### With Configuration File

```bash
# Create config directory
mkdir -p /etc/telegen

# Create configuration
cat > /etc/telegen/config.yaml <<EOF
telegen:
  mode: agent
  service_name: telegen
  log_level: info

otlp:
  endpoint: "otel-collector:4317"
  protocol: grpc
  insecure: true

agent:
  ebpf:
    enabled: true
    network: true
    syscalls: true
  profiling:
    enabled: true
    cpu: true
    memory: true
  discovery:
    enabled: true
EOF

# Run with config
docker run -d --name telegen \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys:/sys:ro \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/telegen:/etc/telegen:ro \
  ghcr.io/platformbuilds/telegen:latest \
  --config=/etc/telegen/config.yaml
```

---

## Docker Compose

### Agent Mode

Create `docker-compose.yaml`:

```yaml
version: '3.8'

services:
  telegen:
    image: ghcr.io/platformbuilds/telegen:latest
    container_name: telegen
    restart: unless-stopped
    privileged: true
    pid: host
    network_mode: host
    
    environment:
      - TELEGEN_OTLP_ENDPOINT=otel-collector:4317
      - TELEGEN_LOG_LEVEL=info
    
    volumes:
      - /sys:/sys:ro
      - /proc:/host/proc:ro
      - /sys/kernel/debug:/sys/kernel/debug
      - /sys/fs/bpf:/sys/fs/bpf
      - ./config.yaml:/etc/telegen/config.yaml:ro
    
    command: ["--config=/etc/telegen/config.yaml", "--mode=agent"]
    
    healthcheck:
      test: ["CMD", "wget", "-q", "-O-", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

### Collector Mode

```yaml
version: '3.8'

services:
  telegen-collector:
    image: ghcr.io/platformbuilds/telegen:latest
    container_name: telegen-collector
    restart: unless-stopped
    
    ports:
      - "162:162/udp"   # SNMP traps
      - "19090:19090"   # Metrics
      - "8080:8080"     # Health
    
    environment:
      - TELEGEN_OTLP_ENDPOINT=otel-collector:4317
      - DELL_PASSWORD=${DELL_PASSWORD}
      - PURE_TOKEN=${PURE_TOKEN}
      - SNMP_AUTH_PASSWORD=${SNMP_AUTH_PASSWORD}
    
    volumes:
      - ./collector-config.yaml:/etc/telegen/config.yaml:ro
    
    command: ["--config=/etc/telegen/config.yaml", "--mode=collector"]
    
    healthcheck:
      test: ["CMD", "wget", "-q", "-O-", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Full Stack (Agent + Collector + OTel Collector)

```yaml
version: '3.8'

services:
  # OpenTelemetry Collector
  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    container_name: otel-collector
    restart: unless-stopped
    ports:
      - "4317:4317"   # OTLP gRPC
      - "4318:4318"   # OTLP HTTP
      - "8888:8888"   # Metrics
    volumes:
      - ./otel-config.yaml:/etc/otelcol/config.yaml:ro
    command: ["--config=/etc/otelcol/config.yaml"]
  
  # Telegen Agent
  telegen-agent:
    image: ghcr.io/platformbuilds/telegen:latest
    container_name: telegen-agent
    restart: unless-stopped
    privileged: true
    pid: host
    network_mode: host
    depends_on:
      - otel-collector
    
    environment:
      - TELEGEN_OTLP_ENDPOINT=localhost:4317
    
    volumes:
      - /sys:/sys:ro
      - /proc:/host/proc:ro
      - /sys/kernel/debug:/sys/kernel/debug
      - /sys/fs/bpf:/sys/fs/bpf
      - ./agent-config.yaml:/etc/telegen/config.yaml:ro
    
    command: ["--config=/etc/telegen/config.yaml", "--mode=agent"]
  
  # Telegen Collector (optional)
  telegen-collector:
    image: ghcr.io/platformbuilds/telegen:latest
    container_name: telegen-collector
    restart: unless-stopped
    depends_on:
      - otel-collector
    
    ports:
      - "162:162/udp"
    
    environment:
      - TELEGEN_OTLP_ENDPOINT=otel-collector:4317
    
    volumes:
      - ./collector-config.yaml:/etc/telegen/config.yaml:ro
    
    command: ["--config=/etc/telegen/config.yaml", "--mode=collector"]
```

---

## Configuration Files

### Agent Configuration (agent-config.yaml)

```yaml
telegen:
  mode: agent
  service_name: telegen
  log_level: info

otlp:
  endpoint: "localhost:4317"
  protocol: grpc
  insecure: true

agent:
  ebpf:
    enabled: true
    network:
      enabled: true
      http: true
      grpc: true
      dns: true
    syscalls:
      enabled: true
  
  profiling:
    enabled: true
    sample_rate: 99
    cpu: true
    off_cpu: true
    memory: true
  
  discovery:
    enabled: true
    interval: 30s
  
  security:
    enabled: true
    syscall_audit: true
    file_integrity: true
```

### Collector Configuration (collector-config.yaml)

```yaml
telegen:
  mode: collector
  service_name: telegen-collector
  log_level: info

otlp:
  endpoint: "otel-collector:4317"
  protocol: grpc
  insecure: true

collector:
  snmp:
    enabled: true
    poll_interval: 60s
    
    targets:
      - name: "core-switch"
        address: "10.0.1.1:161"
        version: "v3"
        security:
          user: "monitor"
          auth_protocol: "SHA256"
          auth_password: "${SNMP_AUTH_PASSWORD}"
          priv_protocol: "AES256"
          priv_password: "${SNMP_PRIV_PASSWORD}"
        modules:
          - if_mib
          - entity_mib
    
    trap_receiver:
      enabled: true
      listen_address: ":162"
  
  storage:
    dell:
      enabled: true
      targets:
        - name: "powerstore-01"
          address: "https://10.0.10.100"
          username: "monitor"
          password: "${DELL_PASSWORD}"
```

### OTel Collector Configuration (otel-config.yaml)

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 10s
    send_batch_size: 1000

exporters:
  debug:
    verbosity: detailed
  
  # Add your backend exporters here
  # otlp/jaeger:
  #   endpoint: jaeger:4317

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TELEGEN_OTLP_ENDPOINT` | OTLP endpoint | `localhost:4317` |
| `TELEGEN_OTLP_PROTOCOL` | Protocol (grpc/http) | `grpc` |
| `TELEGEN_LOG_LEVEL` | Log level | `info` |
| `TELEGEN_MODE` | agent or collector | `agent` |
| `TELEGEN_SERVICE_NAME` | Service name | `telegen` |

---

## Volume Mounts

### Required for Agent Mode

| Host Path | Container Path | Mode | Purpose |
|-----------|----------------|------|---------|
| `/sys` | `/sys` | ro | Kernel info |
| `/proc` | `/host/proc` | ro | Process info |
| `/sys/kernel/debug` | `/sys/kernel/debug` | rw | eBPF debugfs |
| `/sys/fs/bpf` | `/sys/fs/bpf` | rw | BPF filesystem |

### Optional

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `/var/log` | `/var/log` | Log collection |
| `/var/run/docker.sock` | `/var/run/docker.sock` | Container discovery |

---

## Commands

### Start

```bash
docker compose up -d
```

### Stop

```bash
docker compose down
```

### View Logs

```bash
docker compose logs -f telegen
```

### Check Status

```bash
docker compose ps
```

### Check Health

```bash
curl http://localhost:8080/healthz
```

### View Metrics

```bash
curl http://localhost:19090/metrics
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs telegen

# Verify privileged mode
docker inspect telegen | grep -i privileged
```

### eBPF Errors

```bash
# Check kernel version
uname -r

# Check BPF filesystem
mount | grep bpf

# Check BTF availability
ls /sys/kernel/btf/vmlinux
```

### No Telemetry

```bash
# Test OTLP connectivity
docker exec telegen wget -q -O- http://otel-collector:4317/health

# Check agent health
docker exec telegen wget -q -O- http://localhost:8080/healthz
```

---

## Next Steps

- {doc}`linux` - systemd installation
- {doc}`../configuration/index` - Configuration reference
