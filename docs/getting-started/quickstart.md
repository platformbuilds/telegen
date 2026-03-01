# Quick Start Guide

Get Telegen running in under 5 minutes with zero configuration.

## Overview

Telegen is designed to work out-of-the-box. The only required configuration is your OpenTelemetry endpoint—everything else is automatically discovered.

```yaml
# Minimal configuration - just the endpoint!
telegen:
  otlp:
    endpoint: "otel-collector:4317"
```

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 200m (0.2 cores) | 1 core |
| Memory | 256 MB | 1 GB |
| Disk | 100 MB | 500 MB |
| Kernel | 4.18+ | 5.8+ |

### Kernel Requirements

Telegen requires Linux with eBPF support:

- **Minimum**: Linux 4.18 (basic eBPF)
- **Recommended**: Linux 5.8+ (CO-RE, BTF)
- **Optimal**: Linux 5.15+ (ring buffer, improved performance)

Verify your setup:

```bash
# Check kernel version
uname -r

# Check for BTF support (recommended)
ls /sys/kernel/btf/vmlinux

# Check BPF filesystem
mount | grep bpf
```

---

## Installation Methods

### Kubernetes (Recommended)

::::{tab-set}

:::{tab-item} Helm
```bash
helm install telegen oci://ghcr.io/mirastacklabs-ai/charts/telegen \
  --namespace telegen --create-namespace \
  --set otlp.endpoint="otel-collector.observability:4317"
```
:::

:::{tab-item} kubectl
```bash
kubectl apply -f https://raw.githubusercontent.com/mirastacklabs-ai/telegen/main/deployments/kubernetes/rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/mirastacklabs-ai/telegen/main/deployments/kubernetes/configmap.yaml
kubectl apply -f https://raw.githubusercontent.com/mirastacklabs-ai/telegen/main/deployments/kubernetes/daemonset.yaml
```
:::

::::

### Linux

```bash
# Download latest release
VERSION=$(curl -s https://api.github.com/repos/mirastacklabs-ai/telegen/releases/latest | grep tag_name | cut -d '"' -f4)
VERSION=${VERSION#release/mark-v}  # Strip prefix

# Download and install
curl -LO "https://github.com/mirastacklabs-ai/telegen/releases/download/release/mark-v${VERSION}/telegen-linux-amd64.tar.gz"
tar xzf telegen-linux-amd64.tar.gz
sudo mv telegen-linux-amd64 /usr/local/bin/telegen
sudo chmod +x /usr/local/bin/telegen

# Create minimal config and run
sudo mkdir -p /etc/telegen
echo 'otlp:
  endpoint: "otel-collector:4317"' | sudo tee /etc/telegen/config.yaml
sudo telegen --config /etc/telegen/config.yaml
```

See {doc}`../installation/linux` for systemd service setup.

### Docker

```bash
docker run -d --name telegen \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys:/sys:ro \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e TELEGEN_ENDPOINT=otel-collector:4317 \
  ghcr.io/mirastacklabs-ai/telegen:latest
```

---

## Verify Installation

### Check Agent Status

```bash
# Kubernetes
kubectl get pods -n telegen -l app.kubernetes.io/name=telegen

# Linux
systemctl status telegen

# Docker
docker logs telegen
```

### Check Health Endpoint

```bash
curl http://localhost:8080/healthz
```

Expected response:
```json
{"status": "healthy", "version": "3.0.0"}
```

### Check Metrics

```bash
curl http://localhost:19090/metrics | head -20
```

---

## Targeted Instrumentation (Optional)

By default, Telegen instruments all processes. For targeted instrumentation, use port-based discovery:

```yaml
otlp:
  endpoint: "otel-collector:4317"

discovery:
  instrument:
    # Only instrument services on these ports
    - open_ports: "8080-8089"
    - open_ports: "3000,5000"
```

See {doc}`../features/auto-discovery` for more options including Kubernetes-aware targeting.

---

## What Gets Collected

Once running, Telegen automatically collects:

| Signal | Description | Protocol |
|--------|-------------|----------|
| **Metrics** | Host, container, application metrics | OTLP/Prometheus |
| **Traces** | Distributed traces (HTTP, gRPC, DB) | OTLP |
| **Logs** | System and container logs | OTLP |
| **Profiles** | CPU, memory, off-CPU profiles | OTLP |

### Auto-Discovered Metadata

Telegen automatically enriches all signals with:

- **Cloud Provider**: AWS, GCP, Azure, Alibaba, Oracle, DigitalOcean
- **Kubernetes**: namespace, pod, deployment, node
- **Host**: OS, architecture, kernel version
- **Process**: language runtime, framework detection

---

## Next Steps

- {doc}`../installation/index` - Detailed installation guides
- {doc}`../configuration/index` - Configuration options
- {doc}`../features/index` - Explore all features
