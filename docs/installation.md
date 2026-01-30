# Telegen Installation Guide

This guide covers installation of Telegen across all supported platforms.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Kubernetes Installation](#kubernetes-installation)
- [Helm Installation](#helm-installation)
- [Linux Installation](#linux-installation)
- [Docker Installation](#docker-installation)
- [OpenShift Installation](#openshift-installation)
- [AWS ECS Installation](#aws-ecs-installation)
- [Verification](#verification)

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 200m (0.2 cores) | 1 core |
| Memory | 256 MB | 1 GB |
| Disk | 100 MB | 500 MB |
| Kernel | 4.18+ | 5.8+ |

### Kernel Requirements

Telegen requires a Linux kernel with eBPF support:

- **Minimum**: Linux 4.18 (basic eBPF support)
- **Recommended**: Linux 5.8+ (full CO-RE support, BTF)
- **Optimal**: Linux 5.15+ (BPF ring buffer, improved performance)

Check your kernel version:

```bash
uname -r
```

Verify eBPF support:

```bash
# Check for BPF filesystem
mount | grep bpf

# Check for BTF (recommended)
ls /sys/kernel/btf/vmlinux
```

### Network Requirements

Telegen needs to communicate with your observability backend:

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 4317 | gRPC | Outbound | OTLP gRPC export |
| 4318 | HTTP | Outbound | OTLP HTTP export |
| 19090 | HTTP | Inbound | Self-telemetry metrics |
| 8080 | HTTP | Inbound | Health checks |

## Quick Start

### One-Line Installation (Linux)

```bash
curl -sSL https://get.telegen.io | sudo bash
```

Or with custom options:

```bash
curl -sSL https://get.telegen.io | sudo bash -s -- \
  --otlp-endpoint="http://otel-collector:4317" \
  --enable-profiling \
  --enable-security
```

### One-Line Installation (Kubernetes)

```bash
helm install telegen oci://ghcr.io/platformbuilds/telegen/helm/telegen \
  --namespace telegen --create-namespace \
  --set otlp.endpoint="otel-collector:4317"
```

## Kubernetes Installation

### Using kubectl

1. **Create namespace and apply manifests:**

```bash
kubectl apply -f https://raw.githubusercontent.com/platformbuilds/telegen/main/deployments/kubernetes/rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/platformbuilds/telegen/main/deployments/kubernetes/configmap.yaml
kubectl apply -f https://raw.githubusercontent.com/platformbuilds/telegen/main/deployments/kubernetes/daemonset.yaml
kubectl apply -f https://raw.githubusercontent.com/platformbuilds/telegen/main/deployments/kubernetes/service.yaml
```

2. **Verify deployment:**

```bash
kubectl get pods -n telegen
kubectl logs -n telegen -l app.kubernetes.io/name=telegen
```

### Manual Installation

1. **Download manifests:**

```bash
git clone https://github.com/platformbuilds/telegen.git
cd telegen/deployments/kubernetes
```

2. **Customize configuration:**

Edit `configmap.yaml` to set your OTLP endpoint and features:

```yaml
exports:
  otlp:
    grpc:
      endpoint: "your-otel-collector:4317"
```

3. **Apply manifests:**

```bash
kubectl apply -f .
```

## Helm Installation

### Prerequisites

- Helm 3.8+
- Kubernetes 1.21+

### Installation

1. **Add the Helm repository:**

```bash
helm repo add telegen https://charts.telegen.io
helm repo update
```

2. **Install the chart:**

```bash
helm install telegen telegen/telegen \
  --namespace telegen \
  --create-namespace \
  --set otlp.endpoint="otel-collector.observability:4317"
```

### Installation with Values File

1. **Create a values file (`my-values.yaml`):**

```yaml
otlp:
  endpoint: "otel-collector.observability:4317"
  insecure: true

agent:
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 200m
      memory: 256Mi

features:
  tracing:
    enabled: true
  profiling:
    enabled: true
    cpu:
      sampleRate: 99
  security:
    enabled: true
  network:
    enabled: true
  logs:
    enabled: true

discovery:
  kubernetes:
    enabled: true
```

2. **Install with custom values:**

```bash
helm install telegen telegen/telegen \
  --namespace telegen \
  --create-namespace \
  -f my-values.yaml
```

### Upgrading

```bash
helm repo update
helm upgrade telegen telegen/telegen \
  --namespace telegen \
  -f my-values.yaml
```

### Uninstalling

```bash
helm uninstall telegen --namespace telegen
kubectl delete namespace telegen
```

## Linux Installation

### Automated Installation

```bash
curl -sSL https://raw.githubusercontent.com/platformbuilds/telegen/main/scripts/install-linux.sh | sudo bash
```

With options:

```bash
curl -sSL https://raw.githubusercontent.com/platformbuilds/telegen/main/scripts/install-linux.sh | sudo bash -s -- \
  --otlp-endpoint="http://otel-collector:4317" \
  --enable-profiling \
  --enable-security \
  --enable-logs
```

### Manual Installation

1. **Download the binary:**

```bash
# Detect architecture
ARCH=$(uname -m)
case $ARCH in
  x86_64) ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
esac

# Download
VERSION="v2.0.0"
curl -LO "https://github.com/platformbuilds/telegen/releases/download/${VERSION}/telegen_linux_${ARCH}"
chmod +x "telegen_linux_${ARCH}"
sudo mv "telegen_linux_${ARCH}" /usr/local/bin/telegen
```

2. **Create configuration:**

```bash
sudo mkdir -p /etc/telegen
sudo cat > /etc/telegen/config.yaml << 'EOF'
telegen:
  mode: agent
  service_name: "telegen"

ebpf:
  enabled: true

profiling:
  enabled: true

security:
  enabled: true

exports:
  otlp:
    grpc:
      enabled: true
      endpoint: "localhost:4317"
      insecure: true
EOF
```

3. **Create systemd service:**

```bash
sudo cat > /etc/systemd/system/telegen.service << 'EOF'
[Unit]
Description=Telegen Observability Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/telegen --config=/etc/telegen/config.yaml
Restart=always
RestartSec=10
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
```

4. **Start the service:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable telegen
sudo systemctl start telegen
```

### Uninstalling

```bash
sudo systemctl stop telegen
sudo systemctl disable telegen
sudo rm /etc/systemd/system/telegen.service
sudo rm /usr/local/bin/telegen
sudo rm -rf /etc/telegen /var/lib/telegen
sudo systemctl daemon-reload
```

## Docker Installation

### Quick Start

```bash
docker run -d \
  --name telegen \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
  ghcr.io/platformbuilds/telegen:v2.0.0
```

### Docker Compose

1. **Clone the repository:**

```bash
git clone https://github.com/platformbuilds/telegen.git
cd telegen/deployments/docker
```

2. **Start the full stack:**

```bash
docker-compose up -d
```

This starts:
- Telegen Agent
- Telegen Collector
- OpenTelemetry Collector
- Jaeger (traces)
- Prometheus (metrics)
- Grafana (dashboards)
- Loki (logs)
- Pyroscope (profiles)

3. **Access the UIs:**

| Service | URL |
|---------|-----|
| Grafana | http://localhost:3000 (admin/admin) |
| Jaeger | http://localhost:16686 |
| Prometheus | http://localhost:9090 |
| Pyroscope | http://localhost:4040 |

### Custom Configuration

Mount your own configuration:

```bash
docker run -d \
  --name telegen \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /path/to/config.yaml:/etc/telegen/config.yaml:ro \
  ghcr.io/platformbuilds/telegen:v2.0.0
```

## OpenShift Installation

### Prerequisites

- OpenShift 4.8+
- Cluster admin access (for SCC)

### Installation

1. **Apply SecurityContextConstraints:**

```bash
oc apply -f https://raw.githubusercontent.com/platformbuilds/telegen/main/deployments/openshift/scc.yaml
```

2. **Deploy the agent:**

```bash
oc apply -f https://raw.githubusercontent.com/platformbuilds/telegen/main/deployments/openshift/agent-daemonset.yaml
```

3. **Assign SCC to service account:**

```bash
oc adm policy add-scc-to-user telegen-scc -z telegen -n telegen
```

4. **Verify deployment:**

```bash
oc get pods -n telegen
oc logs -n telegen -l app.kubernetes.io/name=telegen
```

### Troubleshooting OpenShift

If pods fail to start with permission errors:

```bash
# Check SCC assignment
oc get scc telegen-scc -o yaml

# Verify service account
oc describe sa telegen -n telegen

# Check pod events
oc describe pod -n telegen -l app.kubernetes.io/name=telegen
```

## AWS ECS Installation

### Prerequisites

- AWS CLI configured
- ECS cluster with EC2 instances (for agent)
- IAM permissions for task execution

### Installation

1. **Deploy IAM roles:**

```bash
aws cloudformation deploy \
  --template-file deployments/ecs/iam-roles.yaml \
  --stack-name telegen-ecs-iam \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides Environment=production
```

2. **Create secrets:**

```bash
aws secretsmanager create-secret \
  --name telegen/otlp-headers \
  --secret-string '{"Authorization": "Bearer your-token"}'
```

3. **Register task definition:**

```bash
# Replace variables in task definition
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export TASK_ROLE_ARN=$(aws cloudformation describe-stacks --stack-name telegen-ecs-iam --query 'Stacks[0].Outputs[?OutputKey==`AgentTaskRoleArn`].OutputValue' --output text)
export EXECUTION_ROLE_ARN=$(aws cloudformation describe-stacks --stack-name telegen-ecs-iam --query 'Stacks[0].Outputs[?OutputKey==`TaskExecutionRoleArn`].OutputValue' --output text)

envsubst < deployments/ecs/task-definition.json > /tmp/task-def.json
aws ecs register-task-definition --cli-input-json file:///tmp/task-def.json
```

4. **Create daemon service:**

```bash
export ECS_CLUSTER_NAME=your-cluster

envsubst < deployments/ecs/service.json > /tmp/service.json
aws ecs create-service --cli-input-json file:///tmp/service.json
```

### Verification

```bash
# Check task status
aws ecs list-tasks --cluster your-cluster --service-name telegen-agent

# View logs
aws logs tail /ecs/telegen-agent --follow
```

## Verification

After installation, verify Telegen is working correctly:

### Check Health

```bash
# Kubernetes
kubectl exec -n telegen -it $(kubectl get pod -n telegen -l app.kubernetes.io/name=telegen -o jsonpath='{.items[0].metadata.name}') -- wget -qO- http://localhost:8080/healthz

# Linux
curl http://localhost:8080/healthz

# Docker
docker exec telegen wget -qO- http://localhost:8080/healthz
```

### Check Metrics

```bash
# View self-telemetry metrics
curl http://localhost:19090/metrics | head -50
```

### Check Logs

```bash
# Kubernetes
kubectl logs -n telegen -l app.kubernetes.io/name=telegen --tail=100

# Linux
journalctl -u telegen -f

# Docker
docker logs -f telegen
```

### Verify eBPF Programs

```bash
# Check loaded eBPF programs (requires bpftool)
sudo bpftool prog list | grep telegen

# Check eBPF maps
sudo bpftool map list | grep telegen
```

## Next Steps

- [Configuration Reference](configuration.md) - Complete configuration options
- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions
- [Feature Guides](../features/) - Detailed feature documentation
