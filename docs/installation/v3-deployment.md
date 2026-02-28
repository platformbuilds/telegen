# V3 Pipeline Deployment Guide

Complete deployment guide for Telegen V3 unified pipeline across all environments.

## Overview

The V3 pipeline provides a unified data path for metrics, traces, and logs with:

- **Data Quality Controls**: Cardinality limiting, rate limiting, attribute limits
- **Signal Transformation**: Rule-based transformations with PII redaction
- **Flexible Export**: Multi-endpoint failover, persistent queuing
- **Hot Reload**: Configuration changes without restart
- **Graceful Shutdown**: Drain in-flight data on shutdown

---

## Configuration Reference

All V3 features are configured under the `v3_pipeline` section:

```yaml
v3_pipeline:
  enabled: true
  
  limits:
    cardinality:
      enabled: true
      default_max_series: 10000
      global_max_series: 100000
    rate:
      enabled: true
      metrics_per_second: 100000
      traces_per_second: 50000
      logs_per_second: 200000
    attributes:
      enabled: true
      max_resource_attributes: 128
      max_attribute_value_size: 4096
  
  transform:
    enabled: true
    rules:
      - name: add-environment
        actions:
          - type: set_attribute
            set_attribute:
              key: environment
              value: production
  
  pii_redaction:
    enabled: true
    scan_log_bodies: true
  
  export:
    otlp:
      endpoint: otel-collector:4317
    batch:
      size: 1000
      timeout: 5s
  
  operations:
    hot_reload:
      enabled: true
      enable_sighup: true
    shutdown:
      timeout: 30s
      drain_timeout: 10s
```

---

## Bare Metal / Virtual Machines

### systemd Deployment

This is the recommended method for Linux servers, VMs, and bare-metal hosts.

#### Prerequisites

- Linux kernel 4.18+ (5.8+ recommended for full eBPF support)
- systemd
- Root access or CAP_BPF/CAP_SYS_ADMIN capabilities
- Network access to OTLP endpoint

#### Step 1: Download Binary

```bash
# Latest version
VERSION=$(curl -s https://api.github.com/repos/platformbuilds/telegen/releases/latest \
  | grep tag_name | cut -d '"' -f4 | sed 's/release\/mark-v//')

# Download (amd64)
curl -LO "https://github.com/platformbuilds/telegen/releases/download/release/mark-v${VERSION}/telegen-linux-amd64.tar.gz"
tar xzf telegen-linux-amd64.tar.gz
sudo mv telegen-linux-amd64 /usr/local/bin/telegen
sudo chmod +x /usr/local/bin/telegen

# Verify
telegen --version
```

For ARM64:
```bash
curl -LO "https://github.com/platformbuilds/telegen/releases/download/release/mark-v${VERSION}/telegen-linux-arm64.tar.gz"
```

#### Step 2: Create V3 Configuration

```bash
sudo mkdir -p /etc/telegen

cat << 'EOF' | sudo tee /etc/telegen/config.yaml
telegen:
  mode: agent
  service_name: telegen
  log_level: info

# V3 Pipeline Configuration
v3_pipeline:
  enabled: true
  
  limits:
    cardinality:
      enabled: true
      default_max_series: 10000
      global_max_series: 100000
      series_ttl: 1h
    rate:
      enabled: true
      metrics_per_second: 100000
      traces_per_second: 50000
      logs_per_second: 200000
    attributes:
      enabled: true
      max_resource_attributes: 128
      max_attribute_value_size: 4096
      protected_attributes:
        - service.name
        - host.name
  
  pii_redaction:
    enabled: true
    scan_log_bodies: true
    rules:
      - name: email
        type: email
        enabled: true
      - name: ssn
        type: ssn
        enabled: true

  transform:
    enabled: true
    rules:
      - name: add-host-info
        match:
          signal_types: [metrics, traces, logs]
        actions:
          - type: set_attribute
            set_attribute:
              key: deployment.environment
              value: ${TELEGEN_ENVIRONMENT:-production}

  export:
    otlp:
      endpoint: ${TELEGEN_OTLP_ENDPOINT:-otel-collector:4317}
      insecure: ${TELEGEN_OTLP_INSECURE:-true}
    batch:
      size: 1000
      timeout: 5s
    queue:
      enabled: true
      directory: /var/lib/telegen/queue
      max_size_bytes: 500000000

  operations:
    hot_reload:
      enabled: true
      config_path: /etc/telegen/config.yaml
      check_interval: 30s
      enable_sighup: true
    shutdown:
      timeout: 30s
      drain_timeout: 10s

# Agent configuration
agent:
  ebpf:
    enabled: true
    network:
      enabled: true
      http: true
      grpc: true
    syscalls:
      enabled: true
  profiling:
    enabled: true
    cpu: true
    memory: true
  discovery:
    enabled: true
    interval: 30s

self_telemetry:
  enabled: true
  listen: ":19090"
EOF
```

#### Step 3: Environment File

```bash
cat << 'EOF' | sudo tee /etc/telegen/telegen.env
# OTLP endpoint
TELEGEN_OTLP_ENDPOINT=otel-collector.example.com:4317
TELEGEN_OTLP_INSECURE=false

# Environment tag
TELEGEN_ENVIRONMENT=production

# Optional: API authentication
# OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer your-token

# Logging
TELEGEN_LOG_LEVEL=info
EOF

sudo chmod 600 /etc/telegen/telegen.env
```

#### Step 4: systemd Service

```bash
cat << 'EOF' | sudo tee /etc/systemd/system/telegen.service
[Unit]
Description=Telegen V3 Observability Agent
Documentation=https://telegen.mirastacklabs.ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

EnvironmentFile=/etc/telegen/telegen.env
ExecStart=/usr/local/bin/telegen --config=/etc/telegen/config.yaml
ExecReload=/bin/kill -HUP $MAINPID

Restart=always
RestartSec=5
LimitNOFILE=65536
LimitMEMLOCK=infinity

# eBPF capabilities
AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH
NoNewPrivileges=false

StandardOutput=journal
StandardError=journal
SyslogIdentifier=telegen

[Install]
WantedBy=multi-user.target
EOF
```

#### Step 5: Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable telegen
sudo systemctl start telegen

# Check status
sudo systemctl status telegen

# View logs
sudo journalctl -u telegen -f
```

#### Hot Reload Configuration

```bash
# Edit configuration
sudo vim /etc/telegen/config.yaml

# Reload without restart
sudo systemctl reload telegen
# Or send SIGHUP directly
sudo kill -HUP $(pidof telegen)
```

---

## Docker Compose

### Single Node Agent

```yaml
# docker-compose.yaml
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
      - TELEGEN_ENVIRONMENT=production
      - TELEGEN_LOG_LEVEL=info
    
    volumes:
      - /sys:/sys:ro
      - /proc:/host/proc:ro
      - /sys/kernel/debug:/sys/kernel/debug
      - /sys/fs/bpf:/sys/fs/bpf
      - ./configs/telegen.yaml:/etc/telegen/config.yaml:ro
      - telegen-queue:/var/lib/telegen/queue
    
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:19090/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  telegen-queue:
```

### Full Observability Stack

```yaml
# docker-compose.full.yaml
version: '3.8'

services:
  # Telegen Agent
  telegen:
    image: ghcr.io/platformbuilds/telegen:latest
    container_name: telegen
    restart: unless-stopped
    privileged: true
    pid: host
    network_mode: host
    environment:
      - TELEGEN_OTLP_ENDPOINT=localhost:4317
    volumes:
      - /sys:/sys:ro
      - /proc:/host/proc:ro
      - /sys/kernel/debug:/sys/kernel/debug
      - /sys/fs/bpf:/sys/fs/bpf
      - ./configs/agent.yaml:/etc/telegen/config.yaml:ro

  # OpenTelemetry Collector
  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    container_name: otel-collector
    restart: unless-stopped
    command: ["--config=/etc/otel/config.yaml"]
    volumes:
      - ./configs/otel-collector.yaml:/etc/otel/config.yaml:ro
    ports:
      - "4317:4317"   # OTLP gRPC
      - "4318:4318"   # OTLP HTTP
      - "8888:8888"   # Metrics

  # Prometheus
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-remote-write-receiver'
    volumes:
      - ./configs/prometheus.yaml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"

  # Loki
  loki:
    image: grafana/loki:latest
    container_name: loki
    restart: unless-stopped
    command: -config.file=/etc/loki/config.yaml
    volumes:
      - ./configs/loki.yaml:/etc/loki/config.yaml:ro
      - loki-data:/loki
    ports:
      - "3100:3100"

  # Grafana
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
    ports:
      - "3000:3000"

volumes:
  prometheus-data:
  loki-data:
  grafana-data:
```

### Collector Mode (Non-eBPF)

```yaml
# docker-compose.collector.yaml
version: '3.8'

services:
  telegen-collector:
    image: ghcr.io/platformbuilds/telegen:latest
    container_name: telegen-collector
    restart: unless-stopped
    
    environment:
      - TELEGEN_OTLP_ENDPOINT=otel-collector:4317
    
    volumes:
      - ./configs/collector.yaml:/etc/telegen/config.yaml:ro
    
    ports:
      - "19090:19090"  # Health/metrics
    
    # No privileged mode needed for collector mode
```

With collector config:

```yaml
# configs/collector.yaml
telegen:
  mode: collector
  service_name: telegen-collector

v3_pipeline:
  enabled: true
  limits:
    cardinality:
      enabled: true
      default_max_series: 50000
  pii_redaction:
    enabled: true
  export:
    otlp:
      endpoint: ${TELEGEN_OTLP_ENDPOINT}

collectors:
  prometheus:
    enabled: true
    scrape_interval: 30s
    targets:
      - name: node-exporter
        address: node-exporter:9100
      - name: cadvisor
        address: cadvisor:8080
        metrics_path: /metrics
```

---

## Kubernetes

### DaemonSet (Agent Mode)

```yaml
# telegen-daemonset.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: telegen
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: telegen
  namespace: telegen
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: telegen
rules:
  - apiGroups: [""]
    resources: ["nodes", "pods", "services", "endpoints", "namespaces", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["nodes/proxy", "nodes/stats"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: telegen
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: telegen
subjects:
  - kind: ServiceAccount
    name: telegen
    namespace: telegen
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: telegen-config
  namespace: telegen
data:
  config.yaml: |
    telegen:
      mode: agent
      service_name: telegen
      log_level: info
    
    v3_pipeline:
      enabled: true
      
      limits:
        cardinality:
          enabled: true
          default_max_series: 10000
          global_max_series: 100000
        rate:
          enabled: true
          metrics_per_second: 100000
        attributes:
          enabled: true
          protected_attributes:
            - service.name
            - k8s.namespace.name
            - k8s.pod.name
      
      pii_redaction:
        enabled: true
        scan_log_bodies: true
      
      transform:
        enabled: true
        rules:
          - name: add-cluster
            match:
              signal_types: [metrics, traces, logs]
            actions:
              - type: set_attribute
                set_attribute:
                  key: k8s.cluster.name
                  value: ${CLUSTER_NAME}
      
      export:
        otlp:
          endpoint: ${OTLP_ENDPOINT}
          insecure: true
        batch:
          size: 1000
          timeout: 5s
        queue:
          enabled: true
          directory: /var/lib/telegen/queue
          max_size_bytes: 100000000
      
      operations:
        hot_reload:
          enabled: true
          enable_sighup: true
        shutdown:
          timeout: 30s
          drain_timeout: 10s
    
    agent:
      ebpf:
        enabled: true
        network:
          enabled: true
      profiling:
        enabled: true
      discovery:
        enabled: true
    
    kube_metrics:
      enabled: true
    
    self_telemetry:
      enabled: true
      listen: ":19090"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: telegen
  namespace: telegen
  labels:
    app: telegen
spec:
  selector:
    matchLabels:
      app: telegen
  template:
    metadata:
      labels:
        app: telegen
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "19090"
    spec:
      serviceAccountName: telegen
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      
      tolerations:
        - operator: Exists
          effect: NoSchedule
        - operator: Exists
          effect: NoExecute
      
      containers:
        - name: telegen
          image: ghcr.io/platformbuilds/telegen:latest
          imagePullPolicy: IfNotPresent
          
          args:
            - --config=/etc/telegen/config.yaml
          
          env:
            - name: OTLP_ENDPOINT
              value: "otel-collector.observability:4317"
            - name: CLUSTER_NAME
              value: "production"
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 1Gi
          
          securityContext:
            privileged: true
          
          volumeMounts:
            - name: config
              mountPath: /etc/telegen
              readOnly: true
            - name: sys
              mountPath: /sys
              readOnly: true
            - name: proc
              mountPath: /host/proc
              readOnly: true
            - name: debugfs
              mountPath: /sys/kernel/debug
            - name: bpffs
              mountPath: /sys/fs/bpf
            - name: queue
              mountPath: /var/lib/telegen/queue
          
          livenessProbe:
            httpGet:
              path: /healthz
              port: 19090
            initialDelaySeconds: 30
            periodSeconds: 30
          
          readinessProbe:
            httpGet:
              path: /readyz
              port: 19090
            initialDelaySeconds: 10
            periodSeconds: 10
      
      volumes:
        - name: config
          configMap:
            name: telegen-config
        - name: sys
          hostPath:
            path: /sys
        - name: proc
          hostPath:
            path: /proc
        - name: debugfs
          hostPath:
            path: /sys/kernel/debug
        - name: bpffs
          hostPath:
            path: /sys/fs/bpf
        - name: queue
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: telegen
  namespace: telegen
  labels:
    app: telegen
spec:
  type: ClusterIP
  ports:
    - name: metrics
      port: 19090
      targetPort: 19090
  selector:
    app: telegen
```

### Apply to Cluster

```bash
# Create resources
kubectl apply -f telegen-daemonset.yaml

# Verify
kubectl -n telegen get pods
kubectl -n telegen logs -l app=telegen -f

# Check health
kubectl -n telegen exec ds/telegen -- curl -s localhost:19090/healthz
```

---

## Helm

### Quick Start

```bash
# Add repository
helm repo add telegen https://charts.mirastacklabs.ai
helm repo update

# Install with defaults
helm install telegen telegen/telegen -n telegen --create-namespace

# Install with custom values
helm install telegen telegen/telegen -n telegen --create-namespace \
  --set otlp.endpoint=otel-collector:4317 \
  --set v3Pipeline.enabled=true \
  --set v3Pipeline.limits.cardinality.enabled=true
```

### Custom Values

```yaml
# values.yaml
replicaCount: 1  # For DaemonSet, this is ignored

image:
  repository: ghcr.io/platformbuilds/telegen
  tag: latest
  pullPolicy: IfNotPresent

# OTLP configuration
otlp:
  endpoint: otel-collector.observability:4317
  insecure: true
  headers: {}

# V3 Pipeline configuration
v3Pipeline:
  enabled: true
  
  limits:
    cardinality:
      enabled: true
      defaultMaxSeries: 10000
      globalMaxSeries: 100000
    rate:
      enabled: true
      metricsPerSecond: 100000
      tracesPerSecond: 50000
      logsPerSecond: 200000
    attributes:
      enabled: true
      maxResourceAttributes: 128
      protectedAttributes:
        - service.name
        - k8s.namespace.name
  
  piiRedaction:
    enabled: true
    scanLogBodies: true
  
  transform:
    enabled: true
    rules:
      - name: add-cluster
        actions:
          - type: set_attribute
            setAttribute:
              key: k8s.cluster.name
              value: "production"
  
  export:
    batch:
      size: 1000
      timeout: 5s
    queue:
      enabled: true
      maxSizeBytes: 100000000
  
  operations:
    hotReload:
      enabled: true
    shutdown:
      timeout: 30s

# Agent configuration
agent:
  ebpf:
    enabled: true
    network: true
  profiling:
    enabled: true
  discovery:
    enabled: true

# Resources
resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 1Gi

# Pod tolerations for scheduling on all nodes
tolerations:
  - operator: Exists
    effect: NoSchedule
  - operator: Exists
    effect: NoExecute

# Service monitor for Prometheus Operator
serviceMonitor:
  enabled: true
  interval: 30s
```

### Install with Values File

```bash
helm install telegen telegen/telegen -n telegen --create-namespace -f values.yaml
```

---

## OpenShift

OpenShift requires additional security context constraints (SCC).

### Create SCC

```yaml
# telegen-scc.yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: telegen-scc
allowHostDirVolumePlugin: true
allowHostIPC: true
allowHostNetwork: true
allowHostPID: true
allowHostPorts: true
allowPrivilegedContainer: true
allowedCapabilities:
  - SYS_ADMIN
  - SYS_PTRACE
  - NET_ADMIN
  - BPF
  - PERFMON
  - SYS_RESOURCE
  - DAC_READ_SEARCH
fsGroup:
  type: RunAsAny
readOnlyRootFilesystem: false
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: RunAsAny
supplementalGroups:
  type: RunAsAny
users:
  - system:serviceaccount:telegen:telegen
volumes:
  - '*'
```

### Apply and Deploy

```bash
# Create SCC
oc apply -f telegen-scc.yaml

# Create project
oc new-project telegen

# Deploy (use the Kubernetes DaemonSet YAML from above)
oc apply -f telegen-daemonset.yaml

# Verify
oc get pods -n telegen
```

---

## AWS ECS

### Task Definition

```json
{
  "family": "telegen",
  "networkMode": "host",
  "pidMode": "host",
  "requiresCompatibilities": ["EC2"],
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/telegenTaskRole",
  "containerDefinitions": [
    {
      "name": "telegen",
      "image": "ghcr.io/platformbuilds/telegen:latest",
      "essential": true,
      "privileged": true,
      "environment": [
        {"name": "TELEGEN_OTLP_ENDPOINT", "value": "otel-collector.internal:4317"},
        {"name": "TELEGEN_ENVIRONMENT", "value": "production"}
      ],
      "mountPoints": [
        {"sourceVolume": "sys", "containerPath": "/sys", "readOnly": true},
        {"sourceVolume": "proc", "containerPath": "/host/proc", "readOnly": true},
        {"sourceVolume": "debugfs", "containerPath": "/sys/kernel/debug"},
        {"sourceVolume": "bpffs", "containerPath": "/sys/fs/bpf"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/telegen",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "telegen"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:19090/healthz || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      },
      "cpu": 256,
      "memory": 512
    }
  ],
  "volumes": [
    {"name": "sys", "host": {"sourcePath": "/sys"}},
    {"name": "proc", "host": {"sourcePath": "/proc"}},
    {"name": "debugfs", "host": {"sourcePath": "/sys/kernel/debug"}},
    {"name": "bpffs", "host": {"sourcePath": "/sys/fs/bpf"}}
  ]
}
```

### Service (Daemon Scheduling)

```json
{
  "serviceName": "telegen",
  "cluster": "production",
  "taskDefinition": "telegen",
  "schedulingStrategy": "DAEMON",
  "deploymentConfiguration": {
    "maximumPercent": 100,
    "minimumHealthyPercent": 0
  }
}
```

---

## Verification

After deployment, verify Telegen is working:

```bash
# Check health
curl http://localhost:19090/healthz
# Expected: {"status":"healthy"}

# Check readiness
curl http://localhost:19090/readyz
# Expected: {"status":"ready"}

# Check metrics
curl http://localhost:19090/metrics | head -20

# Check V3 pipeline stats
curl http://localhost:19090/debug/v3/stats

# View logs
# systemd: journalctl -u telegen -f
# Docker: docker logs telegen -f
# Kubernetes: kubectl -n telegen logs -l app=telegen -f
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| eBPF not starting | Missing capabilities | Run privileged or add CAP_BPF |
| No metrics exported | OTLP endpoint unreachable | Check network/firewall |
| High memory usage | Cardinality explosion | Enable cardinality limits |
| Config not reloading | SIGHUP not working | Check `hot_reload.enabled` |
| Data loss on restart | No persistent queue | Enable `queue.enabled` |

### Debug Commands

```bash
# Check kernel version
uname -r  # Must be 4.18+

# Check eBPF support
ls /sys/fs/bpf

# Check capabilities (container)
capsh --print

# Test OTLP connectivity
nc -zv otel-collector 4317
```

### Logs

```bash
# Increase log level
# In config.yaml: log_level: debug

# Filter errors only
journalctl -u telegen | grep -i error
```

---

## Next Steps

- {doc}`/configuration/full-reference` - Complete configuration reference
- {doc}`/features/index` - Feature documentation
- {doc}`/operations/monitoring` - Monitoring Telegen itself
- {doc}`/operations/performance-tuning` - Optimization guide
