# Upgrading Telegen

Guide for upgrading Telegen to new versions.

## Version Compatibility

### Semantic Versioning

Telegen follows semantic versioning:

- **Major (X.0.0)** - Breaking changes, migration may be required
- **Minor (0.X.0)** - New features, backward compatible
- **Patch (0.0.X)** - Bug fixes, backward compatible

### Upgrade Path

| From | To | Notes |
|------|-----|-------|
| 1.x | 2.x | Config migration required |
| 2.0.x | 2.1.x | Direct upgrade |
| 2.x | 3.0.0 | Add `pipeline:` section, review data quality limits |
| 3.0.x | 3.y | Direct upgrade |

---

## Pre-Upgrade Checklist

Before upgrading:

1. **Backup configuration**
   ```bash
   cp /etc/telegen/config.yaml /etc/telegen/config.yaml.backup
   ```

2. **Check release notes**
   - Review [CHANGELOG.md](https://github.com/platformbuilds/telegen/blob/main/CHANGELOG.md)
   - Note breaking changes

3. **Test in staging**
   - Deploy new version in staging first
   - Verify metrics and traces flow correctly

4. **Plan rollback**
   - Keep previous version available
   - Document rollback procedure

---

## Kubernetes Upgrade

### Using Helm

```bash
# Check current version
helm list -n monitoring

# Update Helm repo
helm repo update

# Check available versions
helm search repo telegen --versions

# Upgrade
helm upgrade telegen oci://ghcr.io/platformbuilds/charts/telegen \
  --namespace monitoring \
  --version 3.0.0 \
  --reuse-values

# Or with new values
helm upgrade telegen oci://ghcr.io/platformbuilds/charts/telegen \
  --namespace monitoring \
  --version 3.0.0 \
  -f values.yaml
```

### Rolling Update (DaemonSet)

Helm manages the rolling update. Monitor progress:

```bash
# Watch rollout
kubectl rollout status daemonset/telegen -n monitoring

# Check pods
kubectl get pods -l app=telegen -n monitoring -w
```

### Rollback

```bash
# List revisions
helm history telegen -n monitoring

# Rollback to previous
helm rollback telegen -n monitoring

# Rollback to specific revision
helm rollback telegen 3 -n monitoring
```

---

## Docker Upgrade

### Pull New Image

```bash
# Pull latest
docker pull ghcr.io/platformbuilds/telegen:latest

# Or specific version
docker pull ghcr.io/platformbuilds/telegen:3.0.0
```

### Replace Container

```bash
# Stop current
docker stop telegen
docker rm telegen

# Start new version
docker run -d --name telegen \
  --privileged --pid=host --network=host \
  -v /sys:/sys:ro \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/telegen:/etc/telegen:ro \
  ghcr.io/platformbuilds/telegen:3.0.0
```

### Docker Compose

```yaml
# docker-compose.yaml
services:
  telegen:
    image: ghcr.io/platformbuilds/telegen:3.0.0
    # ... rest of config
```

```bash
docker compose pull
docker compose up -d
```

---

## Linux Package Upgrade

### Download New Binary

```bash
# Get latest version
VERSION=$(curl -s https://api.github.com/repos/platformbuilds/telegen/releases/latest | jq -r .tag_name)

# Download
curl -LO "https://github.com/platformbuilds/telegen/releases/download/${VERSION}/telegen_linux_amd64.tar.gz"

# Extract
tar -xzf telegen_linux_amd64.tar.gz
```

### Upgrade with Systemd

```bash
# Stop service
sudo systemctl stop telegen

# Backup old binary
sudo mv /usr/local/bin/telegen /usr/local/bin/telegen.old

# Install new binary
sudo mv telegen /usr/local/bin/
sudo chmod +x /usr/local/bin/telegen

# Verify
telegen version

# Start service
sudo systemctl start telegen

# Check status
sudo systemctl status telegen
```

### Rollback

```bash
sudo systemctl stop telegen
sudo mv /usr/local/bin/telegen.old /usr/local/bin/telegen
sudo systemctl start telegen
```

---

## Configuration Migration

### Version 1.x to 2.x

Major changes in 2.0:

| 1.x Config | 2.x Config |
|------------|------------|
| `exporter.endpoint` | `otlp.endpoint` |
| `exporter.insecure` | `otlp.insecure` |
| `ebpf.buffer_size` | `agent.ebpf.ringbuf_size` |
| `profiler.enabled` | `agent.profiling.enabled` |

**Migration script:**

```bash
# Backup
cp /etc/telegen/config.yaml /etc/telegen/config-v1.yaml.backup

# Migrate (example)
sed -i 's/exporter:/otlp:/g' /etc/telegen/config.yaml
sed -i 's/ebpf:/agent:\n  ebpf:/g' /etc/telegen/config.yaml
```

**Recommended:** Create new config from template and migrate values manually.

---

## Zero-Downtime Upgrade

### Blue-Green with Kubernetes

```yaml
# Deploy new version alongside old
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: telegen-v2
spec:
  selector:
    matchLabels:
      app: telegen
      version: v2
  template:
    metadata:
      labels:
        app: telegen
        version: v2
    spec:
      containers:
        - name: telegen
          image: ghcr.io/platformbuilds/telegen:3.0.0
```

Steps:
1. Deploy new DaemonSet (telegen-v2)
2. Verify new pods are healthy
3. Delete old DaemonSet (telegen-v1)

### Canary Deployment

```yaml
# Deploy to subset of nodes
spec:
  template:
    spec:
      nodeSelector:
        telegen-canary: "true"
```

Steps:
1. Label canary nodes: `kubectl label node node1 telegen-canary=true`
2. Deploy new version to canary
3. Monitor for issues
4. Gradually expand to all nodes

---

## Post-Upgrade Verification

### Check Version

```bash
# Binary
telegen version

# Container
kubectl exec -it telegen-xxx -- telegen version

# API
curl http://localhost:19090/status | jq .version
```

### Verify Metrics Flow

```bash
# Check export metrics
curl -s http://localhost:19090/metrics | grep telegen_export

# Verify in backend
# Query your observability platform for recent data
```

### Verify eBPF Programs

```bash
# Check programs loaded
bpftool prog list | grep -c telegen

# Compare with expected count
curl -s http://localhost:19090/status | jq .ebpf.programs_loaded
```

### Check for Errors

```bash
# Logs
kubectl logs -l app=telegen -n monitoring --tail=100 | grep -i error

# Metrics
curl -s http://localhost:19090/metrics | grep -E "error|fail"
```

---

## Troubleshooting Upgrades

### Pods Not Starting After Upgrade

```bash
# Check events
kubectl describe pod telegen-xxx -n monitoring

# Common issues:
# - Image pull errors
# - Resource limits changed
# - Config incompatibility
```

### eBPF Programs Not Loading

```bash
# Check logs for eBPF errors
kubectl logs telegen-xxx -n monitoring | grep -i ebpf

# Possible causes:
# - Kernel version compatibility
# - BTF changes
# - New security restrictions
```

### Missing Metrics After Upgrade

```bash
# Check if collectors changed
curl -s http://localhost:19090/metrics | grep telegen | head -20

# Verify config applied
kubectl get configmap telegen-config -o yaml
```

---

## Version-Specific Notes

### Upgrading to 3.0.0

Key changes:
- **Unified Pipeline Architecture**: All signals (metrics, traces, logs, profiles) flow through a single configurable pipeline
- **Data Quality Controls**: Built-in cardinality limiting, rate limiting, and attribute limits
- **Signal Transformation**: Rule-based transformations with PII redaction support
- **Hot Reload**: Configuration changes without restart (SIGHUP support)
- **Graceful Shutdown**: Drain in-flight data on shutdown

Configuration changes:
- New `pipeline:` section replaces legacy V2 direct exports
- Unified `limits:` configuration for data quality
- New `transform:` section for signal modification
- New `pii_redaction:` for automatic PII detection and masking

Required actions:
1. Add `pipeline:` section to configuration
2. Review and configure data quality limits
3. Test PII redaction rules if handling sensitive data
4. Verify OTLP connectivity with new export paths

**Migration example:**

```yaml
# Add to existing config
pipeline:
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
      protected_attributes:
        - service.name
        - k8s.namespace.name
  
  transform:
    enabled: true
    rules:
      - name: add-environment
        match:
          signal_types: [metrics, traces, logs]
        actions:
          - type: set_attribute
            set_attribute:
              key: environment
              value: production
  
  operations:
    hot_reload:
      enabled: true
      enable_sighup: true
    shutdown:
      timeout: 30s
      drain_timeout: 10s
```

### Upgrading to 2.1.0

Key changes:
- New profiling features
- SNMP v3 support
- Performance improvements

Required actions:
1. No breaking changes
2. Review new configuration options
3. Update Helm values if desired

---

## Next Steps

- {doc}`monitoring` - Monitor the upgrade
- {doc}`troubleshooting` - Fix any issues
- {doc}`../configuration/full-reference` - Review new config options
