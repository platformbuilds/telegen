# Telegen Troubleshooting Guide

This guide helps you diagnose and resolve common issues with Telegen.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Installation Issues](#installation-issues)
- [eBPF Issues](#ebpf-issues)
- [Kubernetes Issues](#kubernetes-issues)
- [Export Issues](#export-issues)
- [Performance Issues](#performance-issues)
- [Feature-Specific Issues](#feature-specific-issues)
- [Log Analysis](#log-analysis)
- [Getting Help](#getting-help)

## Quick Diagnostics

### Health Check

```bash
# Check if Telegen is running
curl http://localhost:8080/healthz

# Expected response
{"status":"healthy","checks":{"ebpf":"ok","export":"ok"}}
```

### Check Metrics

```bash
# View key metrics
curl -s http://localhost:19090/metrics | grep -E "(telegen_|up)"

# Important metrics to check:
# - telegen_ebpf_programs_loaded
# - telegen_traces_exported_total
# - telegen_export_errors_total
```

### Check Logs

```bash
# Kubernetes
kubectl logs -n telegen -l app.kubernetes.io/name=telegen --tail=100

# Linux systemd
journalctl -u telegen -n 100 --no-pager

# Docker
docker logs telegen --tail 100
```

### eBPF Program Status

```bash
# List loaded eBPF programs
sudo bpftool prog list | grep -A2 telegen

# List eBPF maps
sudo bpftool map list | grep telegen
```

## Installation Issues

### Issue: Binary Download Fails

**Symptoms:**
- 404 errors during download
- Connection timeout

**Solutions:**

```bash
# Verify network connectivity
curl -I https://github.com

# Try alternative download
wget https://github.com/platformbuilds/telegen/releases/download/v2.0.0/telegen_linux_amd64

# Check for proxy settings
echo $http_proxy $https_proxy
```

### Issue: Permission Denied on Install

**Symptoms:**
- `permission denied` errors
- Installation fails without sudo

**Solutions:**

```bash
# Run with sudo
sudo ./install-linux.sh

# Or install to user directory
./install-linux.sh --prefix=$HOME/.local
```

### Issue: Unsupported Architecture

**Symptoms:**
- `unsupported architecture` error
- Binary doesn't run

**Solutions:**

```bash
# Check architecture
uname -m

# Supported architectures:
# - x86_64 (amd64)
# - aarch64 (arm64)

# For other architectures, build from source
git clone https://github.com/platformbuilds/telegen.git
cd telegen
make build
```

## eBPF Issues

### Issue: eBPF Programs Fail to Load

**Symptoms:**
- `failed to load BPF program` error
- `operation not permitted` error

**Diagnose:**

```bash
# Check kernel version
uname -r

# Check eBPF support
cat /proc/sys/kernel/unprivileged_bpf_disabled

# Check capabilities
cat /proc/self/status | grep Cap
```

**Solutions:**

```bash
# Ensure running as root or with capabilities
sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep /usr/local/bin/telegen

# Mount BPF filesystem
sudo mount -t bpf bpf /sys/fs/bpf

# Check if BPF JIT is enabled
cat /proc/sys/net/core/bpf_jit_enable
# Enable if needed
echo 1 | sudo tee /proc/sys/net/core/bpf_jit_enable
```

### Issue: BTF Not Available

**Symptoms:**
- `BTF is not available` warning
- `failed to find BTF` error

**Diagnose:**

```bash
# Check for BTF
ls -la /sys/kernel/btf/vmlinux
```

**Solutions:**

```bash
# Option 1: Install kernel with BTF
# Ubuntu/Debian
sudo apt install linux-image-generic

# RHEL/CentOS
sudo dnf install kernel-devel

# Option 2: Generate BTF
pahole --btf_encode_detached vmlinux.btf /boot/vmlinux-$(uname -r)
sudo mkdir -p /sys/kernel/btf
sudo cp vmlinux.btf /sys/kernel/btf/vmlinux
```

### Issue: Memory Lock Limit Too Low

**Symptoms:**
- `failed to create map` error
- `ENOMEM` errors

**Solutions:**

```bash
# Check current limit
ulimit -l

# Increase limit temporarily
ulimit -l unlimited

# Permanent fix: Edit /etc/security/limits.conf
echo "* - memlock unlimited" | sudo tee -a /etc/security/limits.conf

# For systemd services
sudo systemctl edit telegen
# Add:
# [Service]
# LimitMEMLOCK=infinity
```

### Issue: debugfs Not Mounted

**Symptoms:**
- `failed to access /sys/kernel/debug/tracing`
- Tracepoint attachment fails

**Solutions:**

```bash
# Mount debugfs
sudo mount -t debugfs debugfs /sys/kernel/debug

# Make it persistent
echo "debugfs /sys/kernel/debug debugfs defaults 0 0" | sudo tee -a /etc/fstab
```

## Kubernetes Issues

### Issue: Pod Stuck in Pending

**Symptoms:**
- Pod never starts
- `Pending` status

**Diagnose:**

```bash
kubectl describe pod -n telegen -l app.kubernetes.io/name=telegen
```

**Solutions:**

```bash
# Check if nodes have enough resources
kubectl describe nodes | grep -A5 "Allocated resources"

# Check tolerations
kubectl get pod -n telegen -o yaml | grep -A10 tolerations

# Check node selector
kubectl get daemonset -n telegen -o yaml | grep -A5 nodeSelector
```

### Issue: Pod CrashLoopBackOff

**Symptoms:**
- Pod repeatedly crashes
- `CrashLoopBackOff` status

**Diagnose:**

```bash
# Check logs
kubectl logs -n telegen -l app.kubernetes.io/name=telegen --previous

# Check events
kubectl get events -n telegen --sort-by='.lastTimestamp'
```

**Solutions:**

```bash
# Check if privileged mode is enabled
kubectl get pod -n telegen -o yaml | grep privileged

# Verify volume mounts
kubectl describe pod -n telegen -l app.kubernetes.io/name=telegen | grep -A20 Volumes

# Check if SecurityContextConstraints are applied (OpenShift)
oc get scc telegen-scc
```

### Issue: RBAC Permission Denied

**Symptoms:**
- `forbidden` errors in logs
- Can't list pods/nodes

**Solutions:**

```bash
# Check ClusterRole
kubectl describe clusterrole telegen

# Check ClusterRoleBinding
kubectl describe clusterrolebinding telegen

# Verify ServiceAccount
kubectl get serviceaccount -n telegen

# Reapply RBAC
kubectl apply -f deployments/kubernetes/rbac.yaml
```

### Issue: ServiceMonitor Not Working

**Symptoms:**
- Prometheus not scraping Telegen
- No metrics in Prometheus

**Solutions:**

```bash
# Check if Prometheus Operator is installed
kubectl get crd servicemonitors.monitoring.coreos.com

# Verify ServiceMonitor
kubectl get servicemonitor -n telegen

# Check Prometheus targets
# Access Prometheus UI -> Status -> Targets

# Verify label matching
kubectl get servicemonitor -n telegen -o yaml | grep -A5 selector
kubectl get service -n telegen -o yaml | grep -A5 labels
```

## Export Issues

### Issue: OTLP Connection Failed

**Symptoms:**
- `connection refused` errors
- `deadline exceeded` errors

**Diagnose:**

```bash
# Test connectivity
nc -zv otel-collector 4317

# Check DNS resolution
nslookup otel-collector

# Verify endpoint is correct
grep -A5 "otlp" /etc/telegen/config.yaml
```

**Solutions:**

```bash
# Check if collector is running
kubectl get pods -n observability -l app=otel-collector

# Verify port is open
kubectl exec -n telegen -it $(kubectl get pod -n telegen -l app.kubernetes.io/name=telegen -o jsonpath='{.items[0].metadata.name}') -- nc -zv otel-collector 4317

# Try with insecure connection
# Set in config:
# exports:
#   otlp:
#     grpc:
#       insecure: true
```

### Issue: TLS Certificate Errors

**Symptoms:**
- `x509: certificate signed by unknown authority`
- `certificate verify failed`

**Solutions:**

```bash
# Verify certificate
openssl s_client -connect otel-collector:4317 -showcerts

# Add CA certificate to config
# exports:
#   otlp:
#     grpc:
#       tls:
#         enabled: true
#         ca_file: "/etc/telegen/certs/ca.crt"

# Or skip verification (not recommended for production)
# exports:
#   otlp:
#     grpc:
#       tls:
#         insecure_skip_verify: true
```

### Issue: Data Not Appearing in Backend

**Symptoms:**
- No traces/metrics in Jaeger/Prometheus
- Export appears successful

**Diagnose:**

```bash
# Check export metrics
curl -s http://localhost:19090/metrics | grep export

# Look for:
# - telegen_traces_exported_total
# - telegen_export_errors_total
```

**Solutions:**

```bash
# Enable debug logging
# telegen:
#   log_level: debug

# Check collector logs
kubectl logs -n observability -l app=otel-collector

# Verify data pipeline
# Telegen -> OTel Collector -> Backend
```

## Performance Issues

### Issue: High CPU Usage

**Symptoms:**
- CPU usage exceeds limits
- Throttling observed

**Diagnose:**

```bash
# Check resource usage
kubectl top pod -n telegen

# Check internal metrics
curl -s http://localhost:19090/metrics | grep telegen_cpu
```

**Solutions:**

```yaml
# Reduce sample rate
profiling:
  cpu:
    sample_rate: 49  # Reduce from 99

# Limit traced protocols
ebpf:
  network:
    protocols:
      - http  # Only trace HTTP

# Increase CPU limits
resources:
  limits:
    cpu: "2000m"
```

### Issue: High Memory Usage

**Symptoms:**
- OOMKilled pods
- Memory steadily increasing

**Solutions:**

```yaml
# Reduce ring buffer size
ebpf:
  ringbuf_size: 8388608  # 8MB instead of 16MB

# Limit max connections
ebpf:
  max_connections: 50000

# Reduce symbol cache
profiling:
  symbols:
    cache_size: 5000

# Increase memory limits
resources:
  limits:
    memory: "2Gi"
```

### Issue: Missing Events/Traces

**Symptoms:**
- Gaps in tracing data
- Some requests not traced

**Diagnose:**

```bash
# Check drop metrics
curl -s http://localhost:19090/metrics | grep -E "(drop|lost)"
```

**Solutions:**

```yaml
# Increase buffer sizes
ebpf:
  ringbuf_size: 33554432  # 32MB
  perf_buffer_size: 16384

# Increase queue size
exports:
  queue:
    size: 10000
    num_consumers: 20
```

## Feature-Specific Issues

### Issue: Profiling Not Working

**Symptoms:**
- No profile data
- `failed to attach perf event` errors

**Solutions:**

```bash
# Check perf_event_paranoid
cat /proc/sys/kernel/perf_event_paranoid
# Should be <= 1 for user profiling, -1 for full access
sudo sysctl kernel.perf_event_paranoid=-1

# Check capabilities
getcap /usr/local/bin/telegen
# Should include cap_perfmon
```

### Issue: Security Events Not Detected

**Symptoms:**
- No security alerts
- Syscall audit not working

**Solutions:**

```yaml
# Enable all security features
security:
  enabled: true
  syscall_audit:
    enabled: true
    log_all: true  # For debugging

# Check if LSM is blocking
dmesg | grep -i bpf
```

### Issue: Logs Not Collected

**Symptoms:**
- No log data in pipeline
- Position file not updating

**Solutions:**

```bash
# Check file permissions
ls -la /var/log/containers/

# Verify path patterns
grep -r "include:" /etc/telegen/config.yaml

# Check position file
cat /var/lib/telegen/positions.json

# Ensure directory exists
sudo mkdir -p /var/lib/telegen
sudo chown telegen:telegen /var/lib/telegen
```

## Log Analysis

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `failed to load BPF program` | Kernel too old or missing features | Upgrade kernel to 5.8+ |
| `operation not permitted` | Missing capabilities | Run as root or add capabilities |
| `no space left on device` | BPF map limits exceeded | Increase RLIMIT_MEMLOCK |
| `connection refused` | Backend not reachable | Check endpoint and network |
| `context deadline exceeded` | Slow backend | Increase timeout |

### Debug Logging

Enable debug logging for detailed diagnostics:

```yaml
telegen:
  log_level: debug
```

Or via environment:

```bash
TELEGEN_LOG_LEVEL=debug telegen --config=/etc/telegen/config.yaml
```

### Verbose eBPF Output

```bash
# View eBPF debug output
cat /sys/kernel/debug/tracing/trace_pipe | grep telegen
```

## Getting Help

### Collect Diagnostic Information

```bash
#!/bin/bash
# save as collect-diagnostics.sh

echo "=== System Info ==="
uname -a
cat /etc/os-release

echo "=== Kernel Info ==="
uname -r
cat /proc/version

echo "=== eBPF Support ==="
ls -la /sys/kernel/btf/vmlinux 2>/dev/null || echo "BTF not found"
mount | grep bpf
cat /proc/sys/kernel/unprivileged_bpf_disabled

echo "=== Telegen Status ==="
systemctl status telegen 2>/dev/null || kubectl get pods -n telegen

echo "=== Telegen Logs ==="
journalctl -u telegen -n 50 2>/dev/null || kubectl logs -n telegen -l app.kubernetes.io/name=telegen --tail=50

echo "=== Telegen Config ==="
cat /etc/telegen/config.yaml 2>/dev/null

echo "=== eBPF Programs ==="
sudo bpftool prog list 2>/dev/null | head -50

echo "=== Resource Usage ==="
top -b -n1 | grep telegen
```

### Community Support

- **GitHub Issues**: https://github.com/platformbuilds/telegen/issues
- **Discussions**: https://github.com/platformbuilds/telegen/discussions
- **Slack**: #telegen on observability-community.slack.com

### Commercial Support

For enterprise support, contact: support@telegen.io

## Next Steps

- [Installation Guide](installation.md) - Reinstall if needed
- [Configuration Reference](configuration.md) - Verify configuration
