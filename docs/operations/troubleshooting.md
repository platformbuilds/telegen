# Troubleshooting

Common issues and solutions for Telegen.

## Quick Diagnostics

### Check Telegen Status

```bash
# Health check
curl http://localhost:19090/healthz

# Readiness
curl http://localhost:19090/ready

# Full status
curl http://localhost:19090/status
```

### Check eBPF Programs

```bash
# List loaded programs
bpftool prog list | grep -i telegen

# Check if eBPF is working
cat /sys/kernel/debug/tracing/trace_pipe | head -20
```

### Check Logs

```bash
# Kubernetes
kubectl logs -l app=telegen -n monitoring --tail=100

# Docker
docker logs telegen --tail=100

# Systemd
journalctl -u telegen -f
```

---

## Common Issues

### eBPF Program Load Failures

**Symptom:** Telegen starts but shows "eBPF program load failed"

**Causes and Solutions:**

1. **Kernel too old**
   - Minimum: Linux 4.18
   - Recommended: Linux 5.8+
   ```bash
   uname -r  # Check kernel version
   ```

2. **Missing capabilities**
   ```bash
   # Docker
   docker run --privileged ...
   
   # Kubernetes
   securityContext:
     privileged: true
   ```

3. **BPF filesystem not mounted**
   ```bash
   mount | grep bpf
   # Should show: bpffs on /sys/fs/bpf type bpf
   
   # Mount if missing
   mount -t bpf bpf /sys/fs/bpf
   ```

4. **BTF not available**
   ```bash
   ls /sys/kernel/btf/vmlinux
   # Should exist for CO-RE support
   ```

---

### No Traces Being Collected

**Symptom:** Telegen running but no traces in backend

**Diagnostics:**

```bash
# Check if spans are being collected
curl -s http://localhost:19090/metrics | grep telegen_spans

# Check export status
curl -s http://localhost:19090/metrics | grep telegen_export
```

**Solutions:**

1. **OTLP endpoint unreachable**
   ```bash
   # Test connectivity
   nc -zv otel-collector 4317
   
   # Check DNS
   nslookup otel-collector
   ```

2. **Network tracing disabled**
   ```yaml
   agent:
     ebpf:
       network:
         enabled: true  # Ensure enabled
   ```

3. **Wrong port configuration**
   ```yaml
   agent:
     ebpf:
       network:
         include_ports:
           - 80
           - 443
           - 8080  # Add your app ports
   ```

4. **TLS issues**
   ```yaml
   otlp:
     endpoint: "otel-collector:4317"
     insecure: true  # Try without TLS first
   ```

---

### High Memory Usage

**Symptom:** Telegen using excessive memory

**Diagnostics:**

```bash
# Check memory metrics
curl -s http://localhost:19090/metrics | grep telegen_process_resident_memory

# Check queue sizes
curl -s http://localhost:19090/metrics | grep telegen_export_queue
```

**Solutions:**

1. **Reduce ring buffer size**
   ```yaml
   agent:
     ebpf:
       ringbuf_size: 8388608  # 8MB instead of 16MB
   ```

2. **Limit queue memory**
   ```yaml
   queues:
     traces:
       mem_limit: "128Mi"
     metrics:
       mem_limit: "64Mi"
   ```

3. **Increase export frequency**
   - Check if backend is slow
   - Reduce batch sizes
   ```yaml
   queues:
     traces:
       batch_size: 256  # Smaller batches
   ```

---

### Event Loss (Ring Buffer)

**Symptom:** `telegen_ebpf_ringbuf_lost_total` increasing

**Diagnostics:**

```bash
# Check loss rate
curl -s http://localhost:19090/metrics | grep ringbuf_lost
```

**Solutions:**

1. **Increase ring buffer size**
   ```yaml
   agent:
     ebpf:
       ringbuf_size: 67108864  # 64MB
   ```

2. **Reduce event volume**
   ```yaml
   agent:
     ebpf:
       network:
         exclude_ports:
           - 22     # SSH
           - 2379   # etcd
       syscalls:
         exclude:
           - futex
           - nanosleep
   ```

3. **Check CPU bottleneck**
   - Telegen may not be processing fast enough
   - Increase CPU limits

---

### Export Errors

**Symptom:** `telegen_export_errors_total` increasing

**Diagnostics:**

```bash
# Check specific errors
curl -s http://localhost:19090/metrics | grep export_errors

# Check logs
grep -i "export" /var/log/telegen.log | tail -20
```

**Solutions:**

1. **Connection refused**
   ```bash
   # Verify endpoint
   curl -v http://otel-collector:4317
   
   # Check endpoint config
   cat /etc/telegen/config.yaml | grep endpoint
   ```

2. **TLS certificate errors**
   ```yaml
   otlp:
     tls:
       ca_file: "/etc/ssl/certs/ca.crt"
       insecure_skip_verify: false  # Ensure CA is correct
   ```

3. **Authentication failures**
   ```yaml
   otlp:
     headers:
       Authorization: "Bearer ${OTEL_TOKEN}"
   ```

4. **Backend overloaded**
   - Increase retry backoff
   - Check backend capacity
   ```yaml
   backoff:
     initial: "1s"
     max: "60s"
   ```

---

### Missing Kubernetes Metadata

**Symptom:** Traces lack k8s.pod.name, k8s.namespace labels

**Diagnostics:**

```bash
# Check if running in K8s
kubectl get pods -l app=telegen -n monitoring

# Check RBAC
kubectl auth can-i get pods --as=system:serviceaccount:monitoring:telegen
```

**Solutions:**

1. **Missing RBAC permissions**
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRole
   metadata:
     name: telegen
   rules:
     - apiGroups: [""]
       resources: ["pods", "nodes", "services"]
       verbs: ["get", "list", "watch"]
   ```

2. **Downward API not configured**
   ```yaml
   env:
     - name: POD_NAME
       valueFrom:
         fieldRef:
           fieldPath: metadata.name
     - name: POD_NAMESPACE
       valueFrom:
         fieldRef:
           fieldPath: metadata.namespace
   ```

3. **Discovery disabled**
   ```yaml
   agent:
     discovery:
       detect_kubernetes: true
   ```

---

### No GPU Metrics

**Symptom:** GPU metrics not appearing

**Diagnostics:**

```bash
# Check NVML
nvidia-smi

# Check if device is mounted
ls /dev/nvidia*
```

**Solutions:**

1. **NVML not available**
   - Ensure NVIDIA drivers installed
   - Mount NVIDIA device in container
   ```yaml
   volumes:
     - /dev/nvidia0:/dev/nvidia0
     - /dev/nvidiactl:/dev/nvidiactl
   ```

2. **Container not GPU-enabled**
   ```yaml
   spec:
     runtimeClassName: nvidia
     containers:
       - name: telegen
         resources:
           limits:
             nvidia.com/gpu: 0  # Access without allocating
   ```

3. **GPU monitoring disabled**
   ```yaml
   agent:
     gpu:
       enabled: true
       nvidia: true
   ```

---

### Profiling Not Working

**Symptom:** No profiles in backend

**Diagnostics:**

```bash
# Check profiling enabled
curl -s http://localhost:19090/metrics | grep profile

# Check perf_event access
cat /proc/sys/kernel/perf_event_paranoid
```

**Solutions:**

1. **perf_event_paranoid too restrictive**
   ```bash
   # Temporary
   sysctl kernel.perf_event_paranoid=1
   
   # Permanent
   echo 'kernel.perf_event_paranoid=1' >> /etc/sysctl.conf
   ```

2. **Missing capability**
   ```yaml
   securityContext:
     capabilities:
       add:
         - SYS_ADMIN  # or PERFMON on newer kernels
   ```

3. **Profiling disabled**
   ```yaml
   agent:
     profiling:
       enabled: true
   ```

---

### Container Not Starting

**Symptom:** Container exits immediately

**Diagnostics:**

```bash
# Check exit code
docker inspect telegen --format='{{.State.ExitCode}}'

# Check last logs
docker logs telegen 2>&1 | tail -50
```

**Solutions:**

1. **Config file error**
   ```bash
   # Validate config
   telegen --validate-config /etc/telegen/config.yaml
   ```

2. **Required mounts missing**
   ```bash
   docker run -d \
     -v /sys:/sys:ro \
     -v /proc:/host/proc:ro \
     -v /sys/kernel/debug:/sys/kernel/debug \
     -v /sys/fs/bpf:/sys/fs/bpf \
     ...
   ```

3. **Kernel version mismatch**
   - BTF for wrong kernel
   - Use `-fno-BTF` builds or matching kernel

---

## Debug Mode

Enable comprehensive debugging:

```yaml
telegen:
  log_level: debug
  
agent:
  ebpf:
    debug: true
```

Or via environment:

```bash
TELEGEN_LOG_LEVEL=debug \
TELEGEN_AGENT_EBPF_DEBUG=true \
telegen
```

---

## Getting Help

### Collect Diagnostics

```bash
# Create diagnostic bundle
telegen diagnostics > telegen-diagnostics.tar.gz
```

Bundle includes:
- Configuration (sanitized)
- Metrics snapshot
- eBPF program list
- Kernel info
- Recent logs

### Log an Issue

When reporting issues, include:
- Telegen version: `telegen version`
- Kernel version: `uname -a`
- Distribution: `cat /etc/os-release`
- Diagnostic bundle
- Steps to reproduce

---

## Next Steps

- {doc}`monitoring` - Set up monitoring
- {doc}`performance-tuning` - Optimize performance
- {doc}`../configuration/full-reference` - Configuration options
