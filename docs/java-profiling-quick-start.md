# Java Profiling Quick Start Guide

This guide provides quick reference for enabling Java profiling with Telegen on Kubernetes/OpenShift.

## TL;DR - Just Show Me the Configuration

### For IBM OpenJ9 (Java 8/11/17/21)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-java-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: my-app:latest
        env:
        - name: OPENJ9_JAVA_OPTIONS
          value: "-Xjit:perfTool"  # This is the critical flag
```

### For Oracle/OpenJDK HotSpot

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-java-app
spec:
  template:
    spec:
      initContainers:
      - name: perf-map-agent
        image: alpine:latest
        command:
        - sh
        - -c
        - |
          apk add --no-cache git gcc g++ make openjdk11
          git clone --depth=1 https://github.com/jvm-profiling-tools/perf-map-agent
          cd perf-map-agent
          cmake . && make
          cp out/libperfmap.so /opt/perf-map/
        volumeMounts:
        - name: perf-map
          mountPath: /opt/perf-map
      containers:
      - name: app
        image: my-app:latest
        env:
        - name: JAVA_TOOL_OPTIONS
          value: "-XX:+PreserveFramePointer -agentpath:/opt/perf-map/libperfmap.so"
        volumeMounts:
        - name: perf-map
          mountPath: /opt/perf-map
      volumes:
      - name: perf-map
        emptyDir: {}
```

## Decision Tree

```
Is your application using IBM OpenJ9?
│
├─ YES → Add: -Xjit:perfTool
│         (via OPENJ9_JAVA_OPTIONS or JAVA_TOOL_OPTIONS)
│         ✓ Simple, built-in
│         ✓ Low overhead
│         ✓ Works with Java 8+
│
└─ NO → Using Oracle/OpenJDK HotSpot?
         │
         └─ YES → Use perf-map-agent
                   (requires compilation & agent deployment)
                   ✓ More complex but battle-tested
                   ✓ Works with Java 7+
```

## Validation Checklist

After deploying your configuration:

1. **Check JVM flags are applied:**
   ```bash
   kubectl exec -it <pod-name> -- ps aux | grep java
   ```
   Should show `-Xjit:perfTool` (OpenJ9) or `-agentpath` (HotSpot)

2. **Verify perf map is generated:**
   ```bash
   kubectl exec -it <pod-name> -- ls -lh /tmp/perf-*.map
   ```
   Should show a file with non-zero size after application warmup

3. **Run validation script:**
   ```bash
   ./scripts/validate-java-profiling.sh <namespace> <deployment-name>
   ```

4. **Check Telegen logs:**
   ```bash
   kubectl logs -n telegen-system -l app=telegen-agent --tail=50 | grep -i jit
   ```
   Should show "loaded JIT perf map with X entries"

## Common Issues & Fixes

### Issue: No perf map file generated

**Symptom:** `/tmp/perf-*.map` doesn't exist

**Solution:**
- **OpenJ9:** Ensure `-Xjit:perfTool` flag is set
- **HotSpot:** Ensure perf-map-agent is deployed and `-agentpath` is correct
- Restart pod to reload JVM with correct flags
- Trigger hot code paths to force JIT compilation

### Issue: Perf map exists but is empty

**Symptom:** File exists but size is 0 or very small

**Solution:**
- Application hasn't warmed up yet (wait 1-2 minutes)
- Generate load to trigger JIT compilation
- Check JVM threshold: `-Xjit:perfTool,threshold=10` (lower = more methods)

### Issue: Telegen can't read perf map

**Symptom:** Telegen logs show "failed to load perf map: permission denied"

**Solution for OpenShift:**
```bash
# Fix SELinux context
kubectl exec -it <pod-name> -- chcon -t container_file_t /tmp/perf-*.map

# Or globally in SecurityContextConstraints
kubectl patch scc telegen-privileged --type=merge -p '
spec:
  seLinuxContext:
    type: MustRunAs
    seLinuxOptions:
      type: spc_t'
```

**Solution for standard Kubernetes:**
- Ensure Telegen DaemonSet has `hostPID: true`
- Check Telegen can access `/proc/<pid>/root/tmp/`

### Issue: Stack traces still show hex addresses

**Symptom:** Flame graphs show `[unresolved] 0x7f...` instead of method names

**Solution:**
1. Verify perf map has entries (see above)
2. Check Telegen loaded the perf map (check logs)
3. Enable debug logging:
   ```yaml
   env:
   - name: TELEGEN_DEBUG_LOGGING
     value: "true"
   ```
4. Ensure addresses in perf map match JIT code regions
5. Wait for JIT re-compilation after changing flags (can take minutes)

## Performance Impact

| JVM Type | Memory Overhead | CPU Overhead | Latency Impact |
|----------|----------------|--------------|----------------|
| OpenJ9 with perfTool | ~5-10 MB | <0.5% | <1ms p99 |
| HotSpot with perf-map-agent | ~10-20 MB | <1% | <2ms p99 |

Both are production-safe for continuous profiling.

## JVM Version Compatibility

### OpenJ9
- ✓ **0.9.0+** (2018+): Full perfTool support
- ⚠️ **0.8.x** (2017): Limited support, may not generate all methods
- ✗ **0.7.x and earlier**: No perfTool support

Check your version:
```bash
java -version
# Look for: openj9-0.XX.0
```

### HotSpot
- ✓ **Java 7+**: All versions supported with perf-map-agent
- ⚠️ **Java 11+ without -XX:+PreserveFramePointer**: May have incomplete stacks
- ✓ **Java 17+**: Best support with JEP 388 (JFR) integration

## Architecture-Specific Notes

### x86_64 (amd64)
- ✓ Full support
- ✓ Frame pointers preserved by default in most builds

### ARM64 (aarch64)
- ✓ Supported in OpenJ9 0.15.0+
- ⚠️ Frame pointer support varies by JDK distribution
- May need explicit `-XX:+PreserveFramePointer` for HotSpot

### Multi-architecture images
```yaml
image: my-app:latest  # Should be manifest list
# Ensure both amd64 and arm64 variants have profiling enabled
```

## Environment Variables Reference

### OpenJ9
```bash
# Minimal configuration
export OPENJ9_JAVA_OPTIONS="-Xjit:perfTool"

# With tuning
export OPENJ9_JAVA_OPTIONS="-Xjit:perfTool,threshold=10,verbose"

# For containerized environments
export JAVA_TOOL_OPTIONS="-Xjit:perfTool -XX:+UseContainerSupport"
```

### HotSpot
```bash
# With perf-map-agent
export JAVA_TOOL_OPTIONS="-XX:+PreserveFramePointer -agentpath:/opt/perf-map/libperfmap.so"

# Alternative: Use jattach to generate maps on-demand
export JAVA_TOOL_OPTIONS="-XX:+PreserveFramePointer"
# Then: jattach $(pgrep java) load libperfmap.so
```

## Security Considerations

### Required Capabilities (Telegen Agent)
```yaml
securityContext:
  capabilities:
    add:
    - SYS_ADMIN      # For BPF
    - SYS_RESOURCE   # For locked memory
    - IPC_LOCK       # For BPF maps
    - NET_ADMIN      # For network tracing (optional)
```

### OpenShift SecurityContextConstraints
```yaml
allowHostDirVolumePlugin: true
allowHostPID: true
allowPrivilegedContainer: true
seLinuxContext:
  type: MustRunAs
  seLinuxOptions:
    type: spc_t  # Allow access to all container files
```

### Least Privilege Alternative
If privileged mode is not acceptable:
- Use BPF CO-RE (Compile Once, Run Everywhere)
- Mount BPF filesystem as volume instead of hostPath
- Use service accounts with limited RBAC
- See: `deployments/kubernetes/telegen-agent-unprivileged.yaml`

## Next Steps

1. **For OpenJ9 on OpenShift:**
   - See: [docs/java-openj9-profiling.md](java-openj9-profiling.md)
   - Deploy: `deployments/openshift/java-openj9-profiling.yaml`

2. **For HotSpot on Kubernetes:**
   - See: [docs/java-hotspot-profiling.md](java-hotspot-profiling.md) *(if exists)*
   - Deploy: `deployments/kubernetes/java-app-example.yaml`

3. **Validate Your Setup:**
   ```bash
   ./scripts/validate-java-profiling.sh <namespace> <deployment-name>
   ```

4. **View Profiling Data:**
   ```bash
   # Via Prometheus/Grafana
   kubectl port-forward -n telegen-system svc/telegen-metrics 9090:9090
   
   # Via pprof HTTP endpoint
   kubectl port-forward -n telegen-system svc/telegen-api 8080:8080
   curl http://localhost:8080/debug/pprof/profile?seconds=30 > profile.pb.gz
   go tool pprof -http=:9091 profile.pb.gz
   ```

## Getting Help

If you encounter issues not covered here:

1. Enable debug logging in Telegen:
   ```yaml
   env:
   - name: TELEGEN_DEBUG_LOGGING
     value: "true"
   ```

2. Check logs:
   ```bash
   kubectl logs -n telegen-system -l app=telegen-agent --tail=100 | grep -A5 -B5 "error\|warn\|jit"
   ```

3. Run validation script:
   ```bash
   ./scripts/validate-java-profiling.sh <namespace> <deployment>
   ```

4. Review troubleshooting guide:
   - OpenJ9: [docs/java-openj9-profiling.md#troubleshooting](java-openj9-profiling.md#troubleshooting)
   - General: [docs/troubleshooting.md](troubleshooting.md)

## Reference Links

- **OpenJ9 perfTool Documentation:** https://www.eclipse.org/openj9/docs/xjit/#perftool
- **perf-map-agent:** https://github.com/jvm-profiling-tools/perf-map-agent
- **Linux perf map format:** https://www.brendangregg.com/perf.html#JIT_Symbols
- **BPF CO-RE:** https://nakryiko.com/posts/bpf-portability-and-co-re/
