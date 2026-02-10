# Java Profiling with IBM OpenJ9 on OpenShift

## Overview

IBM OpenJ9 Java 8 requires specific JVM configuration to enable symbol resolution for JIT-compiled methods in eBPF profiling.

## OpenJ9 vs HotSpot

| Feature | HotSpot/OpenJDK | IBM OpenJ9 |
|---------|----------------|------------|
| JIT Compiler | C1/C2 | Eclipse OMR JIT |
| Perf Map Support | Via perf-map-agent | Via `-Xjit:perfTool` |
| Default Behavior | Requires agent install | Requires JVM flag |
| Format | Standard perf format | Standard perf format |

## Configuration Steps

### 1. Enable OpenJ9 JIT Perf Maps

Add the following JVM arguments to your Java application:

```bash
# OpenJ9 Java 8 - Enable perf map generation
-Xjit:perfTool

# For more verbose output (optional, for debugging)
-Xjit:verbose={compilePerformance},vlog=/tmp/jit.log
```

**In Kubernetes/OpenShift Deployment:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: your-java-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: your-image:tag
        env:
        - name: JAVA_OPTS
          value: "-Xjit:perfTool"
        # Or if using OpenJ9-specific env var:
        - name: OPENJ9_JAVA_OPTIONS
          value: "-Xjit:perfTool"
```

### 2. Verify Perf Map Generation

After the JVM starts and methods are JIT-compiled:

```bash
# Check if perf map exists (inside container)
ls -l /tmp/perf-*.map

# Example output:
# /tmp/perf-1234.map  (where 1234 is the Java process PID)

# Check content format
head /tmp/perf-1234.map
# Expected format: <address> <size> <method_name>
# Example: 7f8b5a200000 100 java/lang/String.equals(Ljava/lang/Object;)Z
```

### 3. OpenShift-Specific Considerations

#### a. File Permissions
Ensure the telegen profiler can access the perf map:

```yaml
# If running profiler as DaemonSet, ensure it can access container /tmp
volumes:
- name: proc
  hostPath:
    path: /proc
    type: Directory
volumeMounts:
- name: proc
  mountPath: /host/proc
  readOnly: true
```

#### b. Security Context
OpenJ9 needs write access to `/tmp`:

```yaml
securityContext:
  # Ensure Java app can write perf maps
  runAsNonRoot: true
  # If using restricted SCC, ensure /tmp is writable
  fsGroup: 1000
```

#### c. SELinux (if enabled)
```bash
# May need to adjust SELinux contexts for /tmp access
chcon -t container_file_t /tmp/perf-*.map
```

### 4. OpenJ9-Specific JVM Flags Explained

```bash
# Basic perf support
-Xjit:perfTool

# With sampling interval (generate maps every N ms)
-Xjit:perfTool,perfToolSamplingPeriod=1000

# Disable JIT optimizations that make profiling harder
-Xjit:disableInlining

# Increase code cache (if you see "code cache full" warnings)
-Xjit:codeCache=256m

# For production: enable perf with minimal overhead
-Xjit:perfTool,optLevel=warm
```

### 5. Alternative: JVMTI Agent (if perfTool doesn't work)

OpenJ9 Java 8 may have limited perfTool support. Fallback option:

```bash
# Use perf-map-agent (requires compilation for OpenJ9)
# 1. Clone and build perf-map-agent
git clone https://github.com/jvm-profiling-tools/perf-map-agent
cd perf-map-agent
cmake -DJAVA_HOME=/path/to/openj9-jdk .
make

# 2. Attach to running Java process
java -cp attach-main.jar:$JAVA_HOME/lib/tools.jar \
  net.virtualvoid.perf.AttachOnce <pid>

# 3. Verify perf map created
ls -l /tmp/perf-<pid>.map
```

## Troubleshooting

### Issue: No perf map file generated

**Causes:**
1. `-Xjit:perfTool` flag not set
2. No methods JIT-compiled yet (application just started)
3. OpenJ9 version too old (< 0.9.0)
4. `/tmp` not writable

**Solutions:**
```bash
# Check JVM flags
ps aux | grep java | grep perfTool

# Check OpenJ9 version
java -version
# Look for "Eclipse OpenJ9" version

# Check /tmp permissions
stat /tmp
# Should be drwxrwxrwt

# Force JIT compilation (trigger hot code paths)
# Run load test or warmup requests
```

### Issue: Perf map exists but symbols not resolved

**Causes:**
1. Telegen can't access container `/tmp` due to namespaces
2. File permissions deny read access
3. Perf map format unexpected

**Solutions:**
```bash
# Check namespace access (run from telegen agent pod)
nsenter -t <java_pid> -m -n ls -l /tmp/perf-*.map

# Check telegen debug logs (enable with EnableDebugLogging: true)
kubectl logs telegen-agent-xxx | grep "perf map"

# Should see:
# loaded JIT perf map pid=1234 entries=500 path=/tmp/perf-1234.map
```

### Issue: Methods show as [unresolved] even with perf map

**Causes:**
1. Address calculation mismatch
2. JIT recompilation invalidated addresses
3. Inlined methods

**Solutions:**
```bash
# Disable aggressive inlining
-Xjit:perfTool,disableInlining

# Increase perf map refresh (if OpenJ9 supports it)
-Xjit:perfTool,perfToolSamplingPeriod=500

# Check if addresses match
# Compare perf map addresses with sampled stack addresses
cat /tmp/perf-1234.map | head
# vs
# Inspect telegen metrics for unresolved addresses
```

### Issue: Container crashes or OOM after adding perfTool

**Causes:**
1. Code cache exhaustion
2. Memory overhead of perf tracking

**Solutions:**
```bash
# Increase code cache
-Xjit:codeCache=512m

# Limit JIT compilation levels
-Xjit:perfTool,optLevel=warm,count=1000

# Monitor memory
# Perf map file size should be < 10MB typically
du -h /tmp/perf-*.map
```

## Performance Impact

| Configuration | Memory Overhead | CPU Overhead | Disk I/O |
|--------------|----------------|--------------|----------|
| `-Xjit:perfTool` | ~5-10 MB | < 1% | Low (writes on JIT) |
| With sampling | ~5-15 MB | 1-2% | Medium (periodic writes) |
| perf-map-agent | ~10-20 MB | 2-5% | High (full dump) |

**Recommendation for production:** 
```bash
-Xjit:perfTool,optLevel=warm
```

## Validation Checklist

- [ ] Java application deployment has `-Xjit:perfTool` flag
- [ ] `/tmp` directory is writable in container
- [ ] Perf map file exists: `/tmp/perf-<pid>.map`
- [ ] Perf map contains entries (not empty)
- [ ] Telegen agent can access container `/tmp` via namespace
- [ ] Telegen debug logs show "loaded JIT perf map"
- [ ] Flame graphs show Java method names (not hex addresses)

## Expected Results

**Before configuration:**
```
[kernel]  do_syscall_64
[libjvm.so]  [unresolved] 0x7f8b5a200145
[unresolved]  0x7f8b5a200190
```

**After configuration:**
```
[kernel]  do_syscall_64
[jit]  java/lang/String.equals(Ljava/lang/Object;)Z
[jit]  com/example/MyClass.processRequest()V
```

## OpenJ9 Version Compatibility

| OpenJ9 Version | Java Version | perfTool Support | Notes |
|----------------|--------------|------------------|-------|
| 0.8.x | Java 8 | Limited | Basic support, may be unstable |
| 0.9.x+ | Java 8 | Full | Recommended minimum |
| 0.11.x+ | Java 8 | Full + sampling | Best support |
| 0.26.x+ | Java 8 | Full + optimizations | Latest features |

Check your OpenJ9 version:
```bash
java -version
# Example output:
# openjdk version "1.8.0_292"
# Eclipse OpenJ9 VM (build openj9-0.26.0, JRE 1.8.0 Linux amd64-64-Bit)
```

## References

- [OpenJ9 JIT Options](https://www.eclipse.org/openj9/docs/xjit/)
- [OpenJ9 Performance Tuning](https://www.eclipse.org/openj9/docs/performance/)
- [perf-map-agent](https://github.com/jvm-profiling-tools/perf-map-agent)
