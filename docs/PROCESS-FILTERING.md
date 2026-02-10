# Process Filtering for Targeted Profiling

## Overview

Telegen profiler supports **targeted profiling** to focus on specific applications instead of profiling all processes on a node. This significantly reduces memory usage, CPU overhead, and makes profiles more relevant to your needs.

## Why Use Process Filtering?

**Without Filters:**
- Profiles **all 200+ processes** on a node
- High memory usage (~4GB+ with many processes)
- Noisy profiles with irrelevant data
- Difficult to find your application's bottlenecks

**With Filters:**
- Profile **only your application** (e.g., 5-10 Java processes)
- Low memory usage (~200-500 MB)
- Clean, focused profiles
- Easy to identify performance issues

## Filter Types

### 1. Process-Based Filters

#### By Process Name
Profile specific process types:
```yaml
profiler:
  target_process_names:
    - "java"      # All Java processes
    - "python3"   # All Python processes
    - "node"      # All Node.js processes
```

#### By Executable Path
Profile specific binaries:
```yaml
profiler:
  target_executables:
    - "/usr/bin/python3"
    - "/usr/local/bin/my-app"
```

#### By PID
Profile specific process (useful for debugging):
```yaml
profiler:
  target_pid: 12345
  # OR multiple PIDs:
  target_pids:
    - 12345
    - 67890
```

#### By Container ID
Profile specific containers:
```yaml
profiler:
  target_container_ids:
    - "abc123def456"
```

### 2. Kubernetes-Based Filters

#### By Namespace
Profile applications in specific namespaces:
```yaml
profiler:
  target_namespaces:
    - "production"
    - "staging"
  
  # Exclude system namespaces
  exclude_namespaces:
    - "kube-system"
    - "kube-public"
    - "monitoring"
```

#### By Deployment
Profile specific deployments:
```yaml
profiler:
  target_deployments:
    - "api-server"
    - "worker-service"
    - "backend"
```

#### By DaemonSet
Profile specific daemonsets:
```yaml
profiler:
  target_daemonsets:
    - "log-collector"
    - "monitoring-agent"
```

#### By StatefulSet
Profile specific statefulsets:
```yaml
profiler:
  target_statefulsets:
    - "database"
    - "cache-cluster"
```

#### By Labels
Profile pods with specific labels (ALL labels must match):
```yaml
profiler:
  target_labels:
    app: "payment-service"
    environment: "production"
    tier: "backend"
```

## Filter Logic

### Multiple Filter Types (AND Logic)
When you specify **multiple filter types**, they work with **AND logic** - ALL must match:

```yaml
profiler:
  target_process_names:
    - "java"
  target_namespaces:
    - "production"
```

This profiles:
- **Java processes AND in the "production" namespace**
- NOT "any Java process anywhere"
- NOT "any process in production"

**Why AND logic?** This allows precise targeting. If you want "Java in production", you don't accidentally profile all Java everywhere or all processes in production.

### Within Same Filter Type (OR Logic)
Within the same filter type, entries use **OR logic**:

```yaml
profiler:
  target_deployments:
    - "api-server"
    - "worker"
```

This profiles:
- Processes in **"api-server" deployment**
- **OR** processes in **"worker" deployment**

### Single Filter Type (OR Logic)
If only ONE filter type is configured, it works independently:

```yaml
profiler:
  target_process_names:
    - "java"
    - "node"
```

This profiles:
- **All Java processes** (any namespace)
- **OR all Node.js processes** (any namespace)

### Label Filters (AND Logic)
Label filters use **AND logic** - ALL labels must match:

```yaml
profiler:
  target_labels:
    app: "myapp"
    tier: "backend"
```

This profiles ONLY pods that have **BOTH** labels: `app=myapp` **AND** `tier=backend`

### Exclusions (Takes Priority)
Exclusion filters always take priority and support wildcards:

```yaml
profiler:
  target_namespaces:
    - "production"
  exclude_namespaces:
    - "production-system"
    - "openshift-*"      # Wildcard: excludes openshift-monitoring, openshift-logging, etc.
```

Result: Profiles "production" namespace **EXCEPT** "production-system" and any namespace starting with "openshift-"

## Real-World Examples

### Example 1: Java Microservices in Production

**Goal:** Profile only Java applications in production, excluding system components

```yaml
profiler:
  enabled: true
  
  # AND logic: Must be Java AND in one of these namespaces
  target_process_names:
    - "java"
  target_namespaces:
    - "microservices-prod"
  
  # Exclusions with wildcards
  exclude_namespaces:
    - "kube-system"
    - "openshift-*"
  
  cpu:
    enabled: true
    sample_rate: 49  # Lower rate for production
```

**Result:** Profiles ~5-10 Java processes in microservices-prod namespace only

### Example 2: Specific Application by Label

**Goal:** Profile only the payment service, version 2

```yaml
profiler:
  target_labels:
    app: "payment-service"
    version: "v2"
  
  cpu:
    enabled: true
    sample_rate: 99
  off_cpu:
    enabled: true
```

**Result:** Profiles only pods matching both labels

### Example 3: Troubleshooting Memory Leak

**Goal:** Deep profiling of a specific deployment with suspected memory issues

```yaml
profiler:
  target_deployments:
    - "leaky-service"
  
  cpu:
    enabled: true
  memory:
    enabled: true
    min_alloc_size: 10240  # Track 10KB+ allocations
  mutex:
    enabled: true
```

**Result:** Comprehensive profiling of one deployment

### Example 4: Multiple Application Types

**Goal:** Profile Java, Python, and Node.js applications

```yaml
profiler:
  target_process_names:
    - "java"
    - "python3"
    - "node"
  target_namespaces:
    - "app-production"
  exclude_namespaces:
    - "kube-system"
    - "telemetry"
```

**Result:** Profiles only these three types in production namespace

### Example 5: Development Environment

**Goal:** Profile everything for development/testing

```yaml
profiler:
  enabled: true
  # No filters = profile all processes
  
  cpu:
    enabled: true
    sample_rate: 99
```

**Result:** Profiles all processes (useful for discovery)

## Configuration File Locations

### DaemonSet ConfigMap
For Kubernetes deployments, add filtering to the ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: telegen-config
  namespace: telegen
data:
  config.yaml: |
    profiler:
      enabled: true
      target_process_names:
        - "java"
      target_namespaces:
        - "production"
      cpu:
        enabled: true
```

### Direct Configuration
For standalone agents:

```bash
telegen --config /etc/telegen/config.yaml
```

## Performance Impact

### Without Filtering (200+ processes)
- **Memory:** 4GB+ (OOMKills)
- **CPU:** 15-20% baseline
- **Profiles:** Large, noisy, hard to analyze

### With Filtering (5-10 targeted processes)
- **Memory:** 200-500 MB
- **CPU:** 2-5% baseline
- **Profiles:** Clean, focused, actionable

### Recommendations

| **Scenario** | **Filter Strategy** | **Expected Processes** | **Memory Usage** |
|--------------|---------------------|------------------------|------------------|
| **Production (Java only)** | `target_process_names: ["java"]` | 5-20 | 200-800 MB |
| **Specific Deployment** | `target_deployments: ["myapp"]` | 3-10 | 150-400 MB |
| **Namespace-based** | `target_namespaces: ["prod"]` | 10-50 | 400-1500 MB |
| **Development** | No filters | 200+ | 4GB+ |

## Memory Leak Fix Integration

The process filtering feature works with the recent memory leak fix:

**Before (no filtering + memory leak):**
- 6 SymbolResolver instances × 200+ processes = **INSTANT OOM**

**After (filtering + fix):**
- 1 SymbolResolver instance × 10 targeted processes = **Stable ~300 MB**

Combined memory savings: **~10-20x reduction!**

## Filter Priority & Debugging

### Check Active Filters

When the agent starts, it logs the active filters:

```
[INFO] initialized process filter, summary="Active filters: ProcessNames=[java], Namespaces=[production], ExcludeNamespaces=[kube-system]"
[INFO] filtered processes for profiling, total_scanned=243, matched=12, has_filters=true
```

### Verify Filtering

1. **Check logs** for "filtered processes" message
2. **Monitor memory usage** - should be much lower with filters
3. **Inspect profiles** - should only contain targeted processes

### Debugging Tips

**No processes matched?**
```yaml
# Check your filter syntax
profiler:
  target_process_names:
    - "java"  # Correct: matches "java" process
    # NOT: "/usr/bin/java" - this matches executable path, use target_executables instead
```

**Still profiling everything?**
```yaml
# Ensure filters are not commented out
profiler:
  enabled: true
  target_process_names:  # Must not be commented!
    - "java"
```

**Want to see what's running?**
```bash
# List processes by name
ps aux | awk '{print $11}' | sort | uniq

# Check process in container
kubectl exec -it <pod> -- ps aux
```

## Advanced: Filter Cache

The process filter caches metadata to avoid repeated /proc reads:

- **Cache Duration:** Until process exits
- **Cache Invalidation:** Automatic on process termination
- **Manual Clear:** Not needed (handled automatically)

## Limitations

1. **Kubernetes metadata requires K8s access**
   - If running outside Kubernetes, K8s filters won't work
   - Use process-based filters instead

2. **Label filtering requires pod annotations**
   - Labels must be set on pods
   - Check with: `kubectl get pod <pod> -o yaml | grep labels -A 10`

3. **Container ID matching is best-effort**
   - Works with standard Docker/containerd
   - May not work with custom runtimes

## Migration Guide

### From "Profile Everything" to Targeted

**Before:**
```yaml
profiler:
  enabled: true
  cpu:
    enabled: true
```

*Result: 200+ processes, 4GB memory*

**After:**
```yaml
profiler:
  enabled: true
  target_process_names:
    - "java"
  target_namespaces:
    - "production"
  cpu:
    enabled: true
```

*Result: 10-20 processes, ~400 MB memory*

### Testing Strategy

1. **Start with broad filters** (e.g., namespace)
2. **Monitor memory/CPU usage**
3. **Refine filters** if still too many processes
4. **Add exclusions** for known noise

## Troubleshooting

### High Memory Despite Filters

**Check logs:**
```bash
kubectl logs -n telegen <pod> | grep "filtered processes"
```

**Expected:**
```
matched=10  # Good!
```

**Problem:**
```
matched=200  # Filters not working!
```

**Solutions:**
1. Verify filter syntax in ConfigMap
2. Check process names: `kubectl exec <pod> -- ps aux`
3. Ensure ConfigMap is mounted correctly

### Profiles Still Contain Unwanted Processes

**Check filter logic:**
- Remember: Multiple filter types use **OR** logic
- Use `exclude_namespaces` to block specific namespaces
- Combine filters carefully

### No Profiles Generated

**Possible causes:**
1. **Filters too restrictive** - No processes match
2. **Check logs:** `matched=0` indicates no matches
3. **Temporarily remove filters** to test

## Summary

Process filtering is **essential for production use** of Telegen profiler:

✅ **Dramatically reduces memory usage** (4GB → 200-500 MB)  
✅ **Lowers CPU overhead** (20% → 2-5%)  
✅ **Produces focused, actionable profiles**  
✅ **Prevents OOMKills** on nodes with many processes  
✅ **Integrates seamlessly with memory leak fix**

**Recommendation:** Always use filtering in production. Profile everything only in dev/test environments.

## See Also

- [Configuration Examples](../configs/profiler-filtering-examples.yaml) - Ready-to-use configurations
- [Memory Leak Fix](./MEMORY-LEAK-FIX.md) - Recent memory optimization
- [Deployment Guide](../custdeploy/mcx-nonprod/telegen/DEPLOYMENT-GUIDE.md) - Production deployment
