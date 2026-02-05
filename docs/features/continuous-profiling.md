# Continuous Profiling

Telegen provides always-on, low-overhead profiling for production environments.

## Overview

Continuous profiling helps you understand:

- **CPU hotspots** - Where is time being spent?
- **Memory allocations** - What's allocating memory?
- **Off-CPU time** - What's blocking or waiting?
- **Lock contention** - Where are threads competing?

All profiles are automatically correlated with traces and metrics.

---

## Profile Types

| Profile Type | What It Measures | Use Case |
|--------------|------------------|----------|
| **CPU** | On-CPU execution time | Find hot code paths |
| **Off-CPU** | Blocking/waiting time | Find I/O bottlenecks |
| **Memory** | Heap allocations | Find memory issues |
| **Mutex** | Lock contention | Find concurrency issues |
| **Block** | Blocking operations | Find synchronization issues |
| **Goroutine** | Goroutine stacks (Go) | Debug goroutine leaks |

---

## How It Works

```{mermaid}
flowchart TB
    subgraph Kernel["Linux Kernel"]
        P["perf_event"]
        U["uprobes"]
    end
    
    subgraph Telegen["Telegen Agent"]
        S["Stack Sampler"]
        A["Symbol Resolver"]
        C["Profile Builder"]
        E["OTLP Exporter"]
    end
    
    subgraph App["Application"]
        F["Functions"]
    end
    
    P -->|"CPU samples"| S
    U -->|"Alloc samples"| S
    F --> P
    F --> U
    S --> A
    A --> C
    C --> E
    E -->|"pprof"| Backend["Profiling Backend"]
```

### Sampling

Telegen uses statistical sampling to minimize overhead:

1. **CPU profiling** - Sample at 99Hz (configurable)
2. **Stack unwinding** - Frame pointer and DWARF-based
3. **Symbol resolution** - Binary analysis and debug symbols
4. **Aggregation** - Aggregate identical stacks

---

## Configuration

### Enable Profiling

```yaml
agent:
  profiling:
    enabled: true
```

### Full Configuration

```yaml
agent:
  profiling:
    enabled: true
    
    # Sampling rate in Hz
    sample_rate: 99  # 99 Hz avoids aliasing with timers
    
    # Profile types
    cpu: true          # On-CPU time
    off_cpu: true      # Off-CPU waiting time
    memory: true       # Heap allocations
    mutex: true        # Lock contention (Go, Java)
    block: true        # Blocking operations (Go)
    goroutine: true    # Goroutine stacks (Go only)
    
    # Duration of each profile sample
    duration: 10s
    
    # How often to upload profiles
    upload_interval: 60s
    
    # Symbol resolution
    symbols:
      demangle_rust: true
      demangle_cpp: true
      include_kernel: false  # Include kernel symbols
      
    # Filtering
    filters:
      # Minimum samples to include
      min_samples: 1
      
      # Exclude system functions
      exclude_patterns:
        - "runtime.*"  # Go runtime
        - "java.lang.*"  # Java internals
```

---

## CPU Profiling

CPU profiling shows where your application spends execution time.

### Sample Output

```
Total CPU time: 60s

Flat      Flat%   Sum%    Cum       Cum%    Name
15.20s    25.3%   25.3%   15.20s    25.3%   encoding/json.(*decodeState).scanWhile
10.50s    17.5%   42.8%   25.70s    42.8%   net/http.(*conn).serve
 8.30s    13.8%   56.6%   8.30s     13.8%   runtime.mallocgc
 5.20s     8.7%   65.3%   5.20s      8.7%   compress/gzip.(*Reader).Read
 4.10s     6.8%   72.1%   4.10s      6.8%   database/sql.(*DB).queryDC
```

### Use Cases

- **Identify hot functions** - Find the most CPU-intensive code
- **Compare before/after** - Measure optimization impact
- **Find regressions** - Catch performance degradation

---

## Off-CPU Profiling

Off-CPU profiling shows where your application is blocked or waiting.

### What Causes Off-CPU Time

- **I/O operations** - Disk, network reads/writes
- **Lock contention** - Waiting for mutexes
- **Sleep/yield** - Explicit waits
- **Scheduling** - Waiting for CPU time

### Sample Output

```
Total Off-CPU time: 45s

Flat      Flat%   Sum%    Cum       Cum%    Name
12.30s    27.3%   27.3%   12.30s    27.3%   syscall.Read
 9.80s    21.8%   49.1%   9.80s     21.8%   sync.(*Mutex).Lock
 7.50s    16.7%   65.8%   7.50s     16.7%   net.(*netFD).Read
 5.20s    11.6%   77.4%   5.20s     11.6%   database/sql.(*DB).conn
```

---

## Memory Profiling

Memory profiling tracks heap allocations.

### Configuration

```yaml
agent:
  profiling:
    memory: true
    
    # Track allocations or in-use memory
    memory_mode: alloc  # alloc or inuse
```

### Sample Output

```
Total allocations: 1.2GB

Flat      Flat%   Sum%    Cum       Cum%    Name
350MB     29.2%   29.2%   350MB     29.2%   encoding/json.(*decodeState).object
220MB     18.3%   47.5%   220MB     18.3%   bytes.makeSlice
180MB     15.0%   62.5%   180MB     15.0%   net/http.(*persistConn).readLoop
```

---

## Runtime-Specific Features

### Go Profiling

Full goroutine and runtime profiling:

```yaml
agent:
  profiling:
    # Go-specific profile types
    goroutine: true    # Goroutine stacks
    mutex: true        # Mutex contention
    block: true        # Blocking operations
```

### Java Profiling

Integration with JFR (Java Flight Recorder):

```yaml
agent:
  profiling:
    java:
      jfr_enabled: true
      # JFR event types
      cpu: true
      memory: true
      gc: true
      locks: true
```

### Python Profiling

Frame-based profiling:

```yaml
agent:
  profiling:
    python:
      enabled: true
      # AsyncIO support
      asyncio: true
```

---

## Profile-Trace Correlation

Profiles are automatically linked to traces:

```{mermaid}
flowchart LR
    subgraph Request["Slow Request"]
        T["Trace\nspan_id: abc123\nlatency: 2.3s"]
        P["Profile\nspan_id: abc123\nCPU: 1.8s parsing"]
    end
    
    T -->|"Linked"| P
```

### How It Works

1. **Span context** - Profiles capture active span_id
2. **Time range** - Profiles filtered to span duration
3. **Aggregation** - Stack samples grouped by span

### Viewing Correlated Profiles

In your tracing UI, slow spans will show:

- **Profile link** - Click to see CPU/memory profile
- **Hot functions** - Top functions during the span
- **Flame graph** - Visual stack trace

---

## Symbol Resolution

### Automatic Symbol Loading

Telegen resolves symbols from:

| Source | Priority |
|--------|----------|
| **Debug symbols** | Highest (DWARF, .debug_info) |
| **Symbol table** | High (.symtab) |
| **Build ID** | Medium (debuginfod lookup) |
| **Binary name** | Fallback |

### Missing Symbols

If you see `[unknown]` in profiles:

1. **Compile with symbols**:
   ```bash
   # Go
   go build -gcflags="-N -l" ./...
   
   # C/C++
   gcc -g -O2 main.c
   
   # Rust
   RUSTFLAGS="-C debuginfo=2" cargo build
   ```

2. **Use debuginfod** (Linux):
   ```bash
   export DEBUGINFOD_URLS="https://debuginfod.elfutils.org/"
   ```

3. **Include frame pointers**:
   ```bash
   # Go
   GOFLAGS="-buildmode=exe" go build
   
   # C/C++
   gcc -fno-omit-frame-pointer main.c
   ```

---

## Java Profiling

Telegen supports two approaches for profiling Java applications:

### Approach Comparison

| Aspect | JFR (Recommended) | eBPF + perf-map-agent |
|--------|-------------------|----------------------|
| **JVM Flag Required** | None | `-XX:+PreserveFramePointer` |
| **JVM Restart** | Not required | Not required |
| **Symbol Accuracy** | Always accurate | Depends on perf-map refresh |
| **GC Events** | ✅ Native | ❌ Not available |
| **Lock Contention** | ✅ Native | ❌ Not available |
| **Kernel Stacks** | ❌ JVM only | ✅ Full system view |
| **Mixed-mode** | ❌ JVM only | ✅ Java + native |
| **Overhead** | ~1% | ~1-2% |

### JFR-Based Profiling (Recommended)

Java Flight Recorder (JFR) is built into the JVM and provides the most accurate profiling:

```yaml
profiles:
  jfr:
    enabled: true
    input_dirs:
      - /var/log/jfr
    # Export as OTLP Logs for unified pipeline
    direct_export:
      log_export:
        enabled: true
        endpoint: "http://otel-collector:4318/v1/logs"
```

JFR provides:
- **Execution samples** - CPU profiling with accurate Java symbols
- **Allocation samples** - Memory allocation tracking
- **Lock contention** - Monitor enter/exit timing
- **GC events** - Garbage collection correlation

### eBPF-Based Java Profiling

For scenarios requiring kernel-level visibility or mixed-mode profiling (Java + native code), use eBPF with perf-map-agent:

```yaml
profiling:
  enabled: true
  cpu:
    enabled: true
  
  # Enable Java symbol resolution for eBPF profiles
  java_ebpf:
    enabled: true
    agent_jar_path: "/opt/perf-map-agent/attach-main.jar"
    agent_lib_path: "/opt/perf-map-agent/libperfmap.so"
    refresh_interval: 60s
    unfold_all: true
    dotted_class: true
  
  # Export as OTLP Logs (same format as JFR)
  log_export:
    enabled: true
    endpoint: "http://otel-collector:4318/v1/logs"
```

**Requirements:**

1. **JVM Flag** - Java applications must be started with:
   ```bash
   java -XX:+PreserveFramePointer -jar myapp.jar
   ```

2. **perf-map-agent** - Install from [jvm-profiling-tools/perf-map-agent](https://github.com/jvm-profiling-tools/perf-map-agent):
   ```bash
   git clone https://github.com/jvm-profiling-tools/perf-map-agent
   cd perf-map-agent
   cmake .
   make
   # Copy to /opt/perf-map-agent/
   ```

**How It Works:**

```{mermaid}
sequenceDiagram
    participant JVM as Java App
    participant Agent as perf-map-agent
    participant Telegen as Telegen eBPF
    participant Map as /tmp/perf-PID.map
    
    Telegen->>Agent: Attach to PID
    Agent->>JVM: JVMTI attach
    JVM->>Agent: JIT method addresses
    Agent->>Map: Write symbol map
    
    loop Profiling
        Telegen->>JVM: eBPF CPU samples
        Telegen->>Map: Resolve addresses
        Telegen->>Telegen: Build profile
    end
```

### Unified OTLP Logs Export

Both JFR and eBPF profiles can export to the same OTLP Logs endpoint using identical `ProfileEvent` JSON format:

```json
{
  "timestamp": "2024-02-05T10:30:00.123Z",
  "eventType": "jdk.ExecutionSample",
  "profileType": "cpu",
  "serviceName": "my-java-app",
  "k8s_pod_name": "my-java-app-7b5f8d4c9b-x2kpq",
  "k8s_namespace": "production",
  "threadName": "main",
  "threadId": 1,
  "topClass": "com.example.MyService",
  "topMethod": "processRequest",
  "stackPath": "processRequest <- handleRequest <- doFilter",
  "stackDepth": 25,
  "sampleWeight": 150,
  "stackTrace": "[{\"class\":\"com.example.MyService\",\"method\":\"processRequest\",\"line\":42}]"
}
```

---

## Performance Overhead

Telegen profiling is designed for production:

| Profile Type | CPU Overhead | Memory Overhead |
|--------------|--------------|-----------------|
| **CPU** | ~1% | 10MB buffer |
| **Off-CPU** | ~0.5% | 10MB buffer |
| **Memory** | ~2% | 20MB buffer |
| **All enabled** | ~3% | 50MB buffer |

### Reducing Overhead

```yaml
agent:
  profiling:
    # Lower sample rate
    sample_rate: 49  # Instead of 99
    
    # Increase upload interval
    upload_interval: 120s  # Instead of 60s
    
    # Disable unused profile types
    mutex: false
    block: false
    goroutine: false
```

---

## Best Practices

### 1. Always Enable CPU and Off-CPU

These two profiles cover most performance issues:

```yaml
agent:
  profiling:
    enabled: true
    cpu: true
    off_cpu: true
```

### 2. Use Appropriate Sample Rates

| Environment | Recommended Rate |
|-------------|-----------------|
| Development | 99 Hz |
| Staging | 49 Hz |
| Production (high volume) | 19 Hz |

### 3. Include Debug Symbols in Production

Build with symbols, then strip for deployment:

```bash
# Build with symbols
go build -o app ./...

# Keep symbols for profiling (in separate file)
objcopy --only-keep-debug app app.debug

# Strip binary
strip app
```

---

## Troubleshooting

### No Profiles Generated

1. **Check eBPF permissions**:
   ```bash
   # Verify perf_event access
   cat /proc/sys/kernel/perf_event_paranoid
   # Should be 1 or less
   ```

2. **Check capabilities**:
   ```bash
   # Container needs CAP_SYS_ADMIN or CAP_PERFMON
   capsh --print | grep -E "sys_admin|perfmon"
   ```

### Missing Stack Frames

1. **Frame pointers disabled** - Rebuild with `-fno-omit-frame-pointer`
2. **JIT code** - Enable JIT symbol mapping
3. **Optimized code** - Some inlined functions won't appear

---

## Next Steps

- {doc}`distributed-tracing` - Correlate profiles with traces
- {doc}`security-observability` - Security event profiling
- {doc}`../configuration/agent-mode` - Full profiling configuration
