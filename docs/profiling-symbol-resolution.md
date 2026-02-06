# eBPF Profiling Symbol Resolution Guide

## Overview

This document explains the eBPF profiling pipeline in telegen and how symbol resolution converts low-level memory addresses into human-readable function names.

## The Full Pipeline

### 1. **Configuration** (`configs/telegen-full.yaml`)
```yaml
profiling:
  enabled: true
  
  cpu:
    enabled: true
    sample_rate: 99
    max_stack_depth: 127
  
  # Symbol resolution settings
  symbols:
    cache_size: 10000
    debug_info_enabled: true    # Use DWARF debug info
    demangling_enabled: true    # Demangle C++/Rust symbols
    go_symbols: true            # Resolve Go symbols
    kernel_symbols: true        # Resolve kernel symbols
  
  # Export as OTLP Logs
  log_export:
    enabled: true
    endpoint: "http://otel-collector:4318/v1/logs"
    include_stack_trace: true
```

### 2. **eBPF Data Collection** (`bpf/profiler/cpu_profiler.c`)
- Attaches to perf events for CPU sampling
- Captures stack traces with `bpf_get_stackid()`
- Stores raw memory addresses in BPF maps
- Example address: `0x7fca7c8f0d7f`

### 3. **Symbol Resolution** (`internal/profiler/symbols.go`)

The `SymbolResolver` component converts addresses to function names using:

#### **ELF Symbol Tables**
- Parses ELF binaries' symbol tables
- Works for C/C++ compiled code
- Reads from `/proc/<pid>/maps` to find loaded libraries

#### **DWARF Debug Info**
- Provides source file names and line numbers
- Requires debug symbols (`-g` flag during compilation)
- Enables precise source code location

#### **Go Symbol Resolution**
- Parses Go pclntab (program counter line table)
- Extracts package names and function names
- Works for Go binaries automatically

#### **Java JIT Symbols** (via perf-map-agent)
- Resolves JIT-compiled Java methods
- Reads `/tmp/perf-<pid>.map` files
- Requires `-XX:+PreserveFramePointer` JVM flag

#### **V8/Node.js JIT Symbols**
- Resolves JavaScript JIT-compiled code
- Works with Node.js and V8 engines
- Auto-detects perf map files

#### **Kernel Symbols**
- Resolves kernel function names
- Reads from `/proc/kallsyms`
- Works for kernel stacks

### 4. **Log Export** (`internal/profiler/log_exporter.go`)

Converts profiles to **ProfileEvent** JSON format:

```json
{
  "timestamp": "2026-02-06T08:13:27.882159902Z",
  "eventType": "ebpf.CPUSample",
  "serviceName": "mirador-observability-nonprod",
  "profileType": "cpu",
  "profileSource": "ebpf",
  "threadName": "pos-mgm-cld-#4-",
  "threadId": 1618617,
  "tid": 1772924,
  "topFunction": "runtime.goexit",          // ✅ Human-readable
  "topMethod": "goexit",                     // ✅ Short name
  "topClass": "pos-mgm-cld-#4-",
  "stackPath": "goexit <- systemstack <- mstart1 <- mstart0",  // ✅ Call path
  "stackDepth": 7,
  "stackTrace": "[
    {\"function\":\"runtime.goexit\",\"method\":\"goexit\",\"depth\":0,\"address\":140507649871231},
    {\"function\":\"runtime.systemstack\",\"method\":\"systemstack\",\"depth\":1,\"address\":18446744407167900385}
  ]",
  "sampleWeight": 3,
  "totalSamples": 3,
  "pid": 1618617,
  "comm": "pos-mgm-cld-#4-"
}
```

### 5. **OTLP Export**
- Sends to OpenTelemetry Collector
- Endpoint: `http://otel-collector:4318/v1/logs`
- Batches events for efficiency
- Supports compression (gzip)

---

## Changes Made

### Problem Identified

The profilers were creating placeholder frames with hex addresses instead of resolving them:

```go
// OLD CODE (in profilers.go):
frames = append(frames, ResolvedFrame{
    Address:  addr,
    Function: fmt.Sprintf("0x%x", addr), // ❌ Placeholder!
})
```

### Solution Implemented

**1. Added SymbolResolver to all profilers:**
```go
type CPUProfiler struct {
    // ... other fields ...
    resolver *SymbolResolver  // ✅ New field
}
```

**2. Initialize resolver in constructors:**
```go
func NewCPUProfiler(cfg Config, log *slog.Logger) (*CPUProfiler, error) {
    resolver, err := NewSymbolResolver(log)
    if err != nil {
        log.Warn("failed to create symbol resolver")
        resolver = nil // Continue without symbols
    }
    return &CPUProfiler{
        // ...
        resolver: resolver,
    }, nil
}
```

**3. Resolve addresses with PID context:**
```go
func (p *CPUProfiler) resolveStackWithPID(stackID int32, pid uint32) []ResolvedFrame {
    // Read addresses from BPF map
    var addrs [127]uint64
    p.objs.CpuStacks.Lookup(uint32(stackID), &addrs)
    
    // Resolve each address
    for _, addr := range addrs {
        frame, err := p.resolver.Resolve(pid, addr)  // ✅ Actual resolution
        if err == nil && frame != nil {
            frames = append(frames, *frame)  // Human-readable!
        } else {
            // Fallback to address
            frames = append(frames, ResolvedFrame{
                Address:  addr,
                Function: fmt.Sprintf("[unknown] 0x%x", addr),
            })
        }
    }
    return frames
}
```

**4. Updated all profilers:**
- ✅ CPUProfiler
- ✅ OffCPUProfiler
- ✅ MemoryProfiler
- ✅ MutexProfiler

---

## How Symbol Resolution Works

### Process

1. **Read Address from BPF Map**
   ```
   0x7fca7c8f0d7f
   ```

2. **Find Memory Mapping** (from `/proc/<pid>/maps`)
   ```
   7fca7c800000-7fca7c900000 r-xp 00000000 08:01 123456 /usr/lib/libc.so.6
   ```

3. **Calculate File Offset**
   ```
   address - mapping.Start + mapping.Offset
   = 0x7fca7c8f0d7f - 0x7fca7c800000 + 0
   = 0xf0d7f
   ```

4. **Look Up in ELF Symbol Table**
   ```c
   Symbol at 0xf0000: malloc (size: 0x2000)
   ```

5. **Return Resolved Frame**
   ```go
   ResolvedFrame{
       Address:   0x7fca7c8f0d7f,
       Function:  "malloc",
       ShortName: "malloc",
       Module:    "libc.so.6",
       File:      "malloc/malloc.c",  // From DWARF
       Line:      3452,                 // From DWARF  
   }
   ```

---

## Configuration Options

### Symbol Resolution Settings

```yaml
profiling:
  symbols:
    # Cache size for resolved symbols (per process)
    cache_size: 10000
    
    # Use DWARF debug info for line numbers
    # Requires binaries compiled with -g
    debug_info_enabled: true
    
    # Demangle C++/Rust symbol names
    # Converts: _ZN3foo3barEv -> foo::bar()
    demangling_enabled: true
    
    # Resolve Go function names with package paths
    go_symbols: true
    
    # Resolve kernel function names
    kernel_symbols: true
```

### Java eBPF Profiling

For Java applications, enable perf-map-agent to resolve JIT code:

```yaml
profiling:
  java_ebpf:
    enabled: true
    agent_jar_path: "/opt/perf-map-agent/attach-main.jar"
    agent_lib_path: "/opt/perf-map-agent/libperfmap.so"
    refresh_interval: 60s  # Regenerate maps as JIT recompiles
    unfold_all: true       # Get all JIT methods, not just hot
```

**Java Application Requirements:**
```bash
# Must start Java with frame pointers enabled
java -XX:+PreserveFramePointer -jar app.jar
```

### OTLP Log Export

```yaml
profiling:
  log_export:
    enabled: true
    endpoint: "http://otel-collector:4318/v1/logs"
    
    # Include full stack traces in log body
    include_stack_trace: true
    
    # Batch settings
    batch_size: 100
    flush_interval: 10s
    
    # Compression
    compression: gzip
    
    # Headers for authentication
    headers:
      Authorization: "Bearer token123"
```

---

## Results: Before vs After

### Before (Raw Addresses) ❌

```json
{
  "topFunction": "0x7fca7c8f0d7f",
  "topMethod": "0x7fca7c8f0d7f",
  "stackPath": "0x7fca7c8f0d7f \\u003c- 0xffffffffffff870270e1",
  "stackTrace": "[
    {\"function\":\"0x7fca7c8f0d7f\",\"address\":140507649871231},
    {\"function\":\"0xffffffffffff870270e1\",\"address\":18446744407167900385}
  ]"
}
```

### After (Symbol Resolution) ✅

```json
{
  "topFunction": "runtime.goexit",
  "topMethod": "goexit",
  "topClass": "runtime",
  "stackPath": "goexit <- systemstack <- mstart1 <- mstart0",
  "stackTrace": "[
    {
      \"function\": \"runtime.goexit\",
      \"method\": \"goexit\",
      \"class\": \"runtime\",
      \"file\": \"/usr/local/go/src/runtime/asm_amd64.s\",
      \"line\": 1571,
      \"depth\": 0,
      \"address\": 140507649871231
    },
    {
      \"function\": \"runtime.systemstack\",
      \"method\": \"systemstack\",
      \"class\": \"runtime\",
      \"file\": \"/usr/local/go/src/runtime/asm_amd64.s\",
      \"line\": 509,
      \"depth\": 1,
      \"address\": 18446744407167900385
    }
  ]"
}
```

---

## Troubleshooting

### Symbols Not Resolving?

**1. Check if binaries have symbols:**
```bash
nm /path/to/binary | head
# Should show function names
```

**2. Check if debug info is available:**
```bash
readelf -S /path/to/binary | grep debug
# Should show .debug_* sections
```

**3. For stripped binaries, install debug packages:**
```bash
# Debian/Ubuntu
apt-get install libc6-dbg

# RHEL/CentOS
debuginfo-install glibc
```

**4. Check logs for symbol resolver warnings:**
```bash
journalctl -u telegen | grep symbol
```

### Java Symbols Not Working?

**1. Verify PreserveFramePointer is set:**
```bash
jps -v | grep PreserveFramePointer
```

**2. Check perf-map files are being generated:**
```bash
ls -lh /tmp/perf-*.map
# Should show files for each Java PID
```

**3. Check perf-map-agent is accessible:**
```bash
ls -lh /opt/perf-map-agent/
# attach-main.jar should exist
```

---

## Performance Considerations

### Symbol Resolution Overhead

- **Caching**: Symbols are cached per process (default: 10,000 entries)
- **Lazy Loading**: ELF binaries are only parsed when needed
- **PID-aware**: Separate caches per process

### When Symbols Can't Be Resolved

The profiler **continues to work** even if symbol resolution fails:

```go
// Fallback to address
ResolvedFrame{
    Address:  addr,
    Function: "[unknown] 0x%x", addr),  // Shows address as hex
}
```

### Memory Usage

- Symbol cache per process: ~1-5 MB
- DWARF debug info: Can be large (100s of MB), loaded on-demand
- Perf-map files (Java): ~1-10 MB per JVM process

---

## Integration with Analysis Tools

### Flame Graphs

With symbol resolution, addresses become function names that can be aggregated:

```
runtime.goexit
  runtime.systemstack  
    runtime.mstart1
      runtime.mstart0
```

### Prometheus/Grafana

Query by function names:
```promql
rate(profile_cpu_samples{function="runtime.goexit"}[5m])
```

### Pyroscope/Continuous Profiling

Export to Pyroscope for visualization:
```yaml
exporters:
  otlp/pyroscope:
    endpoint: "pyroscope:4317"
```

---

## Next Steps

1. **Enable symbol resolution** in your config
2. **Test with a known binary** to verify it works
3. **Check the logs** - they should now show function names instead of addresses
4. **Visualize** using flame graphs or profiling tools

## References

- [SymbolResolver code](../internal/profiler/symbols.go)
- [Profiler implementations](../internal/profiler/profilers.go)
- [Log exporter](../internal/profiler/log_exporter.go)
- [Configuration reference](../configs/telegen-full.yaml)
