# Profiling Stripped Binaries - Troubleshooting Guide

## Problem

You're seeing hex addresses (e.g., `0x48c02e`, `0x7f7153439edd`) instead of function names in profiling logs, and the `resolutionStatus` field shows `"unresolved"`.

## Root Cause

Your application binaries are **stripped** - they don't contain symbol tables or debug information. This is common in production builds for:
- Smaller binary sizes
- Security through obscurity
- Faster loading times

## Solutions

### 1. Build with Debug Symbols (Recommended)

#### Go Applications
```bash
# Don't use -ldflags="-s -w" which strips symbols
go build -o myapp main.go

# Keep symbols while still optimizing
go build -ldflags="-w" -o myapp main.go  # strips DWARF only, keeps symbols
```

#### C/C++ Applications
```bash
# Include debug symbols
gcc -g -O2 -o myapp main.c

# Or with separate debug file
gcc -g -O2 -o myapp main.c
objcopy --only-keep-debug myapp myapp.debug
objcopy --strip-debug myapp
```

#### Rust Applications
```toml
# In Cargo.toml
[profile.release]
debug = true  # Include debug symbols in release builds
strip = false
```

### 2. Use Separate Debug Symbol Files

For stripped production binaries, you can provide debug symbols separately:

```bash
# Create debug symbol file
objcopy --only-keep-debug /usr/bin/myapp /usr/lib/debug/usr/bin/myapp.debug

# Telegen will automatically look in standard debug directories:
# - /usr/lib/debug/
# - /usr/local/lib/debug/
```

### 3. Enable Kernel Symbol Maps

For kernel code (when profiling shows kernel addresses):

```yaml
# In telegen config
profiling:
  symbols:
    kernel: true
    kallsyms_path: /proc/kallsyms
```

### 4. Java Applications with JIT Compilation

For Java apps, ensure perf-map-agent is configured:

```yaml
profiling:
  java_ebpf:
    enabled: true
    agent_jar_path: /opt/perf-map-agent/attach-main.jar
    agent_lib_path: /opt/perf-map-agent/libperfmap.so
```

## Verification

### Check if Binary is Stripped

```bash
# Check binary type
file /proc/<pid>/exe

# If output contains "stripped" → no symbols
# If output contains "not stripped" → has symbols

# List symbols in binary
nm /proc/<pid>/exe

# Check for debug info
readelf -S /proc/<pid>/exe | grep debug
```

### Monitor Resolution Status

Check your profiling logs for the `resolutionStatus` field:

```json
{
  "resolutionStatus": "resolved",  // ✅ Good - symbols found
  "topFunction": "runtime.schedule",
  "topMethod": "schedule"
}
```

vs

```json
{
  "resolutionStatus": "unresolved",  // ❌ Bad - stripped binary
  "topFunction": "[unknown] 0x48c02e",
  "topMethod": "[unknown] 0x48c02e"
}
```

### Telegen Logs

Watch for warnings in Telegen logs:

```bash
kubectl logs telegen-pod | grep "stripped binary"
# Output: WARN profiling stripped binary without debug symbols pid=12345 comm=myapp
```

## Impact of Stripped Binaries

### What Still Works ✅
- Profile data collection continues
- Sample counts and timing are accurate
- CPU time, block time, allocation size are correct
- Process/thread information is available

### What Doesn't Work ❌
- Function names (shows hex addresses)
- Source file names and line numbers
- Meaningful stack traces
- Flame graph generation with proper labels

## Best Practices

### Development
- Always build with debug symbols (`-g` flag)
- Keep symbols in development and staging environments

### Production
If you must strip binaries:

1. **Keep debug symbol files** in a separate repository
2. **Use build IDs** to match binaries to their symbols
3. **Enable kernel symbols** for system-level profiling
4. **Consider** keeping symbols for critical services

### CI/CD Pipeline

```bash
# Build with symbols
go build -o myapp main.go

# Create two artifacts
cp myapp myapp-symbols
strip myapp  # Stripped for deployment

# Store myapp-symbols for post-processing
upload_to_artifact_store myapp-symbols
```

## Advanced: Post-Processing with Symbols

If you have stripped binaries in production but symbols elsewhere:

```bash
# Collect raw addresses from profiling data
# Match with debug symbols offline
# Re-symbolize stack traces post-collection
```

This is beyond Telegen's scope but can be done with tools like:
- `addr2line` (for C/C++)
- `go tool addr2line` (for Go)
- Flamegraph tools with symbol servers

## References

- [Linux perf documentation](https://perf.wiki.kernel.org/index.php/Main_Page)
- [Go pprof and symbols](https://go.dev/blog/pprof)
- [DWARF debugging format](http://dwarfstd.org/)
