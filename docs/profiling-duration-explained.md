# Understanding Duration in eBPF Profiling

## Overview

eBPF profiling uses **sampling** rather than **instrumentation**, which fundamentally affects how duration/time is measured and reported.

## Quick Reference: Duration by Profile Type

| Profile Type | Duration Meaning | Calculation Method | Precision |
|--------------|------------------|-------------------|-----------|
| **cpu** | On-CPU time | Sample count × sample period | Estimated |
| **offcpu** | Blocked/waiting time | Kernel timestamps (wake - sleep) | Precise |
| **mutex** | Lock wait time | Kernel timestamps (acquire - attempt) | Precise |
| **block** | Go blocking time | Kernel timestamps | Precise |
| **wall** | Total wall-clock time | On-CPU + Off-CPU combined | Varies |
| **memory** | N/A (bytes) | Use `allocationSize` field | N/A |
| **heap** | N/A (bytes) | Use `allocationSize` field | N/A |
| **alloc_count** | N/A (bytes) | Use `allocationSize` field | N/A |

## Duration by Profile Type

### 1. CPU Profiling (Sample-Based)

**How it works:**
- Samples stack traces at regular intervals (e.g., 99 Hz = every ~10.1ms)
- If a function appears in N samples, it was "on-CPU" during those sample periods
- Duration is **estimated**, not measured directly

**Duration calculation:**
```
durationNs = sample_count × (1,000,000,000 / sample_rate_hz)

Example at 99 Hz:
- 1 sample  ≈ 10,101,010 ns (10.1 ms)
- 10 samples ≈ 101,010,100 ns (101 ms)
- 100 samples ≈ 1,010,101,000 ns (1.01 seconds)
```

**Example log:**
```json
{
  "profileType": "cpu",
  "topFunction": "runtime.scanobject",
  "sampleWeight": 15,
  "durationNs": 151515150,  // 15 samples × 10.1ms = ~151ms on-CPU
  "totalSamples": 15
}
```

**Important:**
- Duration represents **on-CPU time**, not wall-clock time
- If function is blocked/sleeping, it won't appear in CPU samples
- Accuracy improves with higher sample rates (but higher overhead)

### 2. Off-CPU Profiling (Event-Based)

**How it works:**
- Tracks when threads block (sleep, I/O, locks)
- Measures **actual block duration** using kernel timestamps
- Duration is **precise**, not estimated

**Duration calculation:**
```
durationNs = wake_timestamp - sleep_timestamp
```

**Example log:**
```json
{
  "profileType": "offcpu",
  "topFunction": "runtime.futex",
  "blockReason": "mutex",
  "durationNs": 2184751,  // Was blocked for 2.18ms (precise measurement)
  "sampleWeight": 2184751
}
```

**Important:**
- Duration is the **actual time blocked**, not sampled
- Useful for finding I/O bottlenecks, lock contention
- Complements CPU profiling (CPU = active, Off-CPU = waiting)

### 3. Memory Profiling

**How it works:**
- Tracks allocation events
- **No duration concept** - allocations are instantaneous events

**Relevant fields:**
```json
{
  "profileType": "memory",
  "topFunction": "runtime.mallocgc",
  "allocationSize": 8192,  // 8KB allocated
  "sampleWeight": 8192,
  "durationNs": 0  // Not applicable for allocations
}
```

**Variants:**
- `memory` - Real-time allocation tracking
- `heap` - Live allocations snapshot
- `alloc_count` - Aggregated allocation statistics
- `alloc_bytes` - Aggregated byte allocation statistics

**Important:**
- Focus on `allocationSize` (bytes) not duration
- Shows memory pressure, not time spent allocating

### 4. Mutex/Lock Contention

**How it works:**
- Tracks time waiting for locks
- Measures **actual wait time** using timestamps

**Duration calculation:**
```
durationNs = lock_acquired_time - lock_attempt_time
```

**Example log:**
```json
{
  "profileType": "mutex",
  "topFunction": "sync.(*Mutex).Lock",
  "durationNs": 5234512,  // Waited 5.23ms for lock (precise)
  "sampleWeight": 5234512
}
```

### 5. Block Profiling

**How it works:**
- Similar to off-CPU but tracks Go-specific blocking operations
- Measures **actual blocked time** using timestamps

**Example log:**
```json
{
  "profileType": "block",
  "topFunction": "runtime.chanrecv1",
  "durationNs": 3456789,  // Blocked for 3.46ms on channel receive
  "blockReason": "block",
  "sampleWeight": 3456789
}
```

### 6. Wall Clock Profiling

**How it works:**
- Tracks total wall-clock time spent in functions
- Combines on-CPU and off-CPU time

**Example log:**
```json
{
  "profileType": "wall",
  "topFunction": "main.processRequest",
  "durationNs": 125000000,  // Total 125ms wall time
  "sampleWeight": 125000000
}
```

## Complete Example Logs

### CPU Profile (High CPU usage)
```json
{
  "timestamp": "2026-02-06T08:13:27.882Z",
  "eventType": "ebpf.CPUSample",
  "profileType": "cpu",
  "resolutionStatus": "resolved",
  
  "topFunction": "crypto/sha256.block",
  "topMethod": "block",
  "stackDepth": 8,
  
  "sampleWeight": 250,       // 250 samples captured
  "durationNs": 2525252500,  // 250 × 10.1ms = 2.52 seconds on-CPU
  "totalSamples": 250,
  
  "pid": 12345,
  "comm": "api-server",
  
  "stackFrames": [
    {"function": "crypto/sha256.block", "resolved": true},
    {"function": "crypto/sha256.Sum256", "resolved": true},
    {"function": "main.hashPassword", "resolved": true}
  ]
}
```

**Interpretation:** The `hashPassword` function spent approximately 2.52 seconds of CPU time in `sha256.block`, appearing in 250 samples at 99 Hz.

### Off-CPU Profile (I/O wait)
```json
{
  "timestamp": "2026-02-06T08:13:28.123Z",
  "eventType": "ebpf.OffCPUSample",
  "profileType": "offcpu",
  "resolutionStatus": "resolved",
  
  "topFunction": "internal/poll.(*pollDesc).wait",
  "topMethod": "wait",
  "stackDepth": 12,
  
  "sampleWeight": 1,
  "durationNs": 45123456,  // Blocked for exactly 45.12ms
  "blockReason": "io",
  
  "pid": 12345,
  "comm": "api-server",
  
  "stackFrames": [
    {"function": "internal/poll.(*pollDesc).wait", "resolved": true},
    {"function": "net.(*netFD).Read", "resolved": true},
    {"function": "http.(*conn).serve", "resolved": true}
  ]
}
```

**Interpretation:** The thread was blocked for exactly 45.12ms waiting for network I/O.

## Calculating Function Performance

### On-CPU Time (CPU Profile)
```
Total on-CPU time = Σ(durationNs for all CPU samples of that function)
Percentage = (function_cpu_time / total_cpu_time) × 100%
```

### Blocked Time (Off-CPU Profile)
```
Total blocked time = Σ(durationNs for all Off-CPU samples of that function)
```

### Combined Analysis
For complete function performance, analyze both:

```python
# Total wall-clock time
total_time = cpu_time + offcpu_time

# Example:
function_cpu_time = 2.5 seconds     # From CPU profile
function_blocked_time = 45 seconds  # From Off-CPU profile
function_total_time = 47.5 seconds  # Wall-clock time

# Time breakdown:
cpu_percentage = (2.5 / 47.5) × 100% = 5.3%    # Actively computing
wait_percentage = (45 / 47.5) × 100% = 94.7%  # Waiting on I/O/locks
```

## Querying Duration in Logs

### Example Loki/LogQL Queries

```logql
# Find functions with high CPU time
{app="profiler"} 
  | json 
  | profileType="cpu" 
  | durationNs > 1000000000  # > 1 second
  | topFunction != ""

# Find I/O bottlenecks
{app="profiler"} 
  | json 
  | profileType="offcpu" 
  | blockReason="io"
  | durationNs > 100000000  # > 100ms blocked

# Find lock contention
{app="profiler"} 
  | json 
  | profileType="mutex"
  | durationNs > 10000000  # > 10ms waiting for lock
```

### Example Elasticsearch Queries

```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"profileType": "cpu"}},
        {"range": {"durationNs": {"gte": 1000000000}}}
      ]
    }
  },
  "aggs": {
    "top_functions": {
      "terms": {"field": "topFunction.keyword"},
      "aggs": {
        "total_cpu_time": {"sum": {"field": "durationNs"}}
      }
    }
  }
}
```

## Important Considerations

### 1. Sampling Overhead vs Accuracy

| Sample Rate | Period | Overhead | Accuracy |
|-------------|--------|----------|----------|
| 49 Hz | ~20ms | Very Low | Lower |
| 99 Hz | ~10ms | Low | Good |
| 249 Hz | ~4ms | Medium | Better |
| 999 Hz | ~1ms | High | Best |

**Recommendation:** 99 Hz is the sweet spot for production.

### 2. Short-lived Functions

Functions that execute in < sample_period may not be captured:
- At 99 Hz (10ms period), functions < 10ms may be missed
- Increase sample rate if profiling microsecond-level operations
- Or use instrumentation/tracing for sub-millisecond precision

### 3. Duration vs Sample Count

Both fields are provided for flexibility:

```json
{
  "sampleWeight": 100,      // Raw sample count
  "durationNs": 1010101000, // Calculated duration
  "totalSamples": 100       // Same as sampleWeight
}
```

Use `sampleWeight` to:
- Calculate percentages relative to other samples
- Understand sampling frequency

Use `durationNs` to:
- Report actual time metrics
- Set SLO thresholds
- Compare across different sample rates

## Advanced: Flame Graphs

Duration values are used to size flame graph blocks:

```
Width of flame graph segment = (function_durationNs / total_durationNs) × 100%
```

A function taking 2 seconds of 10 total seconds = 20% width in flame graph.

## References

- [Brendan Gregg - CPU Flame Graphs](http://www.brendangregg.com/FlameGraphs/cpuflamegraphs.html)
- [Off-CPU Analysis](http://www.brendangregg.com/offcpuanalysis.html)
- [Linux perf profiling](https://perf.wiki.kernel.org/index.php/Tutorial)
