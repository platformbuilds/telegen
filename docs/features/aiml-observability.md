# AI/ML Observability

Telegen provides comprehensive observability for AI/ML workloads: GPU monitoring, LLM API tracing via eBPF, inference metrics, and training observability.

## Overview

AI/ML observability includes:

- **GPU monitoring** - NVIDIA and AMD GPU metrics via NVML
- **LLM API tracing** - eBPF-based tracing for OpenAI, Anthropic, Azure, and other LLM APIs (HTTP enrichment)
- **LLM inference** - Token throughput, latency, TTFT, cost estimation
- **CUDA tracing** - Kernel launches, memory operations as spans
- **Model serving** - Batch size, queue depth, inference time
- **Training metrics** - Loss, throughput, GPU utilization

---

## GPU Monitoring

### NVIDIA GPU Metrics

Telegen collects NVIDIA GPU metrics via NVML (NVIDIA Management Library):

| Metric | Description |
|--------|-------------|
| `gpu_utilization_percent` | GPU compute utilization |
| `gpu_memory_used_bytes` | GPU memory used |
| `gpu_memory_total_bytes` | GPU memory total |
| `gpu_memory_free_bytes` | GPU memory free |
| `gpu_temperature_celsius` | GPU temperature |
| `gpu_power_usage_watts` | Current power draw |
| `gpu_power_limit_watts` | Power limit |
| `gpu_sm_clock_hz` | Streaming multiprocessor clock |
| `gpu_memory_clock_hz` | Memory clock |
| `gpu_pcie_tx_bytes` | PCIe transmit throughput |
| `gpu_pcie_rx_bytes` | PCIe receive throughput |
| `gpu_encoder_utilization_percent` | Video encoder utilization |
| `gpu_decoder_utilization_percent` | Video decoder utilization |

### Per-Process GPU Metrics

Track GPU usage per process:

| Metric | Description |
|--------|-------------|
| `gpu_process_memory_bytes` | Memory used by process |
| `gpu_process_sm_utilization_percent` | SM utilization by process |

### Configuration

GPU collection is automatic. The GPU adapter is registered at startup and
activates whenever a supported device and its driver library are present, so
there is no `gpu` configuration section, no polling interval, and no per-metric
toggle. Adding those keys stops the agent from starting.

---

## AMD GPU Metrics

For AMD GPUs, Telegen uses ROCm SMI:

| Metric | Description |
|--------|-------------|
| `gpu_utilization_percent` | GPU utilization |
| `gpu_memory_used_bytes` | VRAM used |
| `gpu_memory_total_bytes` | VRAM total |
| `gpu_temperature_celsius` | GPU temperature |
| `gpu_power_usage_watts` | Power consumption |
| `gpu_fan_speed_percent` | Fan speed |

### Configuration

AMD collection follows the same rule as NVIDIA: it is detected and enabled
automatically, with no configuration section.

---

## LLM Inference Metrics

Track LLM inference performance:

### Key Metrics

| Metric | Description |
|--------|-------------|
| `llm_request_total` | Total inference requests |
| `llm_request_duration_seconds` | End-to-end request duration |
| `llm_time_to_first_token_seconds` | Time to first token (TTFT) |
| `llm_inter_token_latency_seconds` | Time between tokens |
| `llm_tokens_generated_total` | Total tokens generated |
| `llm_tokens_per_second` | Token generation throughput |
| `llm_prompt_tokens_total` | Input prompt tokens |
| `llm_queue_depth` | Requests waiting in queue |
| `llm_batch_size` | Current batch size |
| `llm_kv_cache_usage_bytes` | KV cache memory usage |

### Example Metrics

```promql
# Average time to first token
histogram_quantile(0.95, 
  sum(rate(llm_time_to_first_token_seconds_bucket[5m])) by (le, model)
)

# Token throughput
sum(rate(llm_tokens_generated_total[5m])) by (model)

# Request rate by model
sum(rate(llm_request_total[5m])) by (model)

# Queue depth
llm_queue_depth{model="llama-3-70b"}
```

### Labels

| Label | Description |
|-------|-------------|
| `model` | Model name/version |
| `instance` | Server instance |
| `gpu` | GPU device index |

---

## LLM API Tracing (eBPF)

Telegen traces LLM API calls at the HTTP layer using eBPF uprobes and generic TCP tracing. This captures requests to OpenAI, Anthropic, Azure OpenAI, and other LLM providers without any SDK changes.

### How It Works

1. **HTTP enrichment** — `internal/ebpf/common/http/genai_parsers.go` parses LLM API request/response payloads
2. **Partial JSON parsing** — `internal/ebpf/common/http/partial_json.go` handles streaming JSON responses (SSE/streaming)
3. **Payload extraction** — `internal/obiconfig/payload_extraction.go` extracts token counts, model names, and latency from HTTP bodies
4. **Span generation** — LLM API calls are converted to OTLP spans with GenAI semantic conventions

### Captured Attributes

| Attribute | Description |
|-----------|-------------|
| `gen_ai.system` | LLM provider (openai, anthropic, azure_openai, etc.) |
| `gen_ai.request.model` | Model name (gpt-4, claude-3-opus, etc.) |
| `gen_ai.request.temperature` | Sampling temperature |
| `gen_ai.request.max_tokens` | Max tokens requested |
| `gen_ai.response.id` | Response ID |
| `gen_ai.response.model` | Model used (may differ from request) |
| `gen_ai.usage.input_tokens` | Prompt tokens |
| `gen_ai.usage.output_tokens` | Completion tokens |
| `gen_ai.usage.total_tokens` | Total tokens |
| `gen_ai.response.finish_reason` | stop, length, content_filter, etc. |
| `gen_ai.operation.name` | chat, completion, embedding, etc. |

### Sample Span

```yaml
span:
  name: "openai.chat.completions"
  kind: CLIENT
  duration_ms: 1250
  attributes:
    gen_ai.system: "openai"
    gen_ai.request.model: "gpt-4"
    gen_ai.request.temperature: 0.7
    gen_ai.usage.input_tokens: 150
    gen_ai.usage.output_tokens: 350
    gen_ai.usage.total_tokens: 500
    gen_ai.response.finish_reason: "stop"
    http.request.method: "POST"
    url.full: "https://api.openai.com/v1/chat/completions"
```

### Cost Estimation

Telegen calculates estimated API costs per request:

```yaml
span:
  attributes:
    gen_ai.usage.input_tokens: 150
    gen_ai.usage.output_tokens: 350
    gen_ai.cost.input_cost_usd: 0.0003    # $0.50/1M input tokens
    gen_ai.cost.output_cost_usd: 0.0035    # $10.00/1M output tokens
    gen_ai.cost.total_cost_usd: 0.0038
```

Configure cost rates in `api/config.example.yaml`:

```yaml
aiml:
  llm:
    cost_rates:
      "openai/gpt-4":
        input_cost_per_1m: 0.50
        output_cost_per_1m: 10.00
      "openai/gpt-3.5-turbo":
        input_cost_per_1m: 0.50
        output_cost_per_1m: 1.50
      "anthropic/claude-3-opus":
        input_cost_per_1m: 15.00
        output_cost_per_1m: 75.00
```

### Streaming Support

TeleMgen traces streaming LLM responses (SSE - Server-Sent Events):

- **Time-to-first-token (TTFT)** is captured from the first SSE chunk
- **Inter-token latency** is calculated from chunk intervals
- The span duration covers the entire streaming response

---

## CUDA Kernel Tracing

Telegen traces CUDA operations as spans using eBPF (`gpuevent` tracer):

### Captured Operations

| Operation | Span Name | Attributes |
|-----------|-----------|------------|
| `cudaLaunchKernel` | `cuda.kernel.launch` | grid/block dimensions, shared memory |
| `cudaMemcpy` | `cuda.memcpy` | direction (H2D, D2H, D2D), bytes copied |
| `cudaMalloc` | `cuda.malloc` | bytes allocated |
| `cudaFree` | `cuda.free` | bytes freed |

### Sample CUDA Span

```yaml
span:
  name: "cuda.kernel.launch"
  kind: INTERNAL
  duration_ms: 0.05
  attributes:
    cuda.kernel.name: "matmul_kernel"
    cuda.kernel.grid.x: 256
    cuda.kernel.grid.y: 1
    cuda.kernel.grid.z: 1
    cuda.kernel.block.x: 32
    cuda.kernel.block.y: 32
    cuda.kernel.shared_memory: 4096
    gpu.device.id: 0
    gpu.device.name: "NVIDIA A100-SXM4-80GB"
```

---

## OpenTelemetry GenAI Semantic Conventions

Telegen uses the [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) for all LLM spans. This ensures compatibility with GenAI observability backends (LangSmith, Helicone, etc.).

### Supported GenAI Attributes

| Attribute | Status | Description |
|-----------|--------|-------------|
| `gen_ai.system` | ✅ | LLM provider |
| `gen_ai.request.model` | ✅ | Model name |
| `gen_ai.request.temperature` | ✅ | Sampling temperature |
| `gen_ai.request.max_tokens` | ✅ | Max tokens |
| `gen_ai.response.model` | ✅ | Response model |
| `gen_ai.usage.input_tokens` | ✅ | Input token count |
| `gen_ai.usage.output_tokens` | ✅ | Output token count |
| `gen_ai.usage.total_tokens` | ✅ | Total token count |
| `gen_ai.response.finish_reason` | ✅ | Completion reason |
| `gen_ai.operation.name` | ✅ | Operation type |
| `gen_ai.tool.name` | 🚧 | Tool/function calls (planned) |
| `gen_ai.prompt.template` | 🚧 | Prompt template (planned) |

---

## Model Serving Frameworks

### Supported Frameworks

| Framework | Auto-Instrumentation |
|-----------|---------------------|
| **vLLM** | ✅ Full metrics |
| **TGI (Text Generation Inference)** | ✅ Full metrics |
| **NVIDIA Triton** | ✅ Full metrics |
| **TensorFlow Serving** | ✅ Basic metrics |
| **TorchServe** | ✅ Basic metrics |
| **ONNX Runtime** | ✅ Basic metrics |

### vLLM Integration

vLLM is recognised from its serving process, and request duration, time to first
token, tokens per second, KV cache usage, and batch size are collected without
configuration. There is no `aiml` section to enable or tune it.

### Triton Integration

Triton is likewise detected automatically. Its metrics endpoint is discovered
from the running server rather than configured.

---

## Training Observability

Monitor ML training jobs:

### Metrics

| Metric | Description |
|--------|-------------|
| `training_loss` | Current training loss |
| `training_step` | Current training step |
| `training_epoch` | Current epoch |
| `training_learning_rate` | Current learning rate |
| `training_throughput_samples_per_second` | Training throughput |
| `training_gpu_utilization_percent` | GPU utilization during training |
| `training_gradient_norm` | Gradient norm |

### Configuration

PyTorch, TensorFlow, and JAX training jobs are detected from the running
process. Training metrics are exported through the normal metrics pipeline with
no dedicated configuration section.

---

## Multi-GPU Monitoring

### GPU Labels

All GPU metrics include device labels:

```yaml
gpu_utilization_percent{
  device="0",
  name="NVIDIA A100-SXM4-80GB",
  uuid="GPU-abc123",
  k8s_pod="llm-server-abc"
} 85.5
```

### Multi-Node Training

Track distributed training across nodes:

```promql
# Total GPU utilization across all training nodes
sum(gpu_utilization_percent{job="distributed-training"})

# GPU memory per node
gpu_memory_used_bytes{job="distributed-training"} by (node)

# Communication overhead (NCCL)
rate(gpu_nccl_send_bytes_total[5m]) + rate(gpu_nccl_recv_bytes_total[5m])
```

---

## Alerting Examples

### GPU Alerts

```yaml
groups:
  - name: gpu
    rules:
      - alert: GPUHighTemperature
        expr: gpu_temperature_celsius > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "GPU {{ $labels.device }} temperature is {{ $value }}°C"
      
      - alert: GPUOutOfMemory
        expr: gpu_memory_used_bytes / gpu_memory_total_bytes > 0.95
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "GPU {{ $labels.device }} memory is {{ $value | humanizePercentage }}"
      
      - alert: GPULowUtilization
        expr: gpu_utilization_percent < 10
        for: 30m
        labels:
          severity: info
        annotations:
          summary: "GPU {{ $labels.device }} underutilized"
```

### LLM Alerts

```yaml
groups:
  - name: llm
    rules:
      - alert: LLMHighLatency
        expr: histogram_quantile(0.95, rate(llm_request_duration_seconds_bucket[5m])) > 30
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "LLM P95 latency is {{ $value | humanizeDuration }}"
      
      - alert: LLMHighQueueDepth
        expr: llm_queue_depth > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "LLM queue depth is {{ $value }}"
      
      - alert: LLMSlowTTFT
        expr: histogram_quantile(0.95, rate(llm_time_to_first_token_seconds_bucket[5m])) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "LLM time-to-first-token P95 is {{ $value | humanizeDuration }}"
```

---

## Kubernetes GPU Support

### NVIDIA GPU Operator

When using NVIDIA GPU Operator in Kubernetes:

```yaml
# DaemonSet config
spec:
  containers:
    - name: telegen
      resources:
        limits:
          nvidia.com/gpu: 0  # Don't request GPU, just monitor
      volumeMounts:
        # Mount NVML socket
        - name: nvidia-mps
          mountPath: /var/run/nvidia
  volumes:
    - name: nvidia-mps
      hostPath:
        path: /var/run/nvidia
```

### MIG (Multi-Instance GPU) Support

Monitor MIG partitions:

```yaml
gpu_utilization_percent{
  device="0",
  mig_device="mig-1g.5gb-0",
  mig_profile="1g.5gb"
} 75.2
```

---

## Dashboard Examples

### GPU Overview

```promql
# GPU fleet summary
sum(gpu_utilization_percent) by (name) / count(gpu_utilization_percent) by (name)

# Memory pressure
sum(gpu_memory_used_bytes) / sum(gpu_memory_total_bytes) * 100

# Power efficiency (tokens per watt)
sum(rate(llm_tokens_generated_total[5m])) / sum(gpu_power_usage_watts)
```

### LLM Performance

```promql
# Requests per second
sum(rate(llm_request_total[5m])) by (model)

# Token generation rate
sum(rate(llm_tokens_generated_total[5m])) by (model)

# Latency percentiles
histogram_quantile(0.50, sum(rate(llm_request_duration_seconds_bucket[5m])) by (le, model))
histogram_quantile(0.95, sum(rate(llm_request_duration_seconds_bucket[5m])) by (le, model))
histogram_quantile(0.99, sum(rate(llm_request_duration_seconds_bucket[5m])) by (le, model))
```

---

## Best Practices

### 1. Use Per-Process Tracking

Per-process GPU attribution is always on. Use the `gpu_process_*` metrics to
identify which processes consume GPU resources.

### 2. Monitor KV Cache

KV cache is critical for LLM performance:

```promql
# Alert when KV cache is near capacity
llm_kv_cache_usage_bytes / llm_kv_cache_capacity_bytes > 0.9
```

### 3. Correlate with Traces

Inference metrics carry the trace context of the request that produced them, so
they join to spans on `trace_id` without any extra configuration.

---

## Next Steps

- {doc}`continuous-profiling` - Profile GPU workloads
- {doc}`../configuration/agent-mode` - GPU configuration
- {doc}`../operations/monitoring` - GPU dashboards
