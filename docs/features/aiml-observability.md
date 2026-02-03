# AI/ML Observability

Telegen provides observability for AI/ML workloads, including GPU monitoring and LLM inference metrics.

## Overview

AI/ML observability includes:

- **GPU monitoring** - NVIDIA and AMD GPU metrics
- **LLM inference** - Token throughput, latency, TTFT
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

```yaml
agent:
  gpu:
    enabled: true
    
    # NVIDIA support
    nvidia: true
    
    # AMD support (via ROCm SMI)
    amd: false
    
    # Polling interval
    poll_interval: 10s
    
    # Metrics to collect
    metrics:
      utilization: true
      memory: true
      temperature: true
      power: true
      clock: true
      pcie_throughput: true
      encoder_decoder: true
      
    # Per-process tracking
    per_process: true
```

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

```yaml
agent:
  gpu:
    enabled: true
    nvidia: false
    amd: true
    poll_interval: 10s
```

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

```yaml
agent:
  aiml:
    frameworks:
      vllm:
        enabled: true
        # Collect all vLLM metrics
        metrics:
          - request_duration
          - time_to_first_token
          - tokens_per_second
          - kv_cache_usage
          - batch_size
```

### Triton Integration

```yaml
agent:
  aiml:
    frameworks:
      triton:
        enabled: true
        metrics_endpoint: "http://localhost:8002/metrics"
```

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

```yaml
agent:
  aiml:
    training:
      enabled: true
      
      # Detect common training frameworks
      detect_frameworks:
        - pytorch
        - tensorflow
        - jax
      
      # Log training metrics to OTLP
      export_metrics: true
```

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

### 1. Enable Per-Process Tracking

Identify which processes use GPU resources:

```yaml
agent:
  gpu:
    per_process: true
```

### 2. Monitor KV Cache

KV cache is critical for LLM performance:

```promql
# Alert when KV cache is near capacity
llm_kv_cache_usage_bytes / llm_kv_cache_capacity_bytes > 0.9
```

### 3. Correlate with Traces

Link inference metrics to traces:

```yaml
agent:
  aiml:
    # Add trace context to LLM metrics
    trace_correlation: true
```

---

## Next Steps

- {doc}`continuous-profiling` - Profile GPU workloads
- {doc}`../configuration/agent-mode` - GPU configuration
- {doc}`../operations/monitoring` - GPU dashboards
