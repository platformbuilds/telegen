package converters

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// GPUConverter converts GPU/AI-ML traces and metrics to OTLP format.
type GPUConverter struct {
	// IncludeKernelDetails includes detailed kernel launch information.
	IncludeKernelDetails bool
	// TrackMemoryAllocations tracks GPU memory allocations.
	TrackMemoryAllocations bool
}

// GPUEvent represents a GPU event from eBPF tracing.
type GPUEvent struct {
	Type      GPUEventType           `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration,omitempty"`
	DeviceID  int                    `json:"deviceId"`
	Process   *GPUProcessInfo        `json:"process,omitempty"`
	Details   map[string]interface{} `json:"details"`
}

// GPUEventType represents types of GPU events.
type GPUEventType string

const (
	// CUDA events.
	GPUEventKernelLaunch    GPUEventType = "cuda_kernel_launch"
	GPUEventMemcpyHtoD      GPUEventType = "cuda_memcpy_htod"
	GPUEventMemcpyDtoH      GPUEventType = "cuda_memcpy_dtoh"
	GPUEventMemcpyDtoD      GPUEventType = "cuda_memcpy_dtod"
	GPUEventMemAlloc        GPUEventType = "cuda_mem_alloc"
	GPUEventMemFree         GPUEventType = "cuda_mem_free"
	GPUEventSynchronize     GPUEventType = "cuda_synchronize"
	GPUEventStreamCreate    GPUEventType = "cuda_stream_create"
	GPUEventStreamDestroy   GPUEventType = "cuda_stream_destroy"

	// LLM inference events.
	GPUEventLLMInference    GPUEventType = "llm_inference"
	GPUEventLLMTokenize     GPUEventType = "llm_tokenize"
	GPUEventLLMDecode       GPUEventType = "llm_decode"
	GPUEventLLMBatchProcess GPUEventType = "llm_batch_process"

	// AI/ML framework events.
	GPUEventTensorOp        GPUEventType = "tensor_operation"
	GPUEventMatmul          GPUEventType = "matmul"
	GPUEventConvolution     GPUEventType = "convolution"
	GPUEventPooling         GPUEventType = "pooling"
	GPUEventNormalization   GPUEventType = "normalization"
	GPUEventActivation      GPUEventType = "activation"
)

// GPUProcessInfo contains process information for GPU events.
type GPUProcessInfo struct {
	PID     int    `json:"pid"`
	Comm    string `json:"comm"`
	Exe     string `json:"exe,omitempty"`
}

// GPUEventBatch represents a batch of GPU events.
type GPUEventBatch struct {
	Events     []GPUEvent     `json:"events"`
	DeviceInfo []GPUDeviceInfo `json:"deviceInfo,omitempty"`
}

// GPUDeviceInfo contains GPU device information.
type GPUDeviceInfo struct {
	DeviceID     int    `json:"deviceId"`
	Name         string `json:"name"`
	Memory       int64  `json:"memory"` // bytes
	ComputeCap   string `json:"computeCapability,omitempty"`
	DriverVersion string `json:"driverVersion,omitempty"`
}

// NewGPUConverter creates a new GPUConverter with default settings.
func NewGPUConverter() *GPUConverter {
	return &GPUConverter{
		IncludeKernelDetails:   true,
		TrackMemoryAllocations: true,
	}
}

// Name returns the converter name.
func (c *GPUConverter) Name() string {
	return "gpu_to_otlp"
}

// ConvertTraces converts GPU events to OTLP traces.
func (c *GPUConverter) ConvertTraces(ctx context.Context, source interface{}) (ptrace.Traces, error) {
	batch, ok := source.(*GPUEventBatch)
	if !ok {
		return ptrace.Traces{}, fmt.Errorf("expected *GPUEventBatch, got %T", source)
	}

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()

	// Set resource attributes.
	res := rs.Resource()
	res.Attributes().PutStr("service.name", "gpu-tracer")
	if len(batch.DeviceInfo) > 0 {
		res.Attributes().PutStr("gpu.device.name", batch.DeviceInfo[0].Name)
		res.Attributes().PutInt("gpu.device.count", int64(len(batch.DeviceInfo)))
	}

	ss := rs.ScopeSpans().AppendEmpty()
	ss.Scope().SetName("telegen.gpu")
	ss.Scope().SetVersion("1.0.0")

	for _, event := range batch.Events {
		span := ss.Spans().AppendEmpty()
		c.convertEventToSpan(&event, span, batch.DeviceInfo)
	}

	return traces, nil
}

// convertEventToSpan converts a GPU event to a trace span.
func (c *GPUConverter) convertEventToSpan(event *GPUEvent, span ptrace.Span, devices []GPUDeviceInfo) {
	span.SetTraceID(generateTraceID())
	span.SetSpanID(generateSpanID())
	span.SetName(string(event.Type))
	span.SetKind(ptrace.SpanKindInternal)
	span.SetStartTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))
	
	if event.Duration > 0 {
		span.SetEndTimestamp(pcommon.NewTimestampFromTime(event.Timestamp.Add(event.Duration)))
	} else {
		span.SetEndTimestamp(pcommon.NewTimestampFromTime(event.Timestamp))
	}

	attrs := span.Attributes()
	attrs.PutStr("gpu.operation.type", string(event.Type))
	attrs.PutStr("gpu.operation.category", c.eventCategory(event.Type))
	attrs.PutInt("gpu.device.id", int64(event.DeviceID))

	// Add device name if available.
	for _, device := range devices {
		if device.DeviceID == event.DeviceID {
			attrs.PutStr("gpu.device.name", device.Name)
			attrs.PutInt("gpu.device.memory", device.Memory)
			break
		}
	}

	// Process info.
	if event.Process != nil {
		attrs.PutInt("process.pid", int64(event.Process.PID))
		attrs.PutStr("process.command", event.Process.Comm)
		if event.Process.Exe != "" {
			attrs.PutStr("process.executable.path", event.Process.Exe)
		}
	}

	// Event-specific details.
	c.addEventDetails(event, attrs)
}

// eventCategory returns the category for a GPU event type.
func (c *GPUConverter) eventCategory(eventType GPUEventType) string {
	switch eventType {
	case GPUEventKernelLaunch:
		return "kernel"
	case GPUEventMemcpyHtoD, GPUEventMemcpyDtoH, GPUEventMemcpyDtoD:
		return "memory_transfer"
	case GPUEventMemAlloc, GPUEventMemFree:
		return "memory_allocation"
	case GPUEventSynchronize:
		return "synchronization"
	case GPUEventStreamCreate, GPUEventStreamDestroy:
		return "stream"
	case GPUEventLLMInference, GPUEventLLMTokenize, GPUEventLLMDecode, GPUEventLLMBatchProcess:
		return "llm"
	case GPUEventTensorOp, GPUEventMatmul, GPUEventConvolution, GPUEventPooling,
		GPUEventNormalization, GPUEventActivation:
		return "tensor"
	default:
		return "unknown"
	}
}

// addEventDetails adds event-specific details to attributes.
func (c *GPUConverter) addEventDetails(event *GPUEvent, attrs pcommon.Map) {
	switch event.Type {
	case GPUEventKernelLaunch:
		if c.IncludeKernelDetails {
			if name, ok := event.Details["kernelName"].(string); ok {
				attrs.PutStr("gpu.kernel.name", name)
			}
			if gridDim, ok := event.Details["gridDim"].([]int); ok && len(gridDim) == 3 {
				attrs.PutStr("gpu.kernel.grid_dim", fmt.Sprintf("%d,%d,%d", gridDim[0], gridDim[1], gridDim[2]))
			}
			if blockDim, ok := event.Details["blockDim"].([]int); ok && len(blockDim) == 3 {
				attrs.PutStr("gpu.kernel.block_dim", fmt.Sprintf("%d,%d,%d", blockDim[0], blockDim[1], blockDim[2]))
			}
			if sharedMem, ok := event.Details["sharedMem"].(float64); ok {
				attrs.PutInt("gpu.kernel.shared_memory", int64(sharedMem))
			}
		}

	case GPUEventMemcpyHtoD, GPUEventMemcpyDtoH, GPUEventMemcpyDtoD:
		if size, ok := event.Details["size"].(float64); ok {
			attrs.PutInt("gpu.memcpy.size", int64(size))
		}
		if kind, ok := event.Details["kind"].(string); ok {
			attrs.PutStr("gpu.memcpy.kind", kind)
		}

	case GPUEventMemAlloc, GPUEventMemFree:
		if c.TrackMemoryAllocations {
			if size, ok := event.Details["size"].(float64); ok {
				attrs.PutInt("gpu.memory.size", int64(size))
			}
			if ptr, ok := event.Details["ptr"].(string); ok {
				attrs.PutStr("gpu.memory.ptr", ptr)
			}
		}

	case GPUEventLLMInference:
		if model, ok := event.Details["modelName"].(string); ok {
			attrs.PutStr("llm.model.name", model)
		}
		if tokens, ok := event.Details["inputTokens"].(float64); ok {
			attrs.PutInt("llm.input.tokens", int64(tokens))
		}
		if tokens, ok := event.Details["outputTokens"].(float64); ok {
			attrs.PutInt("llm.output.tokens", int64(tokens))
		}
		if batchSize, ok := event.Details["batchSize"].(float64); ok {
			attrs.PutInt("llm.batch.size", int64(batchSize))
		}

	case GPUEventTensorOp, GPUEventMatmul, GPUEventConvolution:
		if opName, ok := event.Details["operationName"].(string); ok {
			attrs.PutStr("tensor.operation.name", opName)
		}
		if shape, ok := event.Details["inputShape"].(string); ok {
			attrs.PutStr("tensor.input.shape", shape)
		}
		if shape, ok := event.Details["outputShape"].(string); ok {
			attrs.PutStr("tensor.output.shape", shape)
		}
	}

	// Add remaining generic details.
	for k, v := range event.Details {
		// Skip already-handled fields.
		switch k {
		case "kernelName", "gridDim", "blockDim", "sharedMem",
			"size", "kind", "ptr", "modelName", "inputTokens", "outputTokens",
			"batchSize", "operationName", "inputShape", "outputShape":
			continue
		}
		setAttrValue(attrs, "gpu."+k, v)
	}
}

// setAttrValue sets an attribute value with type handling.
func setAttrValue(attrs pcommon.Map, key string, value interface{}) {
	switch v := value.(type) {
	case string:
		attrs.PutStr(key, v)
	case int:
		attrs.PutInt(key, int64(v))
	case int64:
		attrs.PutInt(key, v)
	case float64:
		attrs.PutDouble(key, v)
	case bool:
		attrs.PutBool(key, v)
	default:
		attrs.PutStr(key, fmt.Sprintf("%v", v))
	}
}

// ConvertMetrics converts GPU events to OTLP metrics.
func (c *GPUConverter) ConvertMetrics(ctx context.Context, source interface{}) (pmetric.Metrics, error) {
	batch, ok := source.(*GPUEventBatch)
	if !ok {
		return pmetric.Metrics{}, fmt.Errorf("expected *GPUEventBatch, got %T", source)
	}

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	res := rm.Resource()
	res.Attributes().PutStr("service.name", "gpu-tracer")

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen.gpu")
	sm.Scope().SetVersion("1.0.0")

	// Aggregate metrics by device and operation type.
	type deviceOp struct {
		deviceID int
		opType   GPUEventType
	}
	opCounts := make(map[deviceOp]int64)
	opDurations := make(map[deviceOp]int64)
	memTransferred := make(map[int]int64)   // by device
	memAllocated := make(map[int]int64)     // by device

	for _, event := range batch.Events {
		key := deviceOp{event.DeviceID, event.Type}
		opCounts[key]++
		opDurations[key] += int64(event.Duration)

		// Track memory.
		if size, ok := event.Details["size"].(float64); ok {
			switch event.Type {
			case GPUEventMemcpyHtoD, GPUEventMemcpyDtoH, GPUEventMemcpyDtoD:
				memTransferred[event.DeviceID] += int64(size)
			case GPUEventMemAlloc:
				memAllocated[event.DeviceID] += int64(size)
			case GPUEventMemFree:
				memAllocated[event.DeviceID] -= int64(size)
			}
		}
	}

	// Operation counts.
	m := sm.Metrics().AppendEmpty()
	m.SetName("gpu.operations.count")
	m.SetDescription("GPU operation counts")
	sum := m.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	for key, count := range opCounts {
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(count)
		dp.SetTimestamp(Now())
		dp.Attributes().PutInt("gpu.device.id", int64(key.deviceID))
		dp.Attributes().PutStr("gpu.operation.type", string(key.opType))
		dp.Attributes().PutStr("gpu.operation.category", c.eventCategory(key.opType))
	}

	// Operation durations.
	m2 := sm.Metrics().AppendEmpty()
	m2.SetName("gpu.operations.duration")
	m2.SetDescription("GPU operation durations")
	m2.SetUnit("ns")
	sum2 := m2.SetEmptySum()
	sum2.SetIsMonotonic(true)
	sum2.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	for key, duration := range opDurations {
		dp := sum2.DataPoints().AppendEmpty()
		dp.SetIntValue(duration)
		dp.SetTimestamp(Now())
		dp.Attributes().PutInt("gpu.device.id", int64(key.deviceID))
		dp.Attributes().PutStr("gpu.operation.type", string(key.opType))
	}

	// Memory transferred.
	if len(memTransferred) > 0 {
		m3 := sm.Metrics().AppendEmpty()
		m3.SetName("gpu.memory.transferred")
		m3.SetDescription("GPU memory transferred")
		m3.SetUnit("By")
		sum3 := m3.SetEmptySum()
		sum3.SetIsMonotonic(true)
		sum3.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		for deviceID, bytes := range memTransferred {
			dp := sum3.DataPoints().AppendEmpty()
			dp.SetIntValue(bytes)
			dp.SetTimestamp(Now())
			dp.Attributes().PutInt("gpu.device.id", int64(deviceID))
		}
	}

	// Memory allocated.
	if len(memAllocated) > 0 {
		m4 := sm.Metrics().AppendEmpty()
		m4.SetName("gpu.memory.allocated")
		m4.SetDescription("GPU memory currently allocated")
		m4.SetUnit("By")
		gauge := m4.SetEmptyGauge()
		for deviceID, bytes := range memAllocated {
			dp := gauge.DataPoints().AppendEmpty()
			dp.SetIntValue(bytes)
			dp.SetTimestamp(Now())
			dp.Attributes().PutInt("gpu.device.id", int64(deviceID))
		}
	}

	return metrics, nil
}

// generateTraceID generates a random trace ID.
func generateTraceID() pcommon.TraceID {
	var id pcommon.TraceID
	// In production, use crypto/rand.
	now := time.Now().UnixNano()
	for i := 0; i < 16; i++ {
		id[i] = byte((now >> (i * 4)) & 0xFF)
	}
	return id
}

// generateSpanID generates a random span ID.
func generateSpanID() pcommon.SpanID {
	var id pcommon.SpanID
	now := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		id[i] = byte((now >> (i * 8)) & 0xFF)
	}
	return id
}
