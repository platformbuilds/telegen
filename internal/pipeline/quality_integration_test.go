package pipeline

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/pipeline/limits"
	"github.com/mirastacklabs-ai/telegen/internal/pipeline/transform"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestIntegrationCardinalityDrop(t *testing.T) {
	cfg := IntegrationConfig{
		Enabled: true,
		Limits: &V3LimitsConfig{
			Cardinality: &limits.CardinalityConfig{
				Enabled:               true,
				GlobalLimit:           1,
				DefaultPerMetricLimit: 1,
				Action:                "drop",
				TTL:                   time.Minute,
				ReportInterval:        time.Hour,
			},
		},
	}
	integration, err := NewIntegration(cfg, nil)
	if err != nil {
		t.Fatalf("NewIntegration failed: %v", err)
	}

	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	m := sm.Metrics().AppendEmpty()
	m.SetName("cardinality.test")
	g := m.SetEmptyGauge()
	dp1 := g.DataPoints().AppendEmpty()
	dp1.SetDoubleValue(1)
	dp1.Attributes().PutStr("pod", "a")
	dp2 := g.DataPoints().AppendEmpty()
	dp2.SetDoubleValue(2)
	dp2.Attributes().PutStr("pod", "b")

	out, err := integration.ProcessMetrics(context.Background(), md)
	if err != nil {
		t.Fatalf("ProcessMetrics failed: %v", err)
	}
	if out.DataPointCount() != 1 {
		t.Fatalf("expected 1 datapoint after cardinality limit, got %d", out.DataPointCount())
	}
}

func TestIntegrationPIIRedactionOnLogs(t *testing.T) {
	cfg := IntegrationConfig{
		Enabled: true,
		PIIRedaction: &transform.PIIRedactionConfig{
			Enabled:         true,
			RedactionString: "[REDACTED]",
			ScanLogBodies:   true,
			Rules: []transform.PIIRule{
				{Name: "email", Type: "email", Enabled: true},
			},
		},
	}
	integration, err := NewIntegration(cfg, nil)
	if err != nil {
		t.Fatalf("NewIntegration failed: %v", err)
	}

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("owner=admin@example.com action=login")

	out, err := integration.ProcessLogs(context.Background(), logs)
	if err != nil {
		t.Fatalf("ProcessLogs failed: %v", err)
	}
	body := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str()
	if strings.Contains(body, "admin@example.com") {
		t.Fatalf("expected email to be redacted, got %q", body)
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("expected redaction token in body, got %q", body)
	}
}

func TestPersistentQueueEnqueueAndDrainOnChannelFull(t *testing.T) {
	cfg := DefaultUnifiedPipelineConfig()
	cfg.Exporter.Endpoint = "localhost:4317"
	cfg.Exporter.Insecure = true
	cfg.Queue = &QueueConfig{
		Enabled:      true,
		Directory:    t.TempDir(),
		MaxSizeBytes: 10 * 1024 * 1024,
		MaxItems:     1000,
	}

	p, err := NewUnifiedPipeline(cfg)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer p.cancel()

	if err := p.initQueues(); err != nil {
		t.Fatalf("initQueues failed: %v", err)
	}
	defer func() {
		_ = p.metricQueue.Close()
	}()

	// Keep metric channel full so SendMetrics must hit persistent queue.
	p.metricCh = make(chan pmetric.Metrics, 1)
	p.metricCh <- createTestMetricsV3()

	metricClient := &countMetricClient{}
	p.exporter = &UnifiedExporter{
		config:       DefaultExporterConfig(),
		sem:          make(chan struct{}, 1),
		traceClient:  &noopTraceClient{},
		logClient:    &noopLogClient{},
		metricClient: metricClient,
	}

	p.wg.Add(1)
	go p.metricQueueWorker()

	if err := p.SendMetrics(context.Background(), createTestMetricsV3()); err != nil {
		t.Fatalf("SendMetrics failed: %v", err)
	}

	waitUntil(t, 2*time.Second, func() bool {
		return p.metricQueue.Stats().TotalPushed > 0
	}, "metric was not enqueued to persistent queue")

	waitUntil(t, 4*time.Second, func() bool {
		stats := p.metricQueue.Stats()
		return stats.TotalPopped > 0 && p.metricQueue.Len() == 0
	}, "persistent queue item was not drained from WAL")

	if metricClient.count.Load() == 0 {
		t.Fatalf("expected drained metric to be exported, exporter saw %d points", metricClient.count.Load())
	}

	p.cancel()
	p.wg.Wait()
}

type noopTraceClient struct{}

func (noopTraceClient) Export(context.Context, ptrace.Traces) error { return nil }

type noopLogClient struct{}

func (noopLogClient) Export(context.Context, plog.Logs) error { return nil }

type countMetricClient struct {
	count atomic.Int64
}

func (c *countMetricClient) Export(_ context.Context, metrics pmetric.Metrics) error {
	c.count.Add(int64(metrics.DataPointCount()))
	return nil
}

func waitUntil(t *testing.T, timeout time.Duration, pred func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}
