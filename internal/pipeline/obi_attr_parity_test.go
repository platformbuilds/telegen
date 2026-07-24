package pipeline

import (
	"context"
	"testing"
	"time"

	obrequest "github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	obsvc "github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
)

func TestForwardOBISpanBatchAttributeParity(t *testing.T) {
	cfg := DefaultUnifiedPipelineConfig()
	cfg.Exporter.Endpoint = "localhost:4317"
	cfg.Exporter.Insecure = true

	p, err := NewUnifiedPipeline(cfg)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	defer p.cancel()

	upstreamSpan := obrequest.Span{
		Type:         obrequest.EventTypeHTTP,
		Method:       "GET",
		Path:         "/orders/42",
		Route:        "/orders/:id",
		Status:       200,
		RequestStart: 100,
		End:          200,
		Service: obsvc.Attrs{
			UID: obsvc.UID{
				Name:      "checkout",
				Namespace: "payments",
				Instance:  "checkout-1",
			},
		},
	}

	if err := p.forwardOBISpanBatch(context.Background(), []obrequest.Span{upstreamSpan}); err != nil {
		t.Fatalf("forwardOBISpanBatch failed: %v", err)
	}

	select {
	case td := <-p.traceCh:
		if td.SpanCount() == 0 {
			t.Fatalf("expected converted traces, got none")
		}
		rs := td.ResourceSpans()
		if rs.Len() == 0 {
			t.Fatalf("expected resource spans")
		}
		attrs := rs.At(0).Resource().Attributes()
		if svcName, ok := attrs.Get("service.name"); !ok || svcName.Str() != "checkout" {
			t.Fatalf("service.name parity mismatch, got %q", svcName.Str())
		}
		if svcNS, ok := attrs.Get("service.namespace"); !ok || svcNS.Str() != "payments" {
			t.Fatalf("service.namespace parity mismatch, got %q", svcNS.Str())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for converted traces")
	}
}
