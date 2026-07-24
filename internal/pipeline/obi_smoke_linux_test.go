//go:build linux

package pipeline

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	obrequest "github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	obsvc "github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

func TestLinuxOBISmoke_ForwardToOTLP(t *testing.T) {
	var receivedSpans atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		if r.URL.Path != "/v1/traces" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		bodyReader := io.Reader(r.Body)
		if strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "gzip") {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer func() { _ = gz.Close() }()
			bodyReader = gz
		}

		body, err := io.ReadAll(bodyReader)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req := ptraceotlp.NewExportRequest()
		if err := req.UnmarshalProto(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedSpans.Add(int64(req.Traces().SpanCount()))
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	cfg := DefaultUnifiedPipelineConfig()
	cfg.Exporter.Endpoint = receiver.URL
	cfg.Exporter.Insecure = true

	p, err := NewUnifiedPipeline(cfg)
	if err != nil {
		t.Fatalf("NewUnifiedPipeline failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = p.Stop(context.Background()) }()

	span := obrequest.Span{
		Type:         obrequest.EventTypeHTTP,
		Method:       "GET",
		Path:         "/smoke",
		Route:        "/smoke",
		Status:       200,
		RequestStart: 100,
		End:          200,
		Service: obsvc.Attrs{
			UID: obsvc.UID{
				Name:      "smoke-service",
				Namespace: "smoke-ns",
				Instance:  "smoke-1",
			},
		},
	}
	if err := p.forwardOBISpanBatch(ctx, []obrequest.Span{span}); err != nil {
		t.Fatalf("forwardOBISpanBatch failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if receivedSpans.Load() > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected OTLP receiver to get spans, got %d", receivedSpans.Load())
}
