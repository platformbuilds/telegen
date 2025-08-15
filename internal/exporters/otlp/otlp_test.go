package otlp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test that HTTP exporters (traces + logs) initialize successfully.
// Uses an httptest server; exporter constructors don't POST during construction.
func TestNew_HTTP_Succeeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No need to validate payload; creation doesn't send data.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var o TraceOpts
	o.HTTP.Enabled = true
	o.HTTP.Endpoint = srv.URL // e.g. "http://127.0.0.1:XXXXX"
	o.HTTP.TracesPath = "/v1/traces"
	o.HTTP.LogsPath = "/v1/logs"
	o.HTTP.Timeout = 2 * time.Second
	o.HTTP.Headers = map[string]string{"x-test": "yes"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cl, err := New(ctx, o)
	if err != nil {
		t.Fatalf("New() returned error with HTTP enabled: %v", err)
	}
	if cl == nil || cl.Trace == nil || cl.Log == nil {
		t.Fatalf("New() returned nil providers: got %#v", cl)
	}

	// Providers should shut down cleanly.
	shCtx, shCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shCancel()
	if err := cl.close(shCtx); err != nil {
		t.Fatalf("close() returned error: %v", err)
	}
}

func TestNew_NoEndpoints_Error(t *testing.T) {
	var o TraceOpts // neither HTTP nor gRPC enabled

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cl, err := New(ctx, o)
	if err == nil {
		if cl != nil && cl.close != nil {
			_ = cl.close(ctx)
		}
		t.Fatalf("expected error when no endpoints configured, got nil")
	}
}
