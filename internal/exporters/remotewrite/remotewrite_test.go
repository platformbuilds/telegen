package remotewrite

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/prometheus/prometheus/prompb"
)

// buildWriteRequest creates a tiny, valid WriteRequest with one sample.
// NOTE: Timeseries is []prompb.TimeSeries (values), not []*prompb.TimeSeries.
func buildWriteRequest() *prompb.WriteRequest {
	ts := prompb.TimeSeries{
		Labels: []prompb.Label{
			{Name: "__name__", Value: "test_metric_total"},
			{Name: "job", Value: "telegen"},
			{Name: "instance", Value: "localhost"},
		},
		Samples: []prompb.Sample{
			{Timestamp: time.Now().UnixMilli(), Value: 1.23},
		},
	}
	return &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{ts},
	}
}

func TestSend_Gzip_Success_WithHeadersAndTenant(t *testing.T) {
	seen := struct {
		method          string
		contentType     string
		contentEncoding string
		tenant          string
		customHeader    string
		timeseries      int
	}{}

	// Endpoint that validates headers and decodes the protobuf payload.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.contentType = r.Header.Get("Content-Type")
		seen.contentEncoding = r.Header.Get("Content-Encoding")
		seen.tenant = r.Header.Get("X-Scope-OrgID")
		seen.customHeader = r.Header.Get("X-Custom-Header")

		// Read body (gzip or plain)
		var body []byte
		var err error
		if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			gr, gzErr := gzip.NewReader(r.Body)
			if gzErr != nil {
				http.Error(w, gzErr.Error(), http.StatusBadRequest)
				return
			}
			defer gr.Close()
			body, err = io.ReadAll(gr)
		} else {
			body, err = io.ReadAll(r.Body)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var req prompb.WriteRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "proto unmarshal failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		seen.timeseries = len(req.Timeseries)

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New()
	wr := buildWriteRequest()
	ep := Endpoint{
		URL:         srv.URL + "/api/v1/push",
		Headers:     map[string]string{"X-Custom-Header": "hello"},
		Tenant:      "acme",
		Timeout:     2 * time.Second,
		Compression: "gzip",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.Send(ctx, wr, ep); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if seen.method != http.MethodPost {
		t.Fatalf("expected POST, got %s", seen.method)
	}
	if seen.contentType != "application/x-protobuf" {
		t.Fatalf("unexpected content-type: %s", seen.contentType)
	}
	if !strings.EqualFold(seen.contentEncoding, "gzip") {
		t.Fatalf("expected gzip content-encoding, got %s", seen.contentEncoding)
	}
	if seen.tenant != "acme" {
		t.Fatalf("expected tenant header 'acme', got %q", seen.tenant)
	}
	if seen.customHeader != "hello" {
		t.Fatalf("expected custom header 'hello', got %q", seen.customHeader)
	}
	if seen.timeseries != 1 {
		t.Fatalf("expected 1 timeseries in payload, got %d", seen.timeseries)
	}
}

func TestSend_NoGzip_Success(t *testing.T) {
	var sawEncoding string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawEncoding = r.Header.Get("Content-Encoding")
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New()
	wr := buildWriteRequest()
	ep := Endpoint{
		URL:         srv.URL + "/api/v1/push",
		Timeout:     time.Second,
		Compression: "none",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := c.Send(ctx, wr, ep); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	if sawEncoding != "" {
		t.Fatalf("expected no Content-Encoding header, got %q", sawEncoding)
	}
}

func TestSend_ServerError_Propagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New()
	wr := buildWriteRequest()
	ep := Endpoint{
		URL:         srv.URL + "/api/v1/push",
		Timeout:     time.Second,
		Compression: "gzip",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := c.Send(ctx, wr, ep); err == nil {
		t.Fatalf("expected error from Send() when server returns 500")
	}
}
