package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/config"
	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
	"github.com/prometheus/prometheus/prompb"
)

func mockIMDSServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("tkn"))
	})
	mux.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accountId":        "123456789012",
			"region":           "us-west-2",
			"instanceId":       "i-abc123",
			"instanceType":     "t3.small",
			"imageId":          "ami-123",
			"availabilityZone": "us-west-2a",
			"privateIp":        "10.0.0.5",
		})
	})
	return httptest.NewServer(mux)
}

//nolint:unused // test helper for remote write mock server
func mockRemoteWrite(t *testing.T, ch chan<- *prompb.WriteRequest) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var wr prompb.WriteRequest
		b, _ := io.ReadAll(r.Body)
		if err := wr.Unmarshal(b); err != nil {
			t.Logf("unmarshal: %v", err)
			w.WriteHeader(400)
			return
		}
		ch <- &wr
		w.WriteHeader(200)
	}))
}

func TestPipelineE2E_RemoteWriteAWSLabels(t *testing.T) {
	imds := mockIMDSServer()
	defer imds.Close()
	base := strings.TrimRight(imds.URL, "/") + "/latest"
	got := make(chan *prompb.WriteRequest, 1)
	rw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var wr prompb.WriteRequest
		b, _ := io.ReadAll(r.Body)
		if err := wr.Unmarshal(b); err != nil {
			t.Logf("unmarshal: %v", err)
			w.WriteHeader(400)
			return
		}
		got <- &wr
		w.WriteHeader(200)
	}))
	defer rw.Close()

	cfg := &config.Config{}
	cfg.Cloud.AWS.Enabled = true
	cfg.Cloud.AWS.Timeout = "100ms"
	cfg.Cloud.AWS.RefreshInterval = "1m"
	cfg.Cloud.AWS.IMDSBaseURL = base
	cfg.Cloud.AWS.DisableProbe = true
	cfg.Exports.RemoteWrite.Endpoints = []config.RWEndpoint{{URL: rw.URL, Timeout: "2s", Compression: ""}}
	cfg.Queues.Metrics.MaxAgeStr = "1m"

	st := selftelemetry.NewRegistry("telegen")
	pl := New(cfg, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := pl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Enqueue a simple metric and ensure AWS labels got injected on the wire
	wr := &prompb.WriteRequest{Timeseries: []prompb.TimeSeries{{Labels: []prompb.Label{{Name: "__name__", Value: "test_metric"}, {Name: "job", Value: "telegen"}, {Name: "instance", Value: "test"}}, Samples: []prompb.Sample{{Timestamp: time.Now().UnixMilli(), Value: 1}}}}}
	pl.EnqueueMetrics(wr)

	select {
	case out := <-got:
		if len(out.Timeseries) == 0 {
			t.Fatalf("no timeseries received")
		}
		labs := out.Timeseries[0].Labels
		toMap := map[string]string{}
		for _, l := range labs {
			toMap[l.Name] = l.Value
		}
		// Validate injected labels
		if toMap["cloud_provider"] != "aws" || toMap["cloud_region"] != "us-west-2" || toMap["cloud_az"] != "us-west-2a" || toMap["instance_id"] != "i-abc123" {
			t.Fatalf("missing aws labels: %+v", toMap)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for remote write")
	}
}
