package selftelemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestInstallHandlers_ExposesDefaultAndExtraGatherers(t *testing.T) {
	mux := http.NewServeMux()

	extraRegistry := prometheus.NewRegistry()
	extraCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "extra_registry_probe_total",
		Help: "probe metric from extra registry",
	})
	extraRegistry.MustRegister(extraCounter)
	extraCounter.Inc()

	InstallHandlers(mux, ":0", extraRegistry)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("request metrics endpoint: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics endpoint: %v", err)
	}
	metricsText := string(body)

	if !strings.Contains(metricsText, "telegen_agent_ringbuf_events_total") {
		t.Fatalf("expected self-telemetry metric in output, got: %s", metricsText)
	}
	if !strings.Contains(metricsText, "extra_registry_probe_total") {
		t.Fatalf("expected extra gatherer metric in output, got: %s", metricsText)
	}
}
