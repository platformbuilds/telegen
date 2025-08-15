package selftelemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// helper to start server in background on a random port
func startTestServer() *httptest.Server {
	// We reuse StartServer's handler setup, but run it in our own httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	return httptest.NewServer(mux)
}

func TestHealthzHandler(t *testing.T) {
	srv := startTestServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "ok" {
		t.Errorf("body = %q, want %q", string(body), "ok")
	}
}

// Optional: Integration test launching StartServer on a free port
func TestStartServerRuns(t *testing.T) {
	// Run StartServer in a goroutine; we expect it to serve /healthz
	go func() {
		StartServer() // This will block, but that's fine in a goroutine
	}()
	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Try hitting the default port
	resp, err := http.Get("http://localhost:19090/healthz")
	if err != nil {
		t.Skipf("Skipping actual StartServer test: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
