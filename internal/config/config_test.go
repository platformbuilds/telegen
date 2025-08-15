package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTempYAML creates a temp YAML file and returns its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp yaml: %v", err)
	}
	return p
}

func TestLoad_MinimalWithDefaults(t *testing.T) {
	// Minimal config: exercise defaulting (SelfTelemetry.Listen => :19090)
	yaml := `
agent:
  service_name: "telegen-self"
queues:
  metrics:
    mem_limit: "64Mi"
    max_age: "5m"
  traces:
    mem_limit: "64Mi"
    max_age: "5m"
  logs:
    mem_limit: "64Mi"
    max_age: "5m"
exports:
  remoteWrite:
    mode: "disabled"
  otlp:
    send_mode: "none"
`
	p := writeTempYAML(t, yaml)

	got, err := Load(p)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.Agent.ServiceName != "telegen-self" {
		t.Errorf("Agent.ServiceName = %q, want %q", got.Agent.ServiceName, "telegen-self")
	}
	if got.SelfTelemetry.Listen != ":19090" {
		t.Errorf("SelfTelemetry.Listen = %q, want %q (default)", got.SelfTelemetry.Listen, ":19090")
	}
	if d := got.Queues.Metrics.MaxAge(); d != 5*time.Minute {
		t.Errorf("Queues.Metrics.MaxAge() = %v, want 5m", d)
	}
}

func TestLoad_FullConfigDecode(t *testing.T) {
	yaml := `
agent:
  service_name: "telegen-agent"

selfTelemetry:
  listen: "0.0.0.0:19091"
  prometheus_namespace: "telegen"

queues:
  metrics:
    mem_limit: "128Mi"
    max_age: "10m"
  traces:
    mem_limit: "256Mi"
    max_age: "15m"
  logs:
    mem_limit: "64Mi"
    max_age: "7m"

backoff:
  initial: "250ms"
  max: "10s"
  multiplier: 2.0
  jitter: 0.2

exports:
  remoteWrite:
    mode: "active"
    tls:
      enable: true
      ca_file: "/etc/ssl/ca.pem"
      cert_file: "/etc/ssl/cert.pem"
      key_file: "/etc/ssl/key.pem"
      insecure_skip_verify: true
    endpoints:
      - url: "https://rw.example/v1/write"
        timeout: "5s"
        headers:
          X-API-Key: "abc123"
        tenant: "team-a"
        compression: "snappy"
  otlp:
    send_mode: "both"
    tls:
      enable: true
      insecure_skip_verify: false
    grpc:
      enabled: true
      endpoint: "otel-grpc.example:4317"
      headers:
        authorization: "Bearer token"
      insecure: false
      gzip: true
      timeout: "7s"
    http:
      enabled: true
      endpoint: "https://otel-http.example:4318"
      traces_path: "/v1/traces"
      logs_path: "/v1/logs"
      headers:
        x-otlp: "1"
      gzip: true
      timeout: "8s"

pipelines:
  metrics:
    also_expose_prometheus: true
  traces:
    enabled: true
  logs:
    enabled: true
    filelog:
      include:
        - "/var/log/syslog"
        - "/var/log/app/*.log"
      position_file: "/var/lib/telegen/positions.yaml"
`
	p := writeTempYAML(t, yaml)

	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// SelfTelemetry
	if c.SelfTelemetry.Listen != "0.0.0.0:19091" {
		t.Errorf("SelfTelemetry.Listen = %q", c.SelfTelemetry.Listen)
	}
	if c.SelfTelemetry.NS != "telegen" {
		t.Errorf("SelfTelemetry.NS = %q, want telegen", c.SelfTelemetry.NS)
	}

	// Queues + MaxAge parsing
	if c.Queues.Metrics.MemLimit != "128Mi" {
		t.Errorf("Queues.Metrics.MemLimit = %q", c.Queues.Metrics.MemLimit)
	}
	if d := c.Queues.Traces.MaxAge(); d != 15*time.Minute {
		t.Errorf("Queues.Traces.MaxAge() = %v, want 15m", d)
	}

	// Backoff
	if c.Backoff.Initial != "250ms" || c.Backoff.Max != "10s" {
		t.Errorf("Backoff initial/max = %q/%q, want 250ms/10s", c.Backoff.Initial, c.Backoff.Max)
	}
	if c.Backoff.Multiplier != 2.0 {
		t.Errorf("Backoff.Multiplier = %v, want 2.0", c.Backoff.Multiplier)
	}
	if c.Backoff.Jitter != 0.2 {
		t.Errorf("Backoff.Jitter = %v, want 0.2", c.Backoff.Jitter)
	}

	// RemoteWrite
	if c.Exports.RemoteWrite.Mode != "active" {
		t.Errorf("RemoteWrite.Mode = %q, want active", c.Exports.RemoteWrite.Mode)
	}
	if !c.Exports.RemoteWrite.TLS.Enable {
		t.Errorf("RemoteWrite.TLS.Enable = false, want true")
	}
	if got, want := len(c.Exports.RemoteWrite.Endpoints), 1; got != want {
		t.Fatalf("RemoteWrite.Endpoints len = %d, want %d", got, want)
	}
	rw := c.Exports.RemoteWrite.Endpoints[0]
	if rw.URL != "https://rw.example/v1/write" {
		t.Errorf("RWEndpoint.URL = %q", rw.URL)
	}
	if rw.Timeout != "5s" {
		t.Errorf("RWEndpoint.Timeout = %q, want 5s", rw.Timeout)
	}
	if rw.Headers["X-API-Key"] != "abc123" {
		t.Errorf("RWEndpoint.Headers[X-API-Key] = %q", rw.Headers["X-API-Key"])
	}
	if rw.Tenant != "team-a" || rw.Compression != "snappy" {
		t.Errorf("RWEndpoint tenant/compression = %q/%q", rw.Tenant, rw.Compression)
	}

	// OTLP (grpc + http)
	if c.Exports.OTLP.SendMode != "both" {
		t.Errorf("OTLP.SendMode = %q, want both", c.Exports.OTLP.SendMode)
	}
	if !c.Exports.OTLP.GRPC.Enabled || c.Exports.OTLP.GRPC.Endpoint != "otel-grpc.example:4317" {
		t.Errorf("OTLP.GRPC enabled/endpoint mismatch: %+v", c.Exports.OTLP.GRPC)
	}
	if !c.Exports.OTLP.GRPC.Gzip || c.Exports.OTLP.GRPC.Timeout != "7s" {
		t.Errorf("OTLP.GRPC gzip/timeout mismatch")
	}
	if !c.Exports.OTLP.HTTP.Enabled || c.Exports.OTLP.HTTP.Endpoint != "https://otel-http.example:4318" {
		t.Errorf("OTLP.HTTP enabled/endpoint mismatch: %+v", c.Exports.OTLP.HTTP)
	}
	if c.Exports.OTLP.HTTP.TracesPath != "/v1/traces" || c.Exports.OTLP.HTTP.LogsPath != "/v1/logs" {
		t.Errorf("OTLP.HTTP paths mismatch")
	}
	if !c.Exports.OTLP.HTTP.Gzip || c.Exports.OTLP.HTTP.Timeout != "8s" {
		t.Errorf("OTLP.HTTP gzip/timeout mismatch")
	}

	// Pipelines
	if !c.Pipelines.Metrics.AlsoExposeProm {
		t.Errorf("Pipelines.Metrics.AlsoExposeProm = false, want true")
	}
	if !c.Pipelines.Traces.Enabled {
		t.Errorf("Pipelines.Traces.Enabled = false, want true")
	}
	if !c.Pipelines.Logs.Enabled {
		t.Errorf("Pipelines.Logs.Enabled = false, want true")
	}
	if got := len(c.Pipelines.Logs.Filelog.Include); got != 2 {
		t.Errorf("Pipelines.Logs.Filelog.Include len = %d, want 2", got)
	}
	if c.Pipelines.Logs.Filelog.PositionFile != "/var/lib/telegen/positions.yaml" {
		t.Errorf("Pipelines.Logs.Filelog.PositionFile = %q", c.Pipelines.Logs.Filelog.PositionFile)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	p := writeTempYAML(t, `
agent:
  service_name: "bad
`) // broken quote

	if _, err := Load(p); err == nil {
		t.Fatalf("Load() = nil error, want non-nil for invalid YAML")
	}
}

func TestQMaxAge_ParseAndInvalid(t *testing.T) {
	q := Q{MaxAgeStr: "1h30m"}
	if d := q.MaxAge(); d != time.Hour+30*time.Minute {
		t.Errorf("MaxAge() = %v, want 1h30m", d)
	}

	qInvalid := Q{MaxAgeStr: "not-a-duration"}
	if d := qInvalid.MaxAge(); d != 0 {
		t.Errorf("MaxAge() with invalid string = %v, want 0", d)
	}
}

// Optional: a quick benchmark for Load (useful as config grows)
func BenchmarkLoad(b *testing.B) {
	yaml := `
agent: { service_name: "bench" }
queues:
  metrics: { mem_limit: "64Mi", max_age: "1m" }
  traces:  { mem_limit: "64Mi", max_age: "1m" }
  logs:    { mem_limit: "64Mi", max_age: "1m" }
`
	p := writeTempYAML(&testing.T{}, yaml)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Load(p); err != nil {
			b.Fatal(err)
		}
	}
}
