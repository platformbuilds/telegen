package pipeline

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// helper: turn a slice of attributes into a map for easy asserts
func kvMap(kvs []attribute.KeyValue) map[string]string {
	out := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		out[string(kv.Key)] = kv.Value.AsString()
	}
	return out
}

func TestDemoSpanGenerators_CassandraAttributes(t *testing.T) {
	// Capture spans with a SpanRecorder
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	tr := tp.Tracer("test")

	// Run the demo generators (creates HTTP, Cassandra, Postgres, Kafka spans)
	DemoSpanGenerators(context.Background(), tr)

	// Find the Cassandra span among ended spans
	var found bool
	for _, s := range rec.Ended() { // s is sdktrace.ReadOnlySpan
		if s.Name() == "Cassandra SELECT" {
			found = true
			attrs := kvMap(s.Attributes())
			// Assert enrichment
			if attrs["db.system"] != "cassandra" {
				t.Fatalf("db.system=%q, want %q", attrs["db.system"], "cassandra")
			}
			if attrs["peer.service"] != "cassandra" {
				t.Fatalf("peer.service=%q, want %q", attrs["peer.service"], "cassandra")
			}
			if ns := attrs["db.namespace"]; ns != "ks" {
				t.Fatalf("db.namespace=%q, want %q", ns, "ks")
			}
			stmt := attrs["db.statement"]
			if stmt == "" || stmt[:6] != "SELECT" {
				t.Fatalf("db.statement=%q, want SELECT ...", stmt)
			}
			break
		}
	}
	if !found {
		t.Fatalf("Cassandra span not found; got %d spans", len(rec.Ended()))
	}
}

func TestDemoSpanGenerators_EmitsOtherSpans(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	tr := tp.Tracer("test")

	DemoSpanGenerators(context.Background(), tr)

	want := map[string]bool{
		"HTTP GET /health": false,
		"PostgreSQL query": false,
		"Kafka request":    false,
	}
	for _, s := range rec.Ended() {
		if _, ok := want[s.Name()]; ok {
			want[s.Name()] = true
		}
	}
	for name, ok := range want {
		if !ok {
			t.Fatalf("expected span %q not emitted", name)
		}
	}
}
