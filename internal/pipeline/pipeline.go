package pipeline

import (
	"context"

	"github.com/platformbuilds/telegen/internal/capture/cassandra"
	httpcap "github.com/platformbuilds/telegen/internal/capture/http"
	"github.com/platformbuilds/telegen/internal/capture/kafka"
	"github.com/platformbuilds/telegen/internal/capture/postgres"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// DemoSpanGenerators creates demo spans for parsers. In production this would use eBPF data.
func DemoSpanGenerators(ctx context.Context, tr trace.Tracer) {
	// HTTP
	if g := httpcap.Classify([]byte("GET /health HTTP/1.1\r\n")); g.Proto != "" {
		_, span := tr.Start(ctx, "HTTP "+g.Method+" "+g.Path, trace.WithSpanKind(trace.SpanKindServer))
		span.SetAttributes(attribute.String("http.method", g.Method), attribute.String("url.path", g.Path))
		span.End()
	}
	// Cassandra: enrich with peer.service & db.namespace
	if ok, stmt := (cassandra.CQL{}).TryParseQuery([]byte("SELECT * FROM ks.tbl WHERE id=1;")); ok {
		_, span := tr.Start(ctx, "Cassandra SELECT", trace.WithSpanKind(trace.SpanKindClient))
		span.SetAttributes(
			attribute.String("db.system", "cassandra"),
			attribute.String("db.statement", stmt),
			attribute.String("peer.service", "cassandra"),
			attribute.String("db.namespace", "ks"),
		)
		span.End()
	}
	// Postgres: use db.namespace default "public"
	if ok, sql := postgres.TryParseSimpleQuery([]byte("Q\x00\x00\x00\x14SELECT 1;\x00")); ok {
		_, span := tr.Start(ctx, "PostgreSQL query", trace.WithSpanKind(trace.SpanKindClient))
		span.SetAttributes(
			attribute.String("db.system", "postgresql"),
			attribute.String("db.statement", sql),
			attribute.String("peer.service", "postgres"),
			attribute.String("db.namespace", "public"),
		)
		span.End()
	}
	// Kafka: enrich with messaging.destination & peer.service
	if kafka.MaybeKafka([]byte{0x00, 0x12}) {
		_, span := tr.Start(ctx, "Kafka request", trace.WithSpanKind(trace.SpanKindClient))
		span.SetAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.destination", "telegen-demo-topic"),
			attribute.String("peer.service", "kafka-broker"),
		)
		span.End()
	}
}

// Helper to obtain a tracer for tests or runtime
func NewDemoTracer() trace.Tracer {
	return otel.Tracer("telegen/demo")
}
