package pipeline

import (
    "context"
    "log"
    "os"
    "time"

    "github.com/platformbuilds/telegen/internal/config"
    httpcap "github.com/platformbuilds/telegen/internal/capture/http"
    "github.com/platformbuilds/telegen/internal/capture/cassandra"
    "github.com/platformbuilds/telegen/internal/capture/postgres"
    "github.com/platformbuilds/telegen/internal/capture/kafka"
    "github.com/platformbuilds/telegen/internal/exporters/otlp"
    "github.com/platformbuilds/telegen/internal/exporters/remotewrite"
    "github.com/platformbuilds/telegen/internal/logs/filetailer"
    "github.com/platformbuilds/telegen/internal/metrics/host"
    "github.com/platformbuilds/telegen/internal/queue"
    "github.com/platformbuilds/telegen/internal/selftelemetry"

    "github.com/prometheus/prometheus/prompb"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
)

type Pipeline struct {
    cfg *config.Config
    st  *selftelemetry.Registry

    qMetrics *queue.Ring[*prompb.WriteRequest]
    stop     chan struct{}

    rw  *remotewrite.Client
    ot  *otlp.Clients
}

func New(cfg *config.Config, st *selftelemetry.Registry) *Pipeline {
    qm := queue.NewRing[*prompb.WriteRequest](8192, func(_ uint64, reason queue.DropReason){
        st.QueueDropped.WithLabelValues("metrics", string(reason)).Inc()
    })
    return &Pipeline{ cfg: cfg, st: st, qMetrics: qm, stop: make(chan struct{}) }
}

func (p *Pipeline) Start(ctx context.Context) error {
    p.rw = remotewrite.New()
    _ = p.rw.WithTLS(remotewrite.TLSConfig{
        Enable: p.cfg.Exports.RemoteWrite.TLS.Enable,
        CAFile: p.cfg.Exports.RemoteWrite.TLS.CAFile,
        CertFile: p.cfg.Exports.RemoteWrite.TLS.CertFile,
        KeyFile: p.cfg.Exports.RemoteWrite.TLS.KeyFile,
        InsecureSkipVerify: p.cfg.Exports.RemoteWrite.TLS.InsecureSkipVerify,
    })

    // OTLP exporters
    o := p.cfg.Exports.OTLP
    var topts otlp.TraceOpts
    topts.Mode = o.SendMode
    topts.TLS.Enable = o.TLS.Enable
    topts.TLS.CAFile, topts.TLS.CertFile, topts.TLS.KeyFile = o.TLS.CAFile, o.TLS.CertFile, o.TLS.KeyFile
    topts.TLS.InsecureSkipVerify = o.TLS.InsecureSkipVerify
    topts.GRPC.Enabled, topts.GRPC.Endpoint, topts.GRPC.Headers = o.GRPC.Enabled, o.GRPC.Endpoint, o.GRPC.Headers
    topts.GRPC.Insecure, topts.GRPC.Gzip = o.GRPC.Insecure, o.GRPC.Gzip
    topts.GRPC.Timeout, _ = time.ParseDuration(o.GRPC.Timeout)
    topts.HTTP.Enabled, topts.HTTP.Endpoint = o.HTTP.Enabled, o.HTTP.Endpoint
    topts.HTTP.TracesURL, topts.HTTP.LogsURL = o.HTTP.TracesPath, o.HTTP.LogsPath
    topts.HTTP.Headers, topts.HTTP.Gzip = o.HTTP.Headers, o.HTTP.Gzip
    topts.HTTP.Timeout, _ = time.ParseDuration(o.HTTP.Timeout)
    var err error
    p.ot, err = otlp.New(ctx, topts)
    if err != nil { log.Printf("otlp init: %v", err) }

    go p.runRemoteWrite(ctx)

    if hostname, _ := os.Hostname(); true {
        col := host.New("telegen", hostname, 15*time.Second, p.EnqueueMetrics)
        go col.Run(p.stop)
    }
    if p.cfg.Pipelines.Logs.Enabled && p.ot != nil && p.ot.Log != nil {
        ft := filetailer.New(p.cfg.Pipelines.Logs.Filelog.Include, p.cfg.Pipelines.Logs.Filelog.PositionFile, p.ot.Log)
        go func(){ _ = ft.Run(p.stop) }()
    }

    // Demo span synthesis to show exemplars plumbing: http + cql + pg + kafka recognizers.
    if p.ot != nil && p.ot.Trace != nil {
        go p.demoSpanGenerators(ctx)
    }

    p.st.SetReady(true)
    return nil
}

func (p *Pipeline) demoSpanGenerators(ctx context.Context) {
    tr := p.ot.Trace.Tracer("telegen/demo")
    // HTTP
    if g := httpcap.Classify([]byte("GET /health HTTP/1.1\r\n")); g.Proto != "" {
        ctx2, span := tr.Start(ctx, "HTTP "+g.Method+" "+g.Path, trace.WithSpanKind(trace.SpanKindServer))
        span.SetAttributes(attribute.String("http.method", g.Method), attribute.String("url.path", g.Path))
        span.End()
        // The ctx2 would carry span context for exemplar linking downstream.
        _ = ctx2
    }
    // Cassandra CQL
    if ok, stmt := cassandra.CQL{}.TryParseQuery([]byte("SELECT * FROM ks.tbl WHERE id=1;")); ok {
        _, span := tr.Start(ctx, "Cassandra SELECT", trace.WithSpanKind(trace.SpanKindClient))
        span.SetAttributes(attribute.String("db.system","cassandra"), attribute.String("db.statement", stmt))
        span.End()
    }
    // Postgres
    if ok, sql := postgres.TryParseSimpleQuery([]byte("Q\x00\x00\x00\x14SELECT 1;\x00")); ok {
        _, span := tr.Start(ctx, "PostgreSQL query", trace.WithSpanKind(trace.SpanKindClient))
        span.SetAttributes(attribute.String("db.system","postgresql"), attribute.String("db.statement", sql))
        span.End()
    }
    // Kafka
    if kafka.MaybeKafka([]byte{0x00,0x12}) {
        _, span := tr.Start(ctx, "Kafka request", trace.WithSpanKind(trace.SpanKindClient))
        span.SetAttributes(attribute.String("messaging.system","kafka"))
        span.End()
    }
}

func (p *Pipeline) runRemoteWrite(ctx context.Context) {
    for ctx.Err() == nil {
        p.st.QueueSize.WithLabelValues("metrics").Set(float64(p.qMetrics.Len()))
        p.qMetrics.DropExpired(p.cfg.Queues.Metrics.MaxAge())
        batch := p.qMetrics.PopBatch(500, 1*time.Second)
        if len(batch) == 0 { continue }
        var wr prompb.WriteRequest
        for _, it := range batch {
            wr.Timeseries = append(wr.Timeseries, it.V.Timeseries...)
            wr.Metadata = append(wr.Metadata, it.V.Metadata...)
        }
        if len(p.cfg.Exports.RemoteWrite.Endpoints) == 0 { time.Sleep(1*time.Second); continue }
        ep := p.cfg.Exports.RemoteWrite.Endpoints[0]
        if err := p.rw.Send(ctx, &wr, remotewrite.Endpoint{ URL: ep.URL, Timeout: mustDur(ep.Timeout), Headers: ep.Headers, Tenant: ep.Tenant, Compression: ep.Compression }); err != nil {
            p.st.ExportFails.WithLabelValues("metrics", "remote_write").Inc()
            time.Sleep(2 * time.Second)
            p.qMetrics.Push(&wr)
            continue
        }
        p.st.ObserveLatency("metrics", "remote_write", 100*time.Millisecond)
    }
}

func mustDur(s string) time.Duration { d, _ := time.ParseDuration(s); return d }

func (p *Pipeline) EnqueueMetrics(wr *prompb.WriteRequest) { p.qMetrics.Push(wr) }
func (p *Pipeline) Close() { close(p.stop) }
