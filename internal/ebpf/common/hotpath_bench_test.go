package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	config "github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

func BenchmarkReadBPFTraceAsSpan(b *testing.B) {
	cfg := config.EBPFTracer{
		HeuristicSQLDetect:                  true,
		KafkaTopicUUIDCacheSize:             16,
		MongoRequestsCacheSize:              16,
		MySQLPreparedStatementsCacheSize:    16,
		PostgresPreparedStatementsCacheSize: 16,
		CouchbaseDBCacheSize:                16,
	}
	filter := &TestPidsFilter{services: map[uint32]svc.Attrs{}}
	parseCtx := NewEBPFParseContext(&cfg, nil, filter)

	cases := map[string]ringbuf.Record{
		"http":  buildBenchmarkTCPRecord("GET /checkout HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"),
		"redis": buildBenchmarkTCPRecord("*2\r\n$3\r\nGET\r\n$5\r\nbeyla\r\n", "$5\r\nhello\r\n"),
		"sql":   buildBenchmarkTCPRecord("SELECT * FROM users WHERE id = 7", "OK"),
	}

	b.ReportAllocs()
	for name, record := range cases {
		record := record
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _ = ReadTCPRequestIntoSpan(parseCtx, &cfg, &record, filter)
			}
		})
	}
}

func BenchmarkFlushEvents(b *testing.B) {
	forwarder := &ringBufForwarder{
		filter:  &TestPidsFilter{services: map[uint32]svc.Attrs{}},
		metrics: &imetrics.NoopReporter{},
	}
	q := msg.NewQueue[[]request.Span]()
	batch := make([]request.Span, 128)
	for i := range batch {
		batch[i] = request.Span{
			Type:   request.EventTypeHTTP,
			Method: "GET",
			Path:   "/checkout",
			Pid:    request.PidInfo{HostPID: uint32(i + 1)},
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		forwarder.flushEvents(q, batch)
	}
}

func buildBenchmarkTCPRecord(requestBody, responseBody string) ringbuf.Record {
	ev := makeTCPReq(requestBody, 8080)
	ev.RespLen = uint32(len(responseBody))
	copy(ev.Rbuf[:], responseBody)
	ev.StartMonotimeNs = uint64(time.Now().UnixNano())
	ev.EndMonotimeNs = ev.StartMonotimeNs + uint64(time.Millisecond)

	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.LittleEndian, ev)
	return ringbuf.Record{RawSample: raw.Bytes()}
}
