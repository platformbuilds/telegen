package reliability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	ebpfcommon "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"
	"github.com/mirastacklabs-ai/telegen/internal/exporters/remotewrite"
	config "github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
	"github.com/prometheus/prometheus/prompb"
)

type runtimeSample struct {
	allocBytes int64
	goroutines int
	fdCount    int
}

func requireReliabilityMode(t *testing.T) {
	t.Helper()
	if os.Getenv("TELEGEN_RELIABILITY") != "1" {
		t.Skip("set TELEGEN_RELIABILITY=1 to run long-running reliability tests")
	}
}

func envDuration(t *testing.T, key string, fallback time.Duration) time.Duration {
	t.Helper()
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		t.Fatalf("invalid duration %s=%q: %v", key, raw, err)
	}
	return d
}

func envInt(t *testing.T, key string, fallback int) int {
	t.Helper()
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		t.Fatalf("invalid int %s=%q: %v", key, raw, err)
	}
	return v
}

func sampleRuntime() runtimeSample {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return runtimeSample{
		allocBytes: int64(mem.Alloc),
		goroutines: runtime.NumGoroutine(),
		fdCount:    currentFDCount(),
	}
}

func currentFDCount() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

func maxDelta(samples []runtimeSample) (allocDelta int64, goroutineDelta int, fdDelta int) {
	if len(samples) == 0 {
		return 0, 0, 0
	}
	base := samples[0]
	var maxAlloc int64
	var maxGoroutines int
	var maxFD int
	for _, s := range samples[1:] {
		if d := s.allocBytes - base.allocBytes; d > maxAlloc {
			maxAlloc = d
		}
		if d := s.goroutines - base.goroutines; d > maxGoroutines {
			maxGoroutines = d
		}
		if base.fdCount >= 0 && s.fdCount >= 0 {
			if d := s.fdCount - base.fdCount; d > maxFD {
				maxFD = d
			}
		}
	}
	return maxAlloc, maxGoroutines, maxFD
}

func TestReliabilityBlackholeSoak(t *testing.T) {
	requireReliabilityMode(t)

	duration := envDuration(t, "TELEGEN_BLACKHOLE_DURATION", 30*time.Minute)
	requestTimeout := envDuration(t, "TELEGEN_BLACKHOLE_REQUEST_TIMEOUT", 250*time.Millisecond)
	sampleEvery := envDuration(t, "TELEGEN_BLACKHOLE_SAMPLE_EVERY", time.Second)
	allowedAllocDelta := int64(envInt(t, "TELEGEN_BLACKHOLE_MAX_ALLOC_DELTA_BYTES", 64*1024*1024))
	allowedGoroutineDelta := envInt(t, "TELEGEN_BLACKHOLE_MAX_GOROUTINE_DELTA", 32)
	allowedFDDelta := envInt(t, "TELEGEN_BLACKHOLE_MAX_FD_DELTA", 32)

	blackholeUntil := time.Now().Add(duration / 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if time.Now().Before(blackholeUntil) {
			time.Sleep(requestTimeout * 2)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := remotewrite.New()
	endpoint := remotewrite.Endpoint{
		URL:     srv.URL,
		Timeout: requestTimeout,
	}
	wr := &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{
			{
				Labels: []prompb.Label{{Name: "__name__", Value: "telegen_reliability_test_metric"}},
				Samples: []prompb.Sample{
					{
						Value:     1.0,
						Timestamp: time.Now().UnixMilli(),
					},
				},
			},
		},
	}

	start := time.Now()
	nextSample := start
	var samples []runtimeSample
	samples = append(samples, sampleRuntime())
	successes := 0
	failures := 0

	for time.Since(start) < duration {
		ctx, cancel := context.WithTimeout(t.Context(), requestTimeout+100*time.Millisecond)
		err := client.Send(ctx, wr, endpoint)
		cancel()
		if err != nil {
			failures++
		} else {
			successes++
		}
		if time.Now().After(nextSample) {
			samples = append(samples, sampleRuntime())
			nextSample = nextSample.Add(sampleEvery)
		}
	}

	if failures == 0 {
		t.Fatal("expected failures during blackhole phase, got none")
	}
	if successes == 0 {
		t.Fatal("expected successful sends after recovery phase, got none")
	}

	allocDelta, goroutineDelta, fdDelta := maxDelta(samples)
	if allocDelta > allowedAllocDelta {
		t.Fatalf("alloc growth exceeded threshold: delta=%d threshold=%d", allocDelta, allowedAllocDelta)
	}
	if goroutineDelta > allowedGoroutineDelta {
		t.Fatalf("goroutine growth exceeded threshold: delta=%d threshold=%d", goroutineDelta, allowedGoroutineDelta)
	}
	if samples[0].fdCount >= 0 && fdDelta > allowedFDDelta {
		t.Fatalf("fd growth exceeded threshold: delta=%d threshold=%d", fdDelta, allowedFDDelta)
	}
}

func TestReliabilityProcessChurnSoak(t *testing.T) {
	requireReliabilityMode(t)

	duration := envDuration(t, "TELEGEN_CHURN_DURATION", 30*time.Minute)
	sampleEvery := envDuration(t, "TELEGEN_CHURN_SAMPLE_EVERY", time.Second)
	allowedAllocDelta := int64(envInt(t, "TELEGEN_CHURN_MAX_ALLOC_DELTA_BYTES", 64*1024*1024))
	allowedGoroutineDelta := envInt(t, "TELEGEN_CHURN_MAX_GOROUTINE_DELTA", 48)
	allowedFDDelta := envInt(t, "TELEGEN_CHURN_MAX_FD_DELTA", 16)

	start := time.Now()
	nextSample := start
	var samples []runtimeSample
	samples = append(samples, sampleRuntime())

	for time.Since(start) < duration {
		done := make(chan struct{})
		go func() {
			time.Sleep(10 * time.Millisecond)
			close(done)
		}()
		<-done

		f, err := os.CreateTemp("", "telegen-reliability-*")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		_ = f.Close()
		_ = os.Remove(f.Name())

		if time.Now().After(nextSample) {
			samples = append(samples, sampleRuntime())
			nextSample = nextSample.Add(sampleEvery)
		}
	}

	allocDelta, goroutineDelta, fdDelta := maxDelta(samples)
	if allocDelta > allowedAllocDelta {
		t.Fatalf("alloc growth exceeded threshold: delta=%d threshold=%d", allocDelta, allowedAllocDelta)
	}
	if goroutineDelta > allowedGoroutineDelta {
		t.Fatalf("goroutine growth exceeded threshold: delta=%d threshold=%d", goroutineDelta, allowedGoroutineDelta)
	}
	if samples[0].fdCount >= 0 && fdDelta > allowedFDDelta {
		t.Fatalf("fd growth exceeded threshold: delta=%d threshold=%d", fdDelta, allowedFDDelta)
	}
}

func TestReliabilityMutatedCorpusNoPanic(t *testing.T) {
	requireReliabilityMode(t)

	cfg := &config.EBPFTracer{BatchLength: 1}
	filter := &ebpfcommon.IdentityPidsFilter{}

	// Use a parse context with a real queue to cover event paths that emit linked spans.
	parseQueue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(8))
	defer parseQueue.Close()

	parseCtx := ebpfcommon.NewEBPFParseContext(cfg, parseQueue, filter)
	if parseCtx == nil {
		t.Fatal("expected non-nil parse context")
	}

	corpus := []struct {
		name      string
		eventType byte
		size      int
	}{
		{name: "http", eventType: ebpfcommon.EventTypeKHTTP, size: int(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))},
		{name: "http2", eventType: ebpfcommon.EventTypeKHTTP2, size: int(unsafe.Sizeof(ebpfcommon.BPFHTTPInfo{}))},
		{name: "sql", eventType: ebpfcommon.EventTypeSQL, size: int(unsafe.Sizeof(ebpfcommon.SQLRequestTrace{}))},
		{name: "tcp", eventType: ebpfcommon.EventTypeTCP, size: int(unsafe.Sizeof(ebpfcommon.TCPRequestInfo{}))},
		{name: "dns", eventType: ebpfcommon.EventTypeDNS, size: int(unsafe.Sizeof(ebpfcommon.DNSInfo{}))},
	}
	mutations := []byte{0x00, 0x7f, 0xff}

	for _, tc := range corpus {
		size := tc.size
		if size < 64 {
			size = 64
		}
		if size > 256 {
			size = 256
		}
		base := make([]byte, size)
		base[0] = tc.eventType

		for i := range base {
			for _, m := range mutations {
				mutated := make([]byte, len(base))
				copy(mutated, base)
				mutated[i] = m
				record := ringbuf.Record{RawSample: mutated}

				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							t.Fatalf("panic for corpus=%s index=%d mutation=%#x: %v", tc.name, i, m, recovered)
						}
					}()
					_, _, _ = ebpfcommon.ReadBPFTraceAsSpan(parseCtx, cfg, &record, filter)
				}()
			}
		}
	}
}
