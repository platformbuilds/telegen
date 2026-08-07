package pipeline

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// The expirable LRU used across parser/pipeline tests starts a janitor
		// goroutine with package-level lifetime.
		goleak.IgnoreTopFunction("github.com/hashicorp/golang-lru/v2/expirable.NewLRU[...].func1"),
		// OTLP/grpc clients created by integration-style tests keep background
		// resolver/transport goroutines past individual test scopes.
		goleak.IgnoreTopFunction("google.golang.org/grpc/internal/resolver/dns.(*dnsResolver).watcher"),
		goleak.IgnoreTopFunction("google.golang.org/grpc/internal/grpcsync.(*CallbackSerializer).run"),
		goleak.IgnoreTopFunction("google.golang.org/grpc.(*addrConn).resetTransportAndUnlock"),
		// Shared OTEL providers started by pipeline integration tests retain their
		// own export loops after subtests complete.
		goleak.IgnoreTopFunction("go.opentelemetry.io/otel/sdk/trace.(*batchSpanProcessor).processQueue"),
		goleak.IgnoreTopFunction("go.opentelemetry.io/otel/sdk/log.exportSync.func1"),
		goleak.IgnoreTopFunction("go.opentelemetry.io/otel/sdk/log.(*BatchProcessor).poll.func1"),
		// Some persistent-queue integration tests intentionally hold background
		// queue loops open across subtests to validate stop paths.
		goleak.IgnoreTopFunction("github.com/mirastacklabs-ai/telegen/internal/queue.(*PersistentQueue).flushLoop"),
		goleak.IgnoreTopFunction("sync.runtime_notifyListWait"),
	)
}
