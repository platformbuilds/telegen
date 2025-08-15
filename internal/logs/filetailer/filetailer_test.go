package filetailer

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// captureExporter implements the sdk/log Exporter interface for v0.3.0.
// NOTE: Export receives a slice of sdklog.Record.
type captureExporter struct {
	mu      sync.Mutex
	bodies  []string
	records int
}

func (e *captureExporter) Export(_ context.Context, recs []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range recs {
		e.records++
		e.bodies = append(e.bodies, r.Body().AsString())
	}
	return nil
}

func (e *captureExporter) Shutdown(context.Context) error   { return nil }
func (e *captureExporter) ForceFlush(context.Context) error { return nil }

func TestTailOnce_EmitsTwoLines_JSONAndText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	content := `{"msg":"hello","val":1}
plain text line
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp log: %v", err)
	}

	// LoggerProvider with a SimpleProcessor that uses our capture exporter.
	exp := &captureExporter{}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)),
	)

	tailer := New([]string{path}, filepath.Join(dir, "pos.json"), lp)

	// Call the single-file pass.
	tailer.tailOnce(path)

	// Give the simple processor a beat (it's synchronous, but play safe).
	time.Sleep(20 * time.Millisecond)

	exp.mu.Lock()
	defer exp.mu.Unlock()

	if exp.records != 2 {
		t.Fatalf("expected 2 log records, got %d", exp.records)
	}
	if len(exp.bodies) != 2 {
		t.Fatalf("expected 2 bodies, got %d", len(exp.bodies))
	}
	if exp.bodies[0] == "" {
		t.Fatalf("first record body empty; want the JSON line")
	}
	if exp.bodies[1] != "plain text line" {
		t.Fatalf("second record body = %q, want %q", exp.bodies[1], "plain text line")
	}
}
