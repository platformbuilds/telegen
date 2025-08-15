package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/platformbuilds/telegen/internal/config"
)

// fakeCloser satisfies the closeOnly (io.Closer-compatible) interface.
// It lets us assert that Pipeline.Close() actually calls Close() on the handle.
type fakeCloser struct {
	closed int
}

func (f *fakeCloser) Close() error {
	f.closed++
	return nil
}

func TestPipeline_StartThenClose_CallsSelfTelemetryClose(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	st := &fakeCloser{}

	p := New(cfg, st)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start should return quickly and not error.
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	// Close should finish and must call st.Close exactly once.
	done := make(chan struct{})
	go func() {
		p.Close()
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(1 * time.Second):
		t.Fatal("Close() did not return in time (possible goroutine leak)")
	}

	if st.closed != 1 {
		t.Fatalf("self-telemetry Close() called %d times, want 1", st.closed)
	}
}

func TestPipeline_CancelContext_ThenClose_ReturnsPromptly(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	st := &fakeCloser{}

	p := New(cfg, st)

	ctx, cancel := context.WithCancel(context.Background())

	if err := p.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start returned error: %v", err)
	}

	// Cancel the parent context to signal the background goroutine to stop.
	cancel()

	// Close should respect the cancellation and return promptly.
	start := time.Now()
	p.Close()
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("Close() took too long after context cancel: %v", elapsed)
	}

	if st.closed != 1 {
		t.Fatalf("self-telemetry Close() called %d times, want 1", st.closed)
	}
}
