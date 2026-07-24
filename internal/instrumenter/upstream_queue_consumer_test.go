package instrumenter

import (
	"context"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

func TestConsumeUpstreamSpanQueue(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(2), msg.Name("test-upstream-span-queue"))
	defer q.Close()

	got := make(chan int, 1)
	ready := make(chan struct{})
	go consumeUpstreamSpanQueue(ctx, q, func(_ context.Context, batch []request.Span) error {
		got <- len(batch)
		return nil
	}, ready)
	<-ready

	q.Send([]request.Span{{}, {}})

	select {
	case n := <-got:
		if n != 2 {
			t.Fatalf("expected 2 spans, got %d", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream queue consumer")
	}
}
