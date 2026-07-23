package instrumenter

import (
	"context"
	"testing"
	"time"

	obrequest "go.opentelemetry.io/obi/pkg/appolly/app/request"
	obmsg "go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestConsumeUpstreamSpanQueue(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := obmsg.NewQueue[[]obrequest.Span](obmsg.ChannelBufferLen(2), obmsg.Name("test-upstream-span-queue"))
	defer q.Close()

	got := make(chan int, 1)
	go ConsumeUpstreamSpanQueue(ctx, q, func(_ context.Context, batch []obrequest.Span) error {
		got <- len(batch)
		return nil
	})
	time.Sleep(50 * time.Millisecond)

	q.Send([]obrequest.Span{{}, {}})

	select {
	case n := <-got:
		if n != 2 {
			t.Fatalf("expected 2 spans, got %d", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream queue consumer")
	}
}
