package instrumenter

import (
	"context"
	"log/slog"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

// ConsumeUpstreamSpanQueue drains batches emitted to upstream OBI's override queue.
func ConsumeUpstreamSpanQueue(
	ctx context.Context,
	q *msg.Queue[[]request.Span],
	consumer func(context.Context, []request.Span) error,
) {
	if q == nil || consumer == nil {
		return
	}

	in := q.Subscribe(msg.SubscriberName("telegen.upstream_span_consumer"))
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-in:
			if !ok {
				return
			}
			if len(batch) == 0 {
				continue
			}
			if err := consumer(ctx, batch); err != nil {
				slog.Error("failed consuming upstream span batch", "error", err, "batch_size", len(batch))
			}
		}
	}
}
