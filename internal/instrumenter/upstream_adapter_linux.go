//go:build linux && obiupstream

package instrumenter

import (
	"context"
	"fmt"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/obi"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/global"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

// RunUpstream starts upstream OBI with a caller-supplied context info and app export queue.
// The caller owns the ContextInfo because exactly one may exist per process: every build
// registers the internal-metrics collectors into the shared Prometheus registry, fetches the
// host ID, and constructs a Kubernetes metadata informer.
// The queue can be drained by ConsumeUpstreamSpanQueue and bridged into telegen's pipeline.
func RunUpstream(
	ctx context.Context,
	cfg *obi.Config,
	ctxInfo *global.ContextInfo,
	appQueue *msg.Queue[[]request.Span],
) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if ctxInfo == nil {
		return fmt.Errorf("context info cannot be nil")
	}

	opts := make([]Option, 0, 1)
	if appQueue != nil {
		opts = append(opts, OverrideAppExportQueue(appQueue))
	}
	return RunWithContextInfo(ctx, cfg, ctxInfo, opts...)
}
