//go:build linux && obiupstream

package instrumenter

import (
	"context"
	"fmt"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/obi"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
	"go.opentelemetry.io/collector/exporter"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// RunUpstream starts upstream OBI with a caller-supplied app export queue.
// The queue can be drained by ConsumeUpstreamSpanQueue and bridged into telegen's pipeline.
func RunUpstream(
	ctx context.Context,
	cfg *obi.Config,
	sharedMetricsExporter sdkmetric.Exporter,
	sharedTracesExporter exporter.Traces,
	appQueue *msg.Queue[[]request.Span],
) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	ctxInfo, err := BuildCommonContextInfoWithExporter(ctx, cfg, sharedMetricsExporter, sharedTracesExporter)
	if err != nil {
		return fmt.Errorf("build upstream context info: %w", err)
	}

	opts := make([]Option, 0, 1)
	if appQueue != nil {
		opts = append(opts, OverrideAppExportQueue(appQueue))
	}
	return RunWithContextInfo(ctx, cfg, ctxInfo, opts...)
}
