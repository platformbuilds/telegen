//go:build linux && obiupstream

package instrumenter

import (
	"context"
	"fmt"

	"github.com/mirastacklabs-ai/telegen/internal/obi"
	obinstrumenter "go.opentelemetry.io/obi/pkg/instrumenter"
	obconfig "go.opentelemetry.io/obi/pkg/obi"
	obrequest "go.opentelemetry.io/obi/pkg/appolly/app/request"
	obmsg "go.opentelemetry.io/obi/pkg/pipe/msg"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"gopkg.in/yaml.v3"
)

// RunUpstream starts upstream OBI with a caller-supplied app export queue.
// The queue can be drained by ConsumeUpstreamSpanQueue and bridged into telegen's pipeline.
func RunUpstream(
	ctx context.Context,
	cfg *obi.Config,
	sharedMetricsExporter sdkmetric.Exporter,
	appQueue *obmsg.Queue[[]obrequest.Span],
) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	upCfg, err := toUpstreamConfig(cfg)
	if err != nil {
		return err
	}

	ctxInfo, err := obinstrumenter.BuildCommonContextInfo(ctx, upCfg)
	if err != nil {
		return fmt.Errorf("build upstream context info: %w", err)
	}
	if ctxInfo.OTELMetricsExporter != nil {
		ctxInfo.OTELMetricsExporter.SharedExporter = sharedMetricsExporter
	}

	opts := make([]obinstrumenter.Option, 0, 1)
	if appQueue != nil {
		opts = append(opts, obinstrumenter.OverrideAppExportQueue(appQueue))
	}
	return obinstrumenter.RunWithContextInfo(ctx, upCfg, ctxInfo, opts...)
}

func toUpstreamConfig(cfg *obi.Config) (*obconfig.Config, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal telegen OBI config: %w", err)
	}
	var upCfg obconfig.Config
	if err := yaml.Unmarshal(raw, &upCfg); err != nil {
		return nil, fmt.Errorf("unmarshal upstream OBI config: %w", err)
	}
	return &upCfg, nil
}
