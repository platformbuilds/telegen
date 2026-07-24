//go:build !linux

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

func RunUpstream(
	_ context.Context,
	_ *obi.Config,
	_ sdkmetric.Exporter,
	_ exporter.Traces,
	_ *msg.Queue[[]request.Span],
) error {
	return fmt.Errorf("upstream OBI adapter is supported on linux only")
}
