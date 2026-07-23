//go:build !linux

package instrumenter

import (
	"context"
	"fmt"

	"github.com/mirastacklabs-ai/telegen/internal/obi"
	obrequest "go.opentelemetry.io/obi/pkg/appolly/app/request"
	obmsg "go.opentelemetry.io/obi/pkg/pipe/msg"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func RunUpstream(
	_ context.Context,
	_ *obi.Config,
	_ sdkmetric.Exporter,
	_ *obmsg.Queue[[]obrequest.Span],
) error {
	return fmt.Errorf("upstream OBI adapter is supported on linux only")
}
