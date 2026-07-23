//go:build linux && !obiupstream

package instrumenter

import (
	"context"
	"fmt"

	"github.com/mirastacklabs-ai/telegen/internal/obi"
	obrequest "go.opentelemetry.io/obi/pkg/appolly/app/request"
	obmsg "go.opentelemetry.io/obi/pkg/pipe/msg"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// RunUpstream is disabled in default linux builds because upstream OBI runtime
// packages require generated artifacts not shipped in the Go module.
// Build with `-tags obiupstream` to enable direct upstream runtime integration.
func RunUpstream(
	_ context.Context,
	_ *obi.Config,
	_ sdkmetric.Exporter,
	_ *obmsg.Queue[[]obrequest.Span],
) error {
	return fmt.Errorf("upstream OBI runtime disabled in this build (enable with -tags obiupstream)")
}
