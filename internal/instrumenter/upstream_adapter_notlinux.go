//go:build !linux

package instrumenter

import (
	"context"
	"fmt"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/obi"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/global"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

func RunUpstream(
	_ context.Context,
	_ *obi.Config,
	_ *global.ContextInfo,
	_ *msg.Queue[[]request.Span],
) error {
	return fmt.Errorf("upstream OBI adapter is supported on linux only")
}
