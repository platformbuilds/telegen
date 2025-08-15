package pipeline

import (
	"context"
	"sync"

	"github.com/platformbuilds/telegen/internal/config"
)

// Pipeline is a thin runtime wrapper used by main.go to manage lifecycle.
// It keeps your demo span generation and can be extended to real capture.
type Pipeline struct {
	cfg *config.Config
	st  any // may (or may not) have Close/Shutdown/Stop

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(cfg *config.Config, st any) *Pipeline {
	return &Pipeline{cfg: cfg, st: st}
}

func (p *Pipeline) Start(ctx context.Context) error {
	ctx, p.cancel = context.WithCancel(ctx)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		tr := NewDemoTracer()
		DemoSpanGenerators(ctx, tr) // existing behavior
		<-ctx.Done()
	}()

	return nil
}

func (p *Pipeline) Close() {
	// stop background work
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()

	// best-effort shutdown of the self-telemetry handle, if it exposes one
	switch h := p.st.(type) {
	case interface{ Close() error }:
		_ = h.Close()
	case interface{ Shutdown() error }:
		_ = h.Shutdown()
	case interface{ Stop() }:
		h.Stop()
	}
}
