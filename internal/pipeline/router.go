// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/exporters"
	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// Signal is an alias to sigdef.Signal for backwards compatibility
type Signal = sigdef.Signal

// Router routes signals through processors and to exporters
type Router struct {
	signalType SignalType
	log        *slog.Logger
	st         *selftelemetry.Metrics

	// Processing components
	processors  *ProcessorChain
	exporterReg *exporters.Registry

	// Signal queue
	queue     chan Signal
	queueSize int

	// Statistics
	received    atomic.Int64
	processed   atomic.Int64
	dropped     atomic.Int64
	exported    atomic.Int64
	exportError atomic.Int64

	// Batching
	batchSize     int
	flushInterval time.Duration

	// Lifecycle
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewRouter creates a new signal router
func NewRouter(
	signalType SignalType,
	queueSize int,
	processors *ProcessorChain,
	exporterReg *exporters.Registry,
	log *slog.Logger,
	st *selftelemetry.Metrics,
) *Router {
	if queueSize <= 0 {
		queueSize = 10000
	}

	return &Router{
		signalType:    signalType,
		log:           log.With("component", "router", "signal", string(signalType)),
		st:            st,
		processors:    processors,
		exporterReg:   exporterReg,
		queue:         make(chan Signal, queueSize),
		queueSize:     queueSize,
		batchSize:     1000,
		flushInterval: 5 * time.Second,
		stopCh:        make(chan struct{}),
	}
}

// Start begins processing signals
func (r *Router) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return nil
	}

	r.log.Info("starting router")

	// Start worker goroutines
	numWorkers := 2
	for i := 0; i < numWorkers; i++ {
		r.wg.Add(1)
		go r.worker(ctx, i)
	}

	r.running = true
	return nil
}

// Stop gracefully shuts down the router
func (r *Router) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	r.log.Info("stopping router", "queue_size", len(r.queue))
	close(r.stopCh)

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		r.log.Info("router stopped gracefully")
	case <-ctx.Done():
		r.log.Warn("router stop timed out")
	}

	r.running = false
	return nil
}

// Send queues a signal for processing
func (r *Router) Send(sig Signal) bool {
	r.received.Add(1)
	if r.st != nil {
		r.st.PipelineReceived.WithLabelValues(string(r.signalType)).Inc()
	}

	select {
	case r.queue <- sig:
		return true
	default:
		// Queue full, drop the signal
		r.dropped.Add(1)
		if r.st != nil {
			r.st.PipelineDropped.WithLabelValues(string(r.signalType), "queue_full").Inc()
		}
		return false
	}
}

// SendBatch queues multiple signals for processing
func (r *Router) SendBatch(signals []Signal) int {
	sent := 0
	for _, sig := range signals {
		if r.Send(sig) {
			sent++
		}
	}
	return sent
}

// Stats returns current router statistics
func (r *Router) Stats() SignalStats {
	return SignalStats{
		QueueSize:   len(r.queue),
		QueueCap:    r.queueSize,
		Received:    r.received.Load(),
		Processed:   r.processed.Load(),
		Dropped:     r.dropped.Load(),
		Exported:    r.exported.Load(),
		ExportError: r.exportError.Load(),
	}
}

// worker processes signals from the queue
func (r *Router) worker(ctx context.Context, id int) {
	defer r.wg.Done()

	batch := make([]Signal, 0, r.batchSize)
	flushTicker := time.NewTicker(r.flushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.flush(ctx, batch)
			return

		case <-r.stopCh:
			// Drain remaining signals
			r.drain(ctx, batch)
			return

		case sig := <-r.queue:
			batch = append(batch, sig)
			if len(batch) >= r.batchSize {
				r.flush(ctx, batch)
				batch = batch[:0]
			}

		case <-flushTicker.C:
			if len(batch) > 0 {
				r.flush(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

// drain processes all remaining signals in the queue
func (r *Router) drain(ctx context.Context, batch []Signal) {
	drainTimeout := time.After(5 * time.Second)
	for {
		select {
		case sig := <-r.queue:
			batch = append(batch, sig)
			if len(batch) >= r.batchSize {
				r.flush(ctx, batch)
				batch = batch[:0]
			}
		case <-drainTimeout:
			if len(batch) > 0 {
				r.flush(ctx, batch)
			}
			return
		default:
			if len(batch) > 0 {
				r.flush(ctx, batch)
			}
			return
		}
	}
}

// flush processes and exports a batch of signals
func (r *Router) flush(ctx context.Context, batch []Signal) {
	if len(batch) == 0 {
		return
	}

	// Process through processor chain
	processed := make([]Signal, 0, len(batch))
	for _, sig := range batch {
		result, err := r.processors.Process(ctx, sig)
		if err != nil {
			r.log.Debug("processor dropped signal", "error", err)
			r.dropped.Add(1)
			if r.st != nil {
				r.st.PipelineDropped.WithLabelValues(string(r.signalType), "processor").Inc()
			}
			continue
		}
		if result != nil {
			processed = append(processed, result)
			r.processed.Add(1)
			if r.st != nil {
				r.st.PipelineProcessed.WithLabelValues(string(r.signalType)).Inc()
			}
		}
	}

	if len(processed) == 0 {
		return
	}

	// Export to all configured exporters
	if r.exporterReg != nil {
		if err := r.exporterReg.Export(ctx, r.signalType, processed); err != nil {
			r.exportError.Add(int64(len(processed)))
			if r.st != nil {
				r.st.PipelineExportError.WithLabelValues(string(r.signalType)).Add(float64(len(processed)))
			}
			r.log.Warn("export failed", "error", err, "count", len(processed))
		} else {
			r.exported.Add(int64(len(processed)))
			if r.st != nil {
				r.st.PipelineExported.WithLabelValues(string(r.signalType)).Add(float64(len(processed)))
			}
		}
	}
}
