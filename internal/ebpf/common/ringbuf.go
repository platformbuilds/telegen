// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/helpers"
	"github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

// Max interval before reading stale available bytes from the ring buffer
const flushInterval = 3 * time.Second

// ringBufReader interface extracts the used methods from ringbuf.Reader for proper
// dependency injection during tests
type ringBufReader interface {
	io.Closer
	Read() (ringbuf.Record, error)
	ReadInto(*ringbuf.Record) error
	AvailableBytes() int
	Flush() error
}

// readerFactory instantiates a ringBufReader from a ring buffer. In unit tests, we can
// replace this function by a mock/dummy.
var readerFactory = func(rb *ebpf.Map) (ringBufReader, error) {
	return ringbuf.NewReader(rb)
}

type ringBufForwarder struct {
	cfg        *config.EBPFTracer
	logger     *slog.Logger
	ringbuffer *ebpf.Map
	closers    []io.Closer
	spans      []request.Span
	spansAlt   []request.Span
	spansLen   int
	access     sync.Mutex
	ticker     *time.Ticker
	reader     func(*EBPFParseContext, *config.EBPFTracer, *ringbuf.Record, ServiceFilter) (request.Span, bool, error)
	// filter the input spans, eliminating these from processes whose PID
	// belong to a process that does not match the discovery policies
	filter           ServiceFilter
	metrics          imetrics.Reporter
	parseContext     *EBPFParseContext
	lastReadAtNanos  atomic.Int64
	panicCount       atomic.Uint64
	lastPanicLog     atomic.Int64
	lastReadErrorLog atomic.Int64
}

// SharedRingbuf returns a function reads HTTPRequestTraces from an input ring buffer, accumulates them into an
// internal buffer, and forwards them to an output events channel, previously converted to request.Span
// instances.
func SharedRingbuf(
	eventContext *EBPFEventContext,
	parseContext *EBPFParseContext,
	cfg *config.EBPFTracer,
	filter ServiceFilter,
	ringbuffer *ebpf.Map,
	metrics imetrics.Reporter,
) func(context.Context, []io.Closer, *msg.Queue[[]request.Span]) {
	eventContext.RingBufLock.Lock()
	defer eventContext.RingBufLock.Unlock()

	log := slog.With("component", "ringbuf.Tracer")

	if eventContext.SharedRingBuffer != nil {
		log.Debug("reusing ringbuf forwarder")
		return eventContext.SharedRingBuffer.alreadyForwarded
	}

	rbf := ringBufForwarder{
		cfg: cfg, logger: log, ringbuffer: ringbuffer,
		closers: nil, reader: ReadBPFTraceAsSpan,
		filter: filter, metrics: metrics,
		parseContext: parseContext,
	}
	eventContext.SharedRingBuffer = &rbf
	return eventContext.SharedRingBuffer.sharedReadAndForward
}

func ForwardRingbuf(
	cfg *config.EBPFTracer,
	ringbuffer *ebpf.Map,
	filter ServiceFilter,
	reader func(*EBPFParseContext, *config.EBPFTracer, *ringbuf.Record, ServiceFilter) (request.Span, bool, error),
	logger *slog.Logger,
	metrics imetrics.Reporter,
	spansChan *msg.Queue[[]request.Span],
	closers ...io.Closer,
) func(context.Context, *msg.Queue[[]request.Span]) {
	rbf := ringBufForwarder{
		cfg: cfg, logger: logger, ringbuffer: ringbuffer,
		closers: closers, reader: reader,
		filter: filter, metrics: metrics,
		parseContext: NewEBPFParseContext(cfg, spansChan, filter),
	}
	return rbf.readAndForward
}

func (rbf *ringBufForwarder) sharedReadAndForward(ctx context.Context, closers []io.Closer, spansChan *msg.Queue[[]request.Span]) {
	rbf.logger.Debug("start reading and forwarding")
	// BPF will send each measured trace via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating perf reader. Exiting", "error", err)
		return
	}
	rbf.spans = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansAlt = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansLen = 0

	// If the underlying context is closed, it closes the objects we have allocated for this bpf program
	go rbf.bgListenSharedContextCancelation(ctx, closers, eventsReader)
	rbf.readAndForwardInner(ctx, eventsReader, spansChan)
}

func (rbf *ringBufForwarder) readAndForward(ctx context.Context, spansChan *msg.Queue[[]request.Span]) {
	rbf.logger.Debug("start reading and forwarding")
	// BPF will send each measured trace via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating perf reader. Exiting", "error", err)
		return
	}
	rbf.closers = append(rbf.closers, eventsReader)
	defer rbf.closeAllResources()

	rbf.spans = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansAlt = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansLen = 0

	// If the underlying context is closed, it closes the events reader
	// so the function can exit.
	go rbf.bgListenContextCancelation(ctx, eventsReader)
	rbf.readAndForwardInner(ctx, eventsReader, spansChan)
}

func (rbf *ringBufForwarder) flushOnAvailableBytes(ctx context.Context, eventsReader ringBufReader) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			available := eventsReader.AvailableBytes()
			lastReadAtNanos := rbf.lastReadAtNanos.Load()
			if available > 0 && lastReadAtNanos > 0 && time.Since(time.Unix(0, lastReadAtNanos)) > flushInterval {
				err := eventsReader.Flush()
				rbf.logger.Debug("flushing ringbuf", "available_bytes", available, "flush_err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (rbf *ringBufForwarder) readAndForwardInner(ctx context.Context, eventsReader ringBufReader, spansChan *msg.Queue[[]request.Span]) {
	// Forwards periodically on timeout, if the batch is not full
	if rbf.cfg.BatchTimeout > 0 {
		rbf.ticker = time.NewTicker(rbf.cfg.BatchTimeout)
		go rbf.bgFlushOnTimeout(ctx, spansChan)
	}

	// Ensure we periodically flush any pending bytes
	go rbf.flushOnAvailableBytes(ctx, eventsReader)

	// Main loop:
	// 1. Listen for content in the ring buffer
	// 2. Decode binary data into HTTPRequestTrace instance
	// 3. Accumulate the HTTPRequestTrace into a batch slice
	// 4. When the length of the batch slice reaches cfg.BatchLength,
	//    submit it to the next stage of the pipeline

	// We just log the first ring buffer read to check that the eBPF side is sending stuff
	// Logging each message adds few information and a lot of noise to the debug logs
	// in production systems with thousands of messages per second
	rbf.logger.Debug("starting to read ring buffer")
	rbf.lastReadAtNanos.Store(time.Now().UnixNano())

	var record ringbuf.Record
	const readErrorBudget = 1000
	consecutiveErrs := 0
	for {
		err := eventsReader.ReadInto(&record)
		rbf.lastReadAtNanos.Store(time.Now().UnixNano())
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) {
				rbf.logger.Debug("ring buffer already flushed")
				continue
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				rbf.logger.Debug("ring buffer is closed")
				return
			}
			consecutiveErrs++
			if consecutiveErrs >= readErrorBudget {
				rbf.logger.Error("ring buffer reader exceeded error budget; stopping loop",
					"consecutive_errors", consecutiveErrs,
					"error_budget", readErrorBudget,
					"last_error", err,
				)
				return
			}
			if helpers.ShouldLogEvery(&rbf.lastReadErrorLog, 10*time.Second) {
				rbf.logger.Warn("error reading from perf reader", "error", err)
			}
			backoff := time.Duration(1<<min(consecutiveErrs, 8)) * time.Millisecond
			if backoff > 250*time.Millisecond {
				backoff = 250 * time.Millisecond
			}
			time.Sleep(backoff)
			continue
		}
		consecutiveErrs = 0
		if len(record.RawSample) == 0 {
			if reg := selftelemetry.GlobalRegistry(); reg != nil {
				reg.RingLost.Inc()
			}
			continue
		}
		rbf.processAndForward(record, spansChan)
	}
}

func (rbf *ringBufForwarder) alreadyForwarded(ctx context.Context, _ []io.Closer, _ *msg.Queue[[]request.Span]) {
	<-ctx.Done()
}

func (rbf *ringBufForwarder) processAndForward(record ringbuf.Record, spansChan *msg.Queue[[]request.Span]) {
	var firstEventByte any = "none"
	if len(record.RawSample) > 0 {
		firstEventByte = record.RawSample[0]
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			panicCount := rbf.panicCount.Add(1)
			if reg := selftelemetry.GlobalRegistry(); reg != nil {
				reg.RingLost.Inc()
				reg.RecoveredPanics.WithLabelValues("ringbuf_forwarder").Inc()
			}
			if shouldRateLimitLog(&rbf.lastPanicLog, 60*time.Second) {
				rbf.logger.Error("recovered panic in processAndForward",
					"panic", recovered,
					"first_event_byte", firstEventByte,
					"panic_count", panicCount,
				)
			}
		}
	}()
	if reg := selftelemetry.GlobalRegistry(); reg != nil {
		reg.RingEvents.Inc()
	}

	s, ignore, err := rbf.reader(rbf.parseContext, rbf.cfg, &record, rbf.filter)
	if err != nil {
		rbf.logger.Debug("error parsing perf event", "error", err)
		return
	}
	if ignore {
		return
	}
	if !s.IsValid() {
		rbf.logger.Debug("invalid span", "span", s)
		return
	}

	rbf.access.Lock()
	rbf.spans[rbf.spansLen] = s
	// we need to decorate each span with the tracer's service name
	// if this information is not forwarded from eBPF
	rbf.spansLen++
	var batch []request.Span
	if rbf.spansLen == rbf.cfg.BatchLength {
		batch = rbf.takeBatchLocked()
		if rbf.ticker != nil {
			rbf.ticker.Reset(rbf.cfg.BatchTimeout)
		}
	}
	rbf.access.Unlock()
	if len(batch) > 0 {
		rbf.logger.Debug("submitting traces after batch is full", "len", len(batch))
		rbf.flushEvents(spansChan, batch)
	}
}

func shouldRateLimitLog(lastLog *atomic.Int64, interval time.Duration) bool {
	now := time.Now().UnixNano()
	last := lastLog.Load()
	if last != 0 && now-last < interval.Nanoseconds() {
		return false
	}
	return lastLog.CompareAndSwap(last, now)
}

func (rbf *ringBufForwarder) flushEvents(spansChan *msg.Queue[[]request.Span], batch []request.Span) {
	rbf.metrics.TracerFlush(len(batch))
	spansChan.Send(rbf.filter.Filter(batch))
}

func (rbf *ringBufForwarder) takeBatchLocked() []request.Span {
	batch := rbf.spans[:rbf.spansLen]
	if len(rbf.spansAlt) != rbf.cfg.BatchLength {
		rbf.spansAlt = make([]request.Span, rbf.cfg.BatchLength)
	}
	rbf.spans, rbf.spansAlt = rbf.spansAlt, rbf.spans
	rbf.spansLen = 0
	return batch
}

func (rbf *ringBufForwarder) bgFlushOnTimeout(ctx context.Context, spansChan *msg.Queue[[]request.Span]) {
	for {
		select {
		case <-ctx.Done():
			return

		case <-rbf.ticker.C:
			var batch []request.Span
			rbf.access.Lock()
			if rbf.spansLen > 0 {
				batch = rbf.takeBatchLocked()
			}
			rbf.access.Unlock()
			if len(batch) > 0 {
				rbf.logger.Debug("submitting traces on timeout", "len", len(batch))
				rbf.flushEvents(spansChan, batch)
			}
		}
	}
}

func (rbf *ringBufForwarder) bgListenContextCancelation(ctx context.Context, eventsReader ringBufReader) {
	<-ctx.Done()
	rbf.logger.Debug("context is cancelled. Closing events reader")
	if err := eventsReader.Close(); err != nil {
		rbf.logger.Debug("failed to close events reader", "error", err)
	}
}

func (rbf *ringBufForwarder) bgListenSharedContextCancelation(ctx context.Context, closers []io.Closer, eventsReader ringBufReader) {
	<-ctx.Done()
	rbf.logger.Debug("context is cancelled. Closing eBPF resources", "len", len(closers))
	// Often there are hundreds of closers, and don't have time to sequentially close within the
	// shutdown grace period. Closing them in parallel
	wg := sync.WaitGroup{}
	wg.Add(len(closers))
	for i := range closers {
		c := closers[i]
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				rbf.logger.Debug("failed to close eBPF resource", "error", err)
			}
		}()
	}
	wg.Wait()
	rbf.logger.Debug("closing events reader")
	if err := eventsReader.Close(); err != nil {
		rbf.logger.Debug("failed to close events reader", "error", err)
	}

	rbf.logger.Debug("the eBPF resources are closed")
}

func (rbf *ringBufForwarder) closeAllResources() {
	rbf.logger.Debug("closing eBPF resources", "len", len(rbf.closers))
	// Often there are hundreds of closers, and don't have time to sequentially close within the
	// shutdowm grace period. Closing them in parallel
	wg := sync.WaitGroup{}
	wg.Add(len(rbf.closers))
	for i := range rbf.closers {
		c := rbf.closers[i]
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				rbf.logger.Debug("failed to close eBPF resource", "error", err)
				return
			}
			rbf.logger.Debug("eBPF resource closed", "num", i)
		}()
	}
	wg.Wait()
	rbf.logger.Debug("the eBPF resources are closed")
}
