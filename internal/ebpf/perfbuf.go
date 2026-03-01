// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
)

// PerfbufConfig holds perf buffer reader configuration
type PerfbufConfig struct {
	// PerCPUBufferSize is the size of each per-CPU buffer
	PerCPUBufferSize int `mapstructure:"per_cpu_buffer_size"`

	// Watermark is the number of bytes after which the buffer is flushed
	Watermark int `mapstructure:"watermark"`

	// Workers is the number of worker goroutines processing events
	Workers int `mapstructure:"workers"`

	// BatchSize is the number of events to batch before processing
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the max time to wait before processing a partial batch
	FlushInterval time.Duration `mapstructure:"flush_interval"`
}

// DefaultPerfbufConfig returns default configuration
func DefaultPerfbufConfig() PerfbufConfig {
	return PerfbufConfig{
		PerCPUBufferSize: os.Getpagesize() * 16,
		Watermark:        1,
		Workers:          2,
		BatchSize:        100,
		FlushInterval:    100 * time.Millisecond,
	}
}

// PerfbufEvent represents an event read from a perf buffer
type PerfbufEvent struct {
	// Raw is the raw event data
	Raw []byte

	// CPU is the CPU that generated the event
	CPU int

	// Timestamp is when the event was read
	Timestamp time.Time

	// Lost is the number of events lost before this one
	Lost uint64
}

// PerfEventHandler processes perf buffer events
type PerfEventHandler func(ctx context.Context, events []PerfbufEvent) error

// PerfbufReader reads events from BPF perf event arrays
type PerfbufReader struct {
	cfg     PerfbufConfig
	log     *slog.Logger
	st      *selftelemetry.Metrics
	mapName string

	reader  *perf.Reader
	handler PerfEventHandler

	// Statistics
	eventsReceived atomic.Int64
	eventsDropped  atomic.Int64
	eventsLost     atomic.Int64
	bytesReceived  atomic.Int64

	// Lifecycle
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewPerfbufReader creates a new perf buffer reader
func NewPerfbufReader(
	perfMap *ebpf.Map,
	mapName string,
	handler PerfEventHandler,
	cfg PerfbufConfig,
	log *slog.Logger,
	st *selftelemetry.Metrics,
) (*PerfbufReader, error) {
	if perfMap == nil {
		return nil, errors.New("perf map is nil")
	}

	opts := perf.ReaderOptions{
		Watermark: cfg.Watermark,
	}

	reader, err := perf.NewReaderWithOptions(perfMap, cfg.PerCPUBufferSize, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create perf buffer reader: %w", err)
	}

	r := &PerfbufReader{
		cfg:     cfg,
		log:     log.With("component", "perfbuf_reader", "map", mapName),
		st:      st,
		mapName: mapName,
		reader:  reader,
		handler: handler,
		stopCh:  make(chan struct{}),
	}

	return r, nil
}

// Start begins reading events from the perf buffer
func (r *PerfbufReader) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return errors.New("reader already running")
	}

	r.log.Info("starting perf buffer reader")
	r.running = true

	// Start reader goroutine
	r.wg.Add(1)
	go r.readLoop(ctx)

	return nil
}

// Stop stops the perf buffer reader
func (r *PerfbufReader) Stop(ctx context.Context) error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	r.log.Info("stopping perf buffer reader")
	close(r.stopCh)

	// Close reader to unblock Read()
	if err := r.reader.Close(); err != nil {
		r.log.Warn("error closing perf buffer reader", "error", err)
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		r.log.Info("perf buffer reader stopped")
	case <-ctx.Done():
		r.log.Warn("perf buffer reader stop timed out")
	}

	r.mu.Lock()
	r.running = false
	r.mu.Unlock()

	return nil
}

// readLoop is the main event reading loop
func (r *PerfbufReader) readLoop(ctx context.Context) {
	defer r.wg.Done()

	batch := make([]PerfbufEvent, 0, r.cfg.BatchSize)
	flushTimer := time.NewTimer(r.cfg.FlushInterval)
	defer flushTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			r.flush(ctx, batch)
			return

		case <-r.stopCh:
			r.flush(ctx, batch)
			return

		case <-flushTimer.C:
			if len(batch) > 0 {
				r.flush(ctx, batch)
				batch = batch[:0]
			}
			flushTimer.Reset(r.cfg.FlushInterval)

		default:
			// Try to read an event
			record, err := r.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					r.flush(ctx, batch)
					return
				}
				r.log.Debug("perf buffer read error", "error", err)
				continue
			}

			// Handle lost samples
			if record.LostSamples > 0 {
				r.eventsLost.Add(int64(record.LostSamples))
				if r.st != nil {
					r.st.PerfbufLost.WithLabelValues(r.mapName).Add(float64(record.LostSamples))
				}
				continue
			}

			if record.RawSample == nil {
				continue
			}

			event := PerfbufEvent{
				Raw:       record.RawSample,
				CPU:       record.CPU,
				Timestamp: time.Now(),
			}

			r.eventsReceived.Add(1)
			r.bytesReceived.Add(int64(len(record.RawSample)))

			if r.st != nil {
				r.st.PerfbufReceived.WithLabelValues(r.mapName).Inc()
				r.st.PerfbufBytes.WithLabelValues(r.mapName).Add(float64(len(record.RawSample)))
			}

			batch = append(batch, event)

			if len(batch) >= r.cfg.BatchSize {
				r.flush(ctx, batch)
				batch = batch[:0]
				flushTimer.Reset(r.cfg.FlushInterval)
			}
		}
	}
}

// flush processes a batch of events
func (r *PerfbufReader) flush(ctx context.Context, batch []PerfbufEvent) {
	if len(batch) == 0 || r.handler == nil {
		return
	}

	// Make a copy to avoid data races
	events := make([]PerfbufEvent, len(batch))
	copy(events, batch)

	if err := r.handler(ctx, events); err != nil {
		r.log.Warn("event handler error", "error", err, "count", len(events))
		r.eventsDropped.Add(int64(len(events)))
		if r.st != nil {
			r.st.PerfbufDropped.WithLabelValues(r.mapName).Add(float64(len(events)))
		}
	}
}

// Stats returns reader statistics
func (r *PerfbufReader) Stats() PerfbufStats {
	return PerfbufStats{
		EventsReceived: r.eventsReceived.Load(),
		EventsDropped:  r.eventsDropped.Load(),
		EventsLost:     r.eventsLost.Load(),
		BytesReceived:  r.bytesReceived.Load(),
	}
}

// PerfbufStats holds perf buffer statistics
type PerfbufStats struct {
	EventsReceived int64
	EventsDropped  int64
	EventsLost     int64
	BytesReceived  int64
}

// CreatePerfEventArray creates a perf event array map for use with perf buffers
func CreatePerfEventArray(name string, maxEntries uint32) (*ebpf.Map, error) {
	if maxEntries == 0 {
		maxEntries = uint32(runtime.NumCPU())
	}

	spec := &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.PerfEventArray,
		KeySize:    4, // u32 for CPU index
		ValueSize:  4, // u32 for fd
		MaxEntries: maxEntries,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create perf event array: %w", err)
	}

	return m, nil
}

// PerfEventHeader represents the common header for perf events
type PerfEventHeader struct {
	// Type identifies the event type
	Type uint32
	// Flags contains event flags
	Flags uint32
	// Size is the total size of the event including header
	Size uint32
}

// ParsePerfEventHeader parses a perf event header from raw data
func ParsePerfEventHeader(data []byte) (*PerfEventHeader, error) {
	if len(data) < int(unsafe.Sizeof(PerfEventHeader{})) {
		return nil, errors.New("insufficient data for perf event header")
	}

	return &PerfEventHeader{
		Type:  binary.LittleEndian.Uint32(data[0:4]),
		Flags: binary.LittleEndian.Uint32(data[4:8]),
		Size:  binary.LittleEndian.Uint32(data[8:12]),
	}, nil
}
