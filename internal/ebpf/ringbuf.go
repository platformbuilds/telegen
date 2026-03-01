// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
)

// RingbufConfig holds ring buffer reader configuration
type RingbufConfig struct {
	// BufferSize is the size hint for the ring buffer reader
	BufferSize int `mapstructure:"buffer_size"`

	// Workers is the number of worker goroutines processing events
	Workers int `mapstructure:"workers"`

	// BatchSize is the number of events to batch before processing
	BatchSize int `mapstructure:"batch_size"`

	// FlushInterval is the max time to wait before processing a partial batch
	FlushInterval time.Duration `mapstructure:"flush_interval"`
}

// DefaultRingbufConfig returns default configuration
func DefaultRingbufConfig() RingbufConfig {
	return RingbufConfig{
		BufferSize:    64 * 1024,
		Workers:       2,
		BatchSize:     100,
		FlushInterval: 100 * time.Millisecond,
	}
}

// RingbufEvent represents an event read from a ring buffer
type RingbufEvent struct {
	// Raw is the raw event data
	Raw []byte

	// Timestamp is when the event was read
	Timestamp time.Time
}

// EventHandler processes ring buffer events
type EventHandler func(ctx context.Context, events []RingbufEvent) error

// RingbufReader reads events from BPF ring buffers
type RingbufReader struct {
	cfg     RingbufConfig
	log     *slog.Logger
	st      *selftelemetry.Metrics
	mapName string

	reader  *ringbuf.Reader
	handler EventHandler

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

// NewRingbufReader creates a new ring buffer reader
func NewRingbufReader(
	ringbufMap *ebpf.Map,
	mapName string,
	handler EventHandler,
	cfg RingbufConfig,
	log *slog.Logger,
	st *selftelemetry.Metrics,
) (*RingbufReader, error) {
	if ringbufMap == nil {
		return nil, errors.New("ringbuf map is nil")
	}

	reader, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	r := &RingbufReader{
		cfg:     cfg,
		log:     log.With("component", "ringbuf_reader", "map", mapName),
		st:      st,
		mapName: mapName,
		reader:  reader,
		handler: handler,
		stopCh:  make(chan struct{}),
	}

	return r, nil
}

// Start begins reading events from the ring buffer
func (r *RingbufReader) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return errors.New("reader already running")
	}

	r.log.Info("starting ring buffer reader")
	r.running = true

	// Start reader goroutine
	r.wg.Add(1)
	go r.readLoop(ctx)

	return nil
}

// Stop stops the ring buffer reader
func (r *RingbufReader) Stop(ctx context.Context) error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	r.log.Info("stopping ring buffer reader")
	close(r.stopCh)

	// Close reader to unblock Read()
	if err := r.reader.Close(); err != nil {
		r.log.Warn("error closing ring buffer reader", "error", err)
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		r.log.Info("ring buffer reader stopped")
	case <-ctx.Done():
		r.log.Warn("ring buffer reader stop timed out")
	}

	r.mu.Lock()
	r.running = false
	r.mu.Unlock()

	return nil
}

// readLoop is the main event reading loop
func (r *RingbufReader) readLoop(ctx context.Context) {
	defer r.wg.Done()

	batch := make([]RingbufEvent, 0, r.cfg.BatchSize)
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
				if errors.Is(err, ringbuf.ErrClosed) {
					r.flush(ctx, batch)
					return
				}
				r.log.Debug("ring buffer read error", "error", err)
				continue
			}

			// Handle lost samples
			if record.RawSample == nil {
				r.eventsLost.Add(1)
				if r.st != nil {
					r.st.RingbufLost.WithLabelValues(r.mapName).Inc()
				}
				continue
			}

			event := RingbufEvent{
				Raw:       record.RawSample,
				Timestamp: time.Now(),
			}

			r.eventsReceived.Add(1)
			r.bytesReceived.Add(int64(len(record.RawSample)))

			if r.st != nil {
				r.st.RingbufReceived.WithLabelValues(r.mapName).Inc()
				r.st.RingbufBytes.WithLabelValues(r.mapName).Add(float64(len(record.RawSample)))
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
func (r *RingbufReader) flush(ctx context.Context, batch []RingbufEvent) {
	if len(batch) == 0 || r.handler == nil {
		return
	}

	// Make a copy to avoid data races
	events := make([]RingbufEvent, len(batch))
	copy(events, batch)

	if err := r.handler(ctx, events); err != nil {
		r.log.Warn("event handler error", "error", err, "count", len(events))
		r.eventsDropped.Add(int64(len(events)))
		if r.st != nil {
			r.st.RingbufDropped.WithLabelValues(r.mapName).Add(float64(len(events)))
		}
	}
}

// Stats returns reader statistics
func (r *RingbufReader) Stats() RingbufStats {
	return RingbufStats{
		EventsReceived: r.eventsReceived.Load(),
		EventsDropped:  r.eventsDropped.Load(),
		EventsLost:     r.eventsLost.Load(),
		BytesReceived:  r.bytesReceived.Load(),
	}
}

// RingbufStats holds ring buffer statistics
type RingbufStats struct {
	EventsReceived int64
	EventsDropped  int64
	EventsLost     int64
	BytesReceived  int64
}

// Helper functions for parsing common event fields

// ReadU32 reads a uint32 from an event at the given offset
func ReadU32(data []byte, offset int) (uint32, error) {
	if offset+4 > len(data) {
		return 0, errors.New("insufficient data for u32")
	}
	return binary.LittleEndian.Uint32(data[offset:]), nil
}

// ReadU64 reads a uint64 from an event at the given offset
func ReadU64(data []byte, offset int) (uint64, error) {
	if offset+8 > len(data) {
		return 0, errors.New("insufficient data for u64")
	}
	return binary.LittleEndian.Uint64(data[offset:]), nil
}

// ReadBytes reads a fixed-size byte slice from an event
func ReadBytes(data []byte, offset, size int) ([]byte, error) {
	if offset+size > len(data) {
		return nil, errors.New("insufficient data for bytes")
	}
	result := make([]byte, size)
	copy(result, data[offset:offset+size])
	return result, nil
}

// ReadCString reads a null-terminated string from an event
func ReadCString(data []byte, offset, maxLen int) (string, error) {
	if offset >= len(data) {
		return "", errors.New("offset out of range")
	}

	end := offset
	limit := offset + maxLen
	if limit > len(data) {
		limit = len(data)
	}

	for end < limit && data[end] != 0 {
		end++
	}

	return string(data[offset:end]), nil
}
