// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package memory provides memory budget management for the Telegen agent.
package memory

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
)

// Config holds memory budget configuration
type Config struct {
	MaxMemoryMB      int64         `mapstructure:"max_memory_mb"`
	SoftLimitPercent int           `mapstructure:"soft_limit_percent"`
	HardLimitPercent int           `mapstructure:"hard_limit_percent"`
	CheckInterval    time.Duration `mapstructure:"check_interval"`
	GCOnLimit        bool          `mapstructure:"gc_on_limit"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		MaxMemoryMB:      512,
		SoftLimitPercent: 70,
		HardLimitPercent: 90,
		CheckInterval:    5 * time.Second,
		GCOnLimit:        true,
	}
}

// State represents the current memory pressure state
type State int32

const (
	StateNormal State = iota
	StateSoftLimit
	StateHardLimit
)

func (s State) String() string {
	switch s {
	case StateNormal:
		return "normal"
	case StateSoftLimit:
		return "soft_limit"
	case StateHardLimit:
		return "hard_limit"
	default:
		return "unknown"
	}
}

// Budget manages memory allocation and tracks usage
type Budget struct {
	cfg Config
	log *slog.Logger
	st  *selftelemetry.Metrics

	state     atomic.Int32
	allocated atomic.Int64
	peak      atomic.Int64

	softLimitBytes int64
	hardLimitBytes int64
	maxBytes       int64

	subscribersMu sync.RWMutex
	subscribers   []func(State)

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewBudget creates a new memory budget manager
func NewBudget(cfg Config, log *slog.Logger, st *selftelemetry.Metrics) (*Budget, error) {
	if cfg.MaxMemoryMB <= 0 {
		cfg.MaxMemoryMB = 512
	}
	if cfg.SoftLimitPercent <= 0 || cfg.SoftLimitPercent > 100 {
		cfg.SoftLimitPercent = 70
	}
	if cfg.HardLimitPercent <= 0 || cfg.HardLimitPercent > 100 {
		cfg.HardLimitPercent = 90
	}
	if cfg.HardLimitPercent <= cfg.SoftLimitPercent {
		cfg.HardLimitPercent = cfg.SoftLimitPercent + 10
		if cfg.HardLimitPercent > 100 {
			cfg.HardLimitPercent = 100
		}
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 5 * time.Second
	}

	maxBytes := cfg.MaxMemoryMB * 1024 * 1024
	b := &Budget{
		cfg:            cfg,
		log:            log.With("component", "memory_budget"),
		st:             st,
		maxBytes:       maxBytes,
		softLimitBytes: maxBytes * int64(cfg.SoftLimitPercent) / 100,
		hardLimitBytes: maxBytes * int64(cfg.HardLimitPercent) / 100,
		stopCh:         make(chan struct{}),
	}
	b.state.Store(int32(StateNormal))
	return b, nil
}

// Start begins the memory monitoring goroutine
func (b *Budget) Start(ctx context.Context) error {
	b.wg.Add(1)
	go b.monitor(ctx)
	return nil
}

// Stop halts the memory monitoring goroutine
func (b *Budget) Stop(_ context.Context) error {
	close(b.stopCh)
	b.wg.Wait()
	return nil
}

// Allocate attempts to allocate the given number of bytes
func (b *Budget) Allocate(bytes int64) bool {
	if bytes <= 0 {
		return true
	}
	newAllocated := b.allocated.Add(bytes)
	for {
		peak := b.peak.Load()
		if newAllocated <= peak || b.peak.CompareAndSwap(peak, newAllocated) {
			break
		}
	}
	if newAllocated > b.hardLimitBytes {
		b.allocated.Add(-bytes)
		b.updateState()
		if b.st != nil {
			b.st.MemoryRejected.Add(float64(bytes))
		}
		return false
	}
	b.updateState()
	return true
}

// Free releases the given number of bytes
func (b *Budget) Free(bytes int64) {
	if bytes <= 0 {
		return
	}
	newVal := b.allocated.Add(-bytes)
	if newVal < 0 {
		b.allocated.Store(0)
	}
	b.updateState()
}

// TryAllocate attempts allocation returning error if denied
func (b *Budget) TryAllocate(bytes int64) error {
	if b.Allocate(bytes) {
		return nil
	}
	return fmt.Errorf("memory budget exceeded: requested %d bytes", bytes)
}

// State returns the current memory pressure state
func (b *Budget) State() State { return State(b.state.Load()) }

// Allocated returns the current allocated bytes
func (b *Budget) Allocated() int64 { return b.allocated.Load() }

// Peak returns the peak allocated bytes
func (b *Budget) Peak() int64 { return b.peak.Load() }

// Available returns bytes available before hard limit
func (b *Budget) Available() int64 {
	available := b.hardLimitBytes - b.allocated.Load()
	if available < 0 {
		return 0
	}
	return available
}

// UsagePercent returns current usage as percentage
func (b *Budget) UsagePercent() float64 {
	return float64(b.allocated.Load()) / float64(b.maxBytes) * 100
}

// Subscribe registers a callback for state changes
func (b *Budget) Subscribe(callback func(State)) {
	b.subscribersMu.Lock()
	defer b.subscribersMu.Unlock()
	b.subscribers = append(b.subscribers, callback)
}

func (b *Budget) updateState() {
	allocated := b.allocated.Load()
	var newState State
	switch {
	case allocated >= b.hardLimitBytes:
		newState = StateHardLimit
	case allocated >= b.softLimitBytes:
		newState = StateSoftLimit
	default:
		newState = StateNormal
	}
	oldState := State(b.state.Swap(int32(newState)))
	if oldState != newState {
		b.notifySubscribers(newState)
		if b.st != nil {
			b.st.MemoryState.Set(float64(newState))
		}
	}
}

func (b *Budget) notifySubscribers(state State) {
	b.subscribersMu.RLock()
	subs := b.subscribers
	b.subscribersMu.RUnlock()
	for _, cb := range subs {
		cb(state)
	}
}

func (b *Budget) monitor(ctx context.Context) {
	defer b.wg.Done()
	ticker := time.NewTicker(b.cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.checkMemory()
		}
	}
}

func (b *Budget) checkMemory() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if b.st != nil {
		b.st.MemoryHeapBytes.Set(float64(m.HeapAlloc))
		b.st.MemoryStackBytes.Set(float64(m.StackInuse))
		b.st.MemoryAllocatedBytes.Set(float64(b.allocated.Load()))
		b.st.MemoryPeakBytes.Set(float64(b.peak.Load()))
	}
	state := b.State()
	if state == StateSoftLimit && b.cfg.GCOnLimit {
		b.log.Debug("triggering GC due to soft memory limit")
		runtime.GC()
	}
	if state == StateHardLimit {
		b.log.Warn("memory hard limit reached",
			"allocated", b.allocated.Load(),
			"limit", b.hardLimitBytes,
			"heap", m.HeapAlloc)
	}
}
