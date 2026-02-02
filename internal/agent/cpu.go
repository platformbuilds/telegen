// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// CPUConfig holds CPU limiter configuration
type CPUConfig struct {
	// MaxCPUPercent is the maximum CPU usage percentage (0-100)
	MaxCPUPercent float64 `mapstructure:"max_cpu_percent"`

	// CheckInterval is how often to check CPU usage
	CheckInterval time.Duration `mapstructure:"check_interval"`

	// ThrottleDuration is how long to throttle when limit is exceeded
	ThrottleDuration time.Duration `mapstructure:"throttle_duration"`

	// Enabled controls whether CPU limiting is active
	Enabled bool `mapstructure:"enabled"`
}

// DefaultCPUConfig returns default CPU limiter configuration
func DefaultCPUConfig() CPUConfig {
	return CPUConfig{
		MaxCPUPercent:    80.0,
		CheckInterval:    time.Second,
		ThrottleDuration: 100 * time.Millisecond,
		Enabled:          true,
	}
}

// CPULimiter monitors and throttles CPU usage
type CPULimiter struct {
	cfg CPUConfig
	log *slog.Logger
	st  *selftelemetry.Metrics

	// Throttling state
	throttled     atomic.Bool
	throttleUntil atomic.Int64

	// CPU tracking
	lastCPUTime  int64
	lastWallTime int64
	cpuPercent   atomic.Int64 // stored as percent * 100 for precision

	// Lifecycle
	mu     sync.RWMutex //nolint:unused // reserved for future thread-safe access
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewCPULimiter creates a new CPU limiter
func NewCPULimiter(cfg CPUConfig, log *slog.Logger, st *selftelemetry.Metrics) *CPULimiter {
	return &CPULimiter{
		cfg:    cfg,
		log:    log.With("component", "cpu_limiter"),
		st:     st,
		stopCh: make(chan struct{}),
	}
}

// Start begins CPU monitoring
func (c *CPULimiter) Start(ctx context.Context) error {
	if !c.cfg.Enabled {
		return nil
	}

	c.wg.Add(1)
	go c.monitor(ctx)
	return nil
}

// Stop halts CPU monitoring
func (c *CPULimiter) Stop(ctx context.Context) error {
	close(c.stopCh)
	c.wg.Wait()
	return nil
}

// ShouldThrottle returns true if processing should be throttled
func (c *CPULimiter) ShouldThrottle() bool {
	if !c.cfg.Enabled {
		return false
	}
	return c.throttled.Load()
}

// WaitIfThrottled blocks until throttling period ends
func (c *CPULimiter) WaitIfThrottled() {
	if !c.cfg.Enabled {
		return
	}

	for c.throttled.Load() {
		until := time.Unix(0, c.throttleUntil.Load())
		sleepTime := time.Until(until)
		if sleepTime <= 0 {
			c.throttled.Store(false)
			return
		}
		time.Sleep(sleepTime)
	}
}

// CPUPercent returns the current CPU usage percentage
func (c *CPULimiter) CPUPercent() float64 {
	return float64(c.cpuPercent.Load()) / 100.0
}

// monitor runs the CPU monitoring loop
func (c *CPULimiter) monitor(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.cfg.CheckInterval)
	defer ticker.Stop()

	// Initialize timing
	c.lastWallTime = time.Now().UnixNano()
	c.lastCPUTime = c.getCPUTime()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.checkCPU()
		}
	}
}

// checkCPU calculates current CPU usage and applies throttling if needed
func (c *CPULimiter) checkCPU() {
	now := time.Now().UnixNano()
	cpuTime := c.getCPUTime()

	wallDelta := now - c.lastWallTime
	cpuDelta := cpuTime - c.lastCPUTime

	if wallDelta > 0 {
		// Calculate CPU percentage (accounting for number of CPUs)
		numCPU := float64(runtime.NumCPU())
		percent := float64(cpuDelta) / float64(wallDelta) * 100.0 / numCPU
		c.cpuPercent.Store(int64(percent * 100)) // Store with 2 decimal precision

		// Update metrics
		if c.st != nil {
			c.st.CPUPercent.Set(percent)
		}

		// Check if throttling is needed
		if percent > c.cfg.MaxCPUPercent {
			c.throttled.Store(true)
			c.throttleUntil.Store(time.Now().Add(c.cfg.ThrottleDuration).UnixNano())
			c.log.Debug("CPU throttling activated",
				"cpu_percent", percent,
				"max_percent", c.cfg.MaxCPUPercent,
				"throttle_duration", c.cfg.ThrottleDuration,
			)
			if c.st != nil {
				c.st.CPUThrottled.Inc()
			}
		} else {
			// Check if we can release throttle
			if c.throttled.Load() {
				until := time.Unix(0, c.throttleUntil.Load())
				if time.Now().After(until) {
					c.throttled.Store(false)
				}
			}
		}
	}

	c.lastWallTime = now
	c.lastCPUTime = cpuTime
}

// getCPUTime returns the cumulative CPU time used by this process in nanoseconds
func (c *CPULimiter) getCPUTime() int64 {
	// This is a simplified implementation
	// On Linux, we'd read from /proc/self/stat
	// For now, we use a goroutine count based estimate
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Use GC CPU time as a proxy (not accurate but portable)
	return int64(m.GCCPUFraction * float64(time.Now().UnixNano()))
}
