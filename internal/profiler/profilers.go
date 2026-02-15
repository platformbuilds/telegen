// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 CpuProfiler ../../bpf/profiler/cpu_profiler.c -- -I../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 OffcpuProfiler ../../bpf/profiler/offcpu_profiler.c -- -I../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 MutexProfiler ../../bpf/profiler/mutex_profiler.c -- -I../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 AllocProfiler ../../bpf/profiler/alloc_profiler.c -- -I../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 WallProfiler ../../bpf/profiler/wall_profiler.c -- -I../../bpf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// bpfTimeToWallClock converts BPF monotonic timestamps (from bpf_ktime_get_ns)
// to wall-clock time. BPF uses CLOCK_MONOTONIC which counts nanoseconds since
// system boot, not Unix epoch.
func bpfTimeToWallClock(bpfNs uint64) time.Time {
	if bpfNs == 0 {
		return time.Time{}
	}
	// Get current monotonic time
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Fallback: return current time if we can't get monotonic time
		return time.Now()
	}
	monoNowNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)

	// Calculate age of the BPF timestamp relative to now
	var ageNs int64
	if monoNowNs >= bpfNs {
		ageNs = int64(monoNowNs - bpfNs)
	} else {
		// BPF timestamp is in the future (shouldn't happen, but handle gracefully)
		ageNs = 0
	}

	// Convert to wall-clock time: current time minus age
	return time.Now().Add(-time.Duration(ageNs))
}

// CPUProfiler handles CPU profiling using eBPF perf events
type CPUProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects - uses generated types from bpf2go
	objs *CpuProfilerObjects

	// Perf event file descriptors (one per CPU)
	perfFDs []int

	// Ring buffer reader for streaming samples
	ringReader *ringbuf.Reader

	// Symbol resolver for address symbolization
	resolver *SymbolResolver

	// State
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewCPUProfiler creates a new CPU profiler
func NewCPUProfiler(cfg Config, log *slog.Logger, resolver *SymbolResolver) (*CPUProfiler, error) {
	// Use provided resolver (shared across profilers) or create new one
	if resolver == nil {
		var err error
		resolver, err = NewSymbolResolver(log)
		if err != nil {
			log.Warn("failed to create symbol resolver for CPU profiler", "error", err)
			resolver = nil // Continue without symbol resolution
		}
	}

	return &CPUProfiler{
		config:   cfg,
		log:      log.With("profiler", "cpu"),
		stopCh:   make(chan struct{}),
		resolver: resolver,
	}, nil
}

// Start loads the eBPF program and starts CPU profiling
func (p *CPUProfiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	p.log.Info("starting CPU profiler", "sample_rate", p.config.SampleRate)

	// Load the BPF program from generated code
	if err := p.loadBPF(); err != nil {
		return fmt.Errorf("failed to load CPU profiler BPF: %w", err)
	}

	// Configure the profiler
	if err := p.configure(); err != nil {
		return fmt.Errorf("failed to configure CPU profiler: %w", err)
	}

	// Attach to perf events on each CPU
	attached, err := p.attachPerfEvents()
	if err != nil {
		return fmt.Errorf("failed to attach perf events: %w", err)
	}

	p.log.Info("CPU profiler BPF attached",
		"attached_cpus", attached,
		"sample_rate", p.config.SampleRate)

	// Start ring buffer reader for streaming samples
	if p.objs != nil && p.objs.CpuProfileEvents != nil {
		rd, err := ringbuf.NewReader(p.objs.CpuProfileEvents)
		if err != nil {
			p.log.Warn("failed to create ring buffer reader", "error", err)
		} else {
			p.ringReader = rd
			go p.processRingBuffer(ctx)
		}
	}

	p.running = true
	return nil
}

// Stop stops the CPU profiler
func (p *CPUProfiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.log.Info("stopping CPU profiler")

	close(p.stopCh)

	// Close ring buffer reader (Read() will return ErrClosed)
	if p.ringReader != nil {
		_ = p.ringReader.Close()
	}

	// Close perf event file descriptors
	for _, fd := range p.perfFDs {
		_ = unix.Close(fd)
	}
	p.perfFDs = nil

	// Close eBPF objects
	if p.objs != nil {
		_ = p.objs.Close()
		p.objs = nil
	}

	p.running = false
	return nil
}

// AddTargetPID dynamically adds a PID to the BPF target PID map
func (p *CPUProfiler) AddTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.CpuTargetPids != nil {
		return p.objs.CpuTargetPids.Put(uint32(pid), uint8(1))
	}
	return nil
}

// RemoveTargetPID removes a PID from the BPF target PID map
func (p *CPUProfiler) RemoveTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.CpuTargetPids != nil {
		return p.objs.CpuTargetPids.Delete(uint32(pid))
	}
	return nil
}

// Collect gathers current CPU profile data
func (p *CPUProfiler) Collect(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		p.log.Debug("CPU profiler not running, skipping collect")
		return nil, nil
	}

	collectStart := time.Now()
	profile := NewProfile(ProfileTypeCPU)
	profile.Metadata["sample_rate"] = fmt.Sprintf("%d", p.config.SampleRate)

	// Read aggregated counts from the BPF map
	if p.objs == nil || p.objs.CpuStackCounts == nil {
		p.log.Debug("CPU profiler counts map is nil, returning empty profile")
		return profile, nil
	}

	var key CpuProfilerStackKey
	var value CpuProfilerStackCount
	var sampleCount int
	const maxSamples = 10000 // Limit samples to prevent memory exhaustion
	keysToDelete := make([]CpuProfilerStackKey, 0, maxSamples)

	iter := p.objs.CpuStackCounts.Iterate()
	for iter.Next(&key, &value) {
		if sampleCount >= maxSamples {
			p.log.Warn("CPU profiler hit max sample limit, stopping collection", "max", maxSamples)
			break
		}

		sample := StackSample{
			PID:       key.Pid,
			TGID:      key.Tgid,
			Comm:      nullTermString(int8SliceToBytes(key.Comm[:])),
			Value:     int64(value.Count),
			Count:     int64(value.Count),
			FirstSeen: bpfTimeToWallClock(value.FirstSeenNs),
			LastSeen:  bpfTimeToWallClock(value.LastSeenNs),
		}

		// Resolve user stack trace with symbols
		if key.UserStackId >= 0 {
			sample.Frames = p.resolveStackWithPID(key.UserStackId, key.Pid)
		}

		// Resolve kernel stack trace if present
		if key.KernelStackId >= 0 {
			kernelFrames := p.resolveStackWithPID(key.KernelStackId, 0) // kernel PID = 0
			for i := range kernelFrames {
				kernelFrames[i].IsKernel = true
			}
			sample.Frames = append(sample.Frames, kernelFrames...)
		}

		profile.AddSample(sample)
		keysToDelete = append(keysToDelete, key)
		sampleCount++
	}

	if err := iter.Err(); err != nil {
		p.log.Warn("error iterating CPU stack counts", "error", err)
		// Don't delete keys if iteration failed
		return profile, nil
	}

	// Clear collected samples from BPF map to prevent unbounded growth
	deleted := 0
	for _, k := range keysToDelete {
		if err := p.objs.CpuStackCounts.Delete(&k); err != nil {
			// Log but continue - don't fail entire collection
			if deleted == 0 {
				p.log.Debug("error deleting CPU stack count", "error", err)
			}
		} else {
			deleted++
		}
	}

	// Set profile duration based on collection interval config
	profile.Duration = p.config.CollectionInterval
	if profile.Duration == 0 {
		// Fallback: use elapsed time since collection started
		profile.Duration = time.Since(collectStart)
	}

	p.log.Debug("collected CPU profile samples", "count", sampleCount, "deleted", deleted)
	return profile, nil
}

// loadBPF loads the eBPF program using the generated code from bpf2go
func (p *CPUProfiler) loadBPF() error {
	p.log.Info("loading CPU profiler BPF program")

	// Remove memory lock limit for BPF operations
	if err := rlimit.RemoveMemlock(); err != nil {
		p.log.Warn("failed to remove memlock rlimit, BPF loading may fail", "error", err)
	}

	p.objs = &CpuProfilerObjects{}
	if err := LoadCpuProfilerObjects(p.objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}

	p.log.Info("BPF objects loaded successfully")
	return nil
}

// configure sets up the profiler configuration in the BPF map
func (p *CPUProfiler) configure() error {
	if p.objs == nil || p.objs.CpuProfilerCfg == nil {
		return fmt.Errorf("BPF config map not loaded")
	}

	captureKernel := uint8(1)
	if p.config.ExcludeKernel {
		captureKernel = 0
	}
	captureUser := uint8(1)
	if p.config.ExcludeUser {
		captureUser = 0
	}

	cfg := CpuProfilerCpuProfilerConfig{
		SampleRateHz:  uint32(p.config.SampleRate),
		CaptureKernel: captureKernel,
		CaptureUser:   captureUser,
	}

	// Set target PID filtering if specified (skip sentinel PID)
	if len(p.config.TargetPIDs) > 0 && p.config.TargetPIDs[0] != 0xFFFFFFFF {
		cfg.TargetPid = p.config.TargetPIDs[0]
	}

	// Tell BPF whether userspace has process filters active.
	// When filter_active=1, BPF will ONLY profile PIDs in the target map
	// rather than falling through to "profile everything" when target_pid==0.
	if p.config.FilterActive {
		cfg.FilterActive = 1
	}

	if err := p.objs.CpuProfilerCfg.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("failed to configure BPF: %w", err)
	}

	// Populate target PIDs map for all discovered PIDs
	if len(p.config.TargetPIDs) > 0 && p.objs.CpuTargetPids != nil {
		for _, pid := range p.config.TargetPIDs {
			// Skip sentinel PID (0xFFFFFFFF = no processes matched yet)
			if pid == 0xFFFFFFFF {
				continue
			}
			if err := p.objs.CpuTargetPids.Put(uint32(pid), uint8(1)); err != nil {
				p.log.Warn("failed to add target PID", "pid", pid, "error", err)
			}
		}
	}

	p.log.Info("BPF profiler configured",
		"sample_rate_hz", cfg.SampleRateHz,
		"target_pids", len(p.config.TargetPIDs),
		"filter_active", p.config.FilterActive)
	return nil
}

// attachPerfEvents attaches the BPF program to perf events on each CPU
func (p *CPUProfiler) attachPerfEvents() (int, error) {
	if p.objs == nil || p.objs.ProfileCpu == nil {
		return 0, fmt.Errorf("BPF program not loaded")
	}

	numCPUs := runtime.NumCPU()
	p.perfFDs = make([]int, 0, numCPUs)

	// When PerfBitFreq is set, Sample is the desired samples per second (frequency)
	sampleRate := p.config.SampleRate
	if sampleRate == 0 {
		sampleRate = 99 // Default to 99 Hz if not specified
	}

	attachedCount := 0
	for cpu := 0; cpu < numCPUs; cpu++ {
		// Create perf event with frequency-based sampling
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: uint64(sampleRate), // Frequency in Hz when PerfBitFreq is set
			Bits:   unix.PerfBitFreq,
		}

		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			// Non-fatal: some CPUs might be offline
			p.log.Warn("failed to open perf event", "cpu", cpu, "error", err)
			continue
		}

		// Attach BPF program to perf event using ioctl
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, p.objs.ProfileCpu.FD()); err != nil {
			_ = unix.Close(fd)
			p.log.Warn("failed to attach BPF program to perf event", "cpu", cpu, "error", err)
			continue
		}

		// Enable the perf event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			_ = unix.Close(fd)
			p.log.Warn("failed to enable perf event", "cpu", cpu, "error", err)
			continue
		}

		p.perfFDs = append(p.perfFDs, fd)
		attachedCount++
		p.log.Debug("attached BPF program to perf event", "cpu", cpu)
	}

	if attachedCount == 0 {
		return 0, fmt.Errorf("failed to attach BPF program to any CPU")
	}

	p.log.Info("BPF profiler attached to perf events", "total_cpus", numCPUs, "attached", attachedCount)
	return attachedCount, nil
}

// resolveStackWithPID resolves a stack trace with PID context for proper symbol resolution
func (p *CPUProfiler) resolveStackWithPID(stackID int32, pid uint32) []ResolvedFrame {
	if p.objs == nil || p.objs.CpuStacks == nil || stackID < 0 {
		return nil
	}

	// Read stack trace from map
	var addrs [127]uint64
	if err := p.objs.CpuStacks.Lookup(uint32(stackID), &addrs); err != nil {
		return nil
	}

	// Extract non-zero addresses
	validAddrs := make([]uint64, 0, len(addrs))
	for _, addr := range addrs {
		if addr == 0 {
			break
		}
		validAddrs = append(validAddrs, addr)
	}

	if len(validAddrs) == 0 {
		return nil
	}

	// If no resolver available, return unresolved frames
	if p.resolver == nil {
		p.log.Warn("symbol resolver not available for CPU profiler",
			"pid", pid, "stack_id", stackID, "frame_count", len(validAddrs))
		frames := make([]ResolvedFrame, len(validAddrs))
		for i, addr := range validAddrs {
			frames[i] = ResolvedFrame{
				Address:  addr,
				Function: fmt.Sprintf("0x%x", addr),
				Resolved: false,
			}
		}
		return frames
	}

	// Resolve addresses to symbols with PID context
	frames := make([]ResolvedFrame, 0, len(validAddrs))
	resolvedCount := 0
	for _, addr := range validAddrs {
		frame, err := p.resolver.Resolve(pid, addr)
		if err != nil || frame == nil {
			// Fallback to unresolved
			frames = append(frames, ResolvedFrame{
				Address:  addr,
				Function: fmt.Sprintf("[unknown] 0x%x", addr),
				Resolved: false,
			})
		} else {
			frames = append(frames, *frame)
			if frame.Resolved {
				resolvedCount++
			}
		}
	}

	// Log warning if no symbols were resolved
	if len(frames) > 0 && resolvedCount == 0 {
		p.log.Debug("no symbols resolved in CPU stack",
			"pid", pid, "frame_count", len(frames))
	}

	return frames
}

// processRingBuffer reads samples from the ring buffer in real-time
func (p *CPUProfiler) processRingBuffer(ctx context.Context) {
	p.log.Info("starting ring buffer processor")
	sampleCount := 0
	emptyReads := 0
	lastStatsLog := time.Now()

	for {
		select {
		case <-ctx.Done():
			p.log.Info("ring buffer processor stopped (context cancelled)",
				"samples_processed", sampleCount, "empty_reads", emptyReads)
			return
		case <-p.stopCh:
			p.log.Info("ring buffer processor stopped",
				"samples_processed", sampleCount, "empty_reads", emptyReads)
			return
		default:
		}

		// Non-blocking read with timeout to allow checking shutdown signals
		record, err := p.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				p.log.Debug("ring buffer closed")
				return
			}
			// Brief pause on error to avoid tight loop
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Parse the sample event from the ring buffer
		if len(record.RawSample) >= 8 { // Minimum size check
			sampleCount++
			if emptyReads > 0 {
				p.log.Debug("ring buffer resumed after idle period", "consecutive_empty_reads", emptyReads)
				emptyReads = 0 // Reset backoff counter
			}
			// The ring buffer contains CpuProfilerSampleEvent structs
			// These are also aggregated in the BPF map for batch collection
			// This path is primarily for real-time streaming if needed
			if sampleCount%10000 == 0 {
				p.log.Debug("ring buffer samples processed", "count", sampleCount)
			}
		} else if len(record.RawSample) == 0 {
			// Ring buffer returned empty, apply backoff to prevent CPU spinning
			emptyReads++
			backoff := emptyReads
			if backoff > 100 {
				backoff = 100
			}
			sleepTime := time.Duration(backoff) * time.Millisecond

			// Log if we're experiencing sustained empty reads (potential CPU spin)
			if emptyReads == 10 || emptyReads == 100 || emptyReads%1000 == 0 {
				p.log.Warn("ring buffer experiencing sustained empty reads - possible CPU spin",
					"consecutive_empty_reads", emptyReads, "backoff_ms", sleepTime.Milliseconds())
			}

			time.Sleep(sleepTime)
		}

		// Periodic stats logging
		if time.Since(lastStatsLog) > 60*time.Second {
			p.log.Info("ring buffer processor stats",
				"samples", sampleCount, "empty_reads", emptyReads)
			lastStatsLog = time.Now()
		}
	}
}

// nullTermString converts a null-terminated byte slice to string
func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// int8SliceToBytes converts []int8 (C char array) to []byte
func int8SliceToBytes(s []int8) []byte {
	b := make([]byte, len(s))
	for i, v := range s {
		b[i] = byte(v)
	}
	return b
}

// OffCPUProfiler handles off-CPU profiling using sched_switch tracepoint
type OffCPUProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects - uses generated types from bpf2go
	objs *OffcpuProfilerObjects

	// Tracepoint link for sched_switch
	schedLink link.Link

	// Ring buffer reader for streaming samples
	ringReader *ringbuf.Reader

	// Symbol resolver for address symbolization
	resolver *SymbolResolver

	// State
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewOffCPUProfiler creates a new off-CPU profiler
func NewOffCPUProfiler(cfg Config, log *slog.Logger, resolver *SymbolResolver) (*OffCPUProfiler, error) {
	// Use provided resolver (shared across profilers) or create new one
	if resolver == nil {
		var err error
		resolver, err = NewSymbolResolver(log)
		if err != nil {
			log.Warn("failed to create symbol resolver for off-CPU profiler", "error", err)
			resolver = nil // Continue without symbol resolution
		}
	}

	return &OffCPUProfiler{
		config:   cfg,
		log:      log.With("profiler", "offcpu"),
		stopCh:   make(chan struct{}),
		resolver: resolver,
	}, nil
}

// Start starts off-CPU profiling
func (p *OffCPUProfiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	p.log.Info("starting off-CPU profiler",
		"min_block_time_ns", p.config.MinBlockTimeNs)

	// Load BPF program from generated code
	if err := p.loadBPF(); err != nil {
		return fmt.Errorf("failed to load off-CPU profiler BPF: %w", err)
	}

	// Configure the profiler
	if err := p.configure(); err != nil {
		_ = p.objs.Close()
		return fmt.Errorf("failed to configure off-CPU profiler: %w", err)
	}

	// Attach to sched_switch tracepoint
	if err := p.attachTracepoints(); err != nil {
		_ = p.objs.Close()
		return fmt.Errorf("failed to attach tracepoints: %w", err)
	}

	// Start ring buffer reader
	if p.objs.OffcpuEvents != nil {
		rd, err := ringbuf.NewReader(p.objs.OffcpuEvents)
		if err != nil {
			p.log.Warn("failed to create ring buffer reader", "error", err)
		} else {
			p.ringReader = rd
			go p.processRingBuffer(ctx)
		}
	}

	p.running = true
	p.log.Info("off-CPU profiler started")
	return nil
}

// Stop stops off-CPU profiling
func (p *OffCPUProfiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.log.Info("stopping off-CPU profiler")
	close(p.stopCh)

	if p.ringReader != nil {
		_ = p.ringReader.Close()
	}

	if p.schedLink != nil {
		_ = p.schedLink.Close()
		p.schedLink = nil
	}

	if p.objs != nil {
		_ = p.objs.Close()
		p.objs = nil
	}

	p.running = false
	return nil
}

// AddTargetPID dynamically adds a PID to the BPF target PID map
func (p *OffCPUProfiler) AddTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.OffcpuTargetPids != nil {
		return p.objs.OffcpuTargetPids.Put(uint32(pid), uint8(1))
	}
	return nil
}

// RemoveTargetPID removes a PID from the BPF target PID map
func (p *OffCPUProfiler) RemoveTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.OffcpuTargetPids != nil {
		return p.objs.OffcpuTargetPids.Delete(uint32(pid))
	}
	return nil
}

// Collect gathers off-CPU profile data
func (p *OffCPUProfiler) Collect(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	collectStart := time.Now()
	profile := NewProfile(ProfileTypeOffCPU)
	profile.Metadata["min_block_ns"] = fmt.Sprintf("%d", p.config.MinBlockTimeNs)

	if p.objs == nil || p.objs.OffcpuCounts == nil {
		return profile, nil
	}

	var key OffcpuProfilerOffcpuKey
	var value OffcpuProfilerOffcpuValue
	var sampleCount int
	const maxSamples = 10000
	keysToDelete := make([]OffcpuProfilerOffcpuKey, 0, maxSamples)

	iter := p.objs.OffcpuCounts.Iterate()
	for iter.Next(&key, &value) {
		if sampleCount >= maxSamples {
			p.log.Warn("off-CPU profiler hit max sample limit", "max", maxSamples)
			break
		}

		sample := StackSample{
			PID:         key.Pid,
			TGID:        key.Tgid,
			Comm:        nullTermString(int8SliceToBytes(key.Comm[:])),
			Value:       int64(value.TotalTimeNs),
			Count:       int64(value.Count),
			BlockReason: BlockReason(key.BlockReason),
		}

		// Resolve user stack with PID context
		if key.UserStackId >= 0 {
			sample.Frames = p.resolveStackWithPID(key.UserStackId, key.Pid)
		}

		// Resolve kernel stack
		if key.KernelStackId >= 0 {
			kernelFrames := p.resolveStackWithPID(key.KernelStackId, 0) // kernel PID = 0
			for i := range kernelFrames {
				kernelFrames[i].IsKernel = true
			}
			sample.Frames = append(sample.Frames, kernelFrames...)
		}

		profile.AddSample(sample)
		keysToDelete = append(keysToDelete, key)
		sampleCount++
	}

	if err := iter.Err(); err != nil {
		p.log.Warn("error iterating off-CPU counts", "error", err)
		return profile, nil
	}

	// Clear collected samples from BPF map
	deleted := 0
	for _, k := range keysToDelete {
		if err := p.objs.OffcpuCounts.Delete(&k); err != nil {
			if deleted == 0 {
				p.log.Debug("error deleting off-CPU count", "error", err)
			}
		} else {
			deleted++
		}
	}

	// Set profile duration
	profile.Duration = p.config.CollectionInterval
	if profile.Duration == 0 {
		profile.Duration = time.Since(collectStart)
	}

	p.log.Debug("collected off-CPU profile samples", "count", sampleCount, "deleted", deleted)
	return profile, nil
}

// loadBPF loads the eBPF program using generated code
func (p *OffCPUProfiler) loadBPF() error {
	p.log.Info("loading off-CPU profiler BPF program")

	// Remove memory lock limit for BPF operations
	if err := rlimit.RemoveMemlock(); err != nil {
		p.log.Warn("failed to remove memlock rlimit, BPF loading may fail", "error", err)
	}

	p.objs = &OffcpuProfilerObjects{}
	if err := LoadOffcpuProfilerObjects(p.objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}

	p.log.Info("off-CPU BPF objects loaded successfully")
	return nil
}

// configure sets up the profiler configuration in the BPF map
func (p *OffCPUProfiler) configure() error {
	if p.objs == nil || p.objs.OffcpuCfg == nil {
		return fmt.Errorf("BPF config map not loaded")
	}

	minBlockNs := p.config.MinBlockTimeNs
	if minBlockNs == 0 {
		minBlockNs = 1000000 // Default 1ms
	}

	captureKernel := uint8(1)
	if p.config.ExcludeKernel {
		captureKernel = 0
	}
	captureUser := uint8(1)
	if p.config.ExcludeUser {
		captureUser = 0
	}

	cfg := OffcpuProfilerOffcpuConfig{
		MinBlockNs:    minBlockNs,
		CaptureKernel: captureKernel,
		CaptureUser:   captureUser,
	}

	if len(p.config.TargetPIDs) > 0 && p.config.TargetPIDs[0] != 0xFFFFFFFF {
		cfg.TargetPid = p.config.TargetPIDs[0]
	}

	// Tell BPF whether userspace has process filters active
	if p.config.FilterActive {
		cfg.FilterActive = 1
	}

	if err := p.objs.OffcpuCfg.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("failed to configure BPF: %w", err)
	}

	// Populate target PIDs map for all discovered PIDs
	if len(p.config.TargetPIDs) > 0 && p.objs.OffcpuTargetPids != nil {
		for _, pid := range p.config.TargetPIDs {
			if pid == 0xFFFFFFFF {
				continue
			}
			if err := p.objs.OffcpuTargetPids.Put(uint32(pid), uint8(1)); err != nil {
				p.log.Warn("failed to add off-CPU target PID", "pid", pid, "error", err)
			}
		}
	}

	p.log.Info("off-CPU BPF configured",
		"min_block_ns", minBlockNs,
		"target_pids", len(p.config.TargetPIDs),
		"filter_active", p.config.FilterActive)
	return nil
}

// attachTracepoints attaches the BPF program to the sched_switch tracepoint
func (p *OffCPUProfiler) attachTracepoints() error {
	if p.objs == nil || p.objs.OffcpuSchedSwitch == nil {
		return fmt.Errorf("BPF program not loaded")
	}

	// Attach tp_btf/sched_switch using tracing attachment
	l, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.OffcpuSchedSwitch,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sched_switch tracepoint: %w", err)
	}
	p.schedLink = l

	p.log.Info("attached to sched_switch tracepoint")
	return nil
}

// resolveStackWithPID resolves a stack trace with PID context for proper symbol resolution
func (p *OffCPUProfiler) resolveStackWithPID(stackID int32, pid uint32) []ResolvedFrame {
	if p.objs == nil || p.objs.OffcpuStacks == nil || stackID < 0 {
		return nil
	}

	var addrs [127]uint64
	if err := p.objs.OffcpuStacks.Lookup(uint32(stackID), &addrs); err != nil {
		return nil
	}

	// Extract non-zero addresses
	validAddrs := make([]uint64, 0, len(addrs))
	for _, addr := range addrs {
		if addr == 0 {
			break
		}
		validAddrs = append(validAddrs, addr)
	}

	if len(validAddrs) == 0 {
		return nil
	}

	// If no resolver available, return unresolved frames
	if p.resolver == nil {
		frames := make([]ResolvedFrame, len(validAddrs))
		for i, addr := range validAddrs {
			frames[i] = ResolvedFrame{
				Address:  addr,
				Function: fmt.Sprintf("0x%x", addr),
				Resolved: false,
			}
		}
		return frames
	}

	// Resolve addresses to symbols with PID context
	frames := make([]ResolvedFrame, 0, len(validAddrs))
	resolvedCount := 0
	for _, addr := range validAddrs {
		frame, err := p.resolver.Resolve(pid, addr)
		if err != nil || frame == nil {
			// Fallback to unresolved
			frames = append(frames, ResolvedFrame{
				Address:  addr,
				Function: fmt.Sprintf("[unknown] 0x%x", addr),
				Resolved: false,
			})
		} else {
			frames = append(frames, *frame)
			if frame.Resolved {
				resolvedCount++
			}
		}
	}

	// Log warning if no symbols were resolved
	if len(frames) > 0 && resolvedCount == 0 {
		p.log.Debug("no symbols resolved in OffCPU stack",
			"pid", pid, "frame_count", len(frames))
	}

	return frames
}

// processRingBuffer reads samples from the ring buffer
func (p *OffCPUProfiler) processRingBuffer(ctx context.Context) {
	p.log.Info("starting off-CPU ring buffer processor")
	sampleCount := 0
	emptyReads := 0
	lastStatsLog := time.Now()

	for {
		select {
		case <-ctx.Done():
			p.log.Info("off-CPU ring buffer processor stopped (context)",
				"samples", sampleCount, "empty_reads", emptyReads)
			return
		case <-p.stopCh:
			p.log.Info("off-CPU ring buffer processor stopped",
				"samples", sampleCount, "empty_reads", emptyReads)
			return
		default:
		}

		record, err := p.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if len(record.RawSample) >= 8 {
			sampleCount++
			if emptyReads > 0 {
				p.log.Debug("off-CPU ring buffer resumed", "consecutive_empty_reads", emptyReads)
				emptyReads = 0
			}
			if sampleCount%10000 == 0 {
				p.log.Debug("off-CPU samples processed", "count", sampleCount)
			}
		} else if len(record.RawSample) == 0 {
			emptyReads++
			backoff := emptyReads
			if backoff > 100 {
				backoff = 100
			}
			sleepTime := time.Duration(backoff) * time.Millisecond

			if emptyReads == 10 || emptyReads == 100 || emptyReads%1000 == 0 {
				p.log.Warn("off-CPU ring buffer sustained empty reads",
					"consecutive_empty_reads", emptyReads, "backoff_ms", sleepTime.Milliseconds())
			}

			time.Sleep(sleepTime)
		}

		if time.Since(lastStatsLog) > 60*time.Second {
			p.log.Info("off-CPU ring buffer stats",
				"samples", sampleCount, "empty_reads", emptyReads)
			lastStatsLog = time.Now()
		}
	}
}

// WallProfiler handles wall clock profiling combining on-CPU + off-CPU time
// It uses perf_event sampling and sched_switch tracing to measure total elapsed time
type WallProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects - uses generated types from bpf2go
	objs *WallProfilerObjects

	// Perf event file descriptors (one per CPU)
	perfFDs []int

	// Ring buffer reader for streaming samples
	ringReader *ringbuf.Reader

	// Symbol resolver for address symbolization
	resolver *SymbolResolver

	// State
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewWallProfiler creates a new wall clock profiler
func NewWallProfiler(cfg Config, log *slog.Logger, resolver *SymbolResolver) (*WallProfiler, error) {
	// Use provided resolver (shared across profilers) or create new one
	if resolver == nil {
		var err error
		resolver, err = NewSymbolResolver(log)
		if err != nil {
			log.Warn("failed to create symbol resolver for wall profiler", "error", err)
			resolver = nil // Continue without symbol resolution
		}
	}

	return &WallProfiler{
		config:   cfg,
		log:      log.With("profiler", "wall"),
		stopCh:   make(chan struct{}),
		resolver: resolver,
	}, nil
}

// Start loads the eBPF program and starts wall clock profiling
func (p *WallProfiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	sampleRate := p.config.WallSampleRate
	if sampleRate <= 0 {
		sampleRate = 19 // Default 19 Hz for wall profiler (lower than CPU to reduce overhead)
	}
	p.log.Info("starting wall clock profiler", "sample_rate", sampleRate)

	// Load the BPF program from generated code
	if err := p.loadBPF(); err != nil {
		return fmt.Errorf("failed to load wall profiler BPF: %w", err)
	}

	// Configure the profiler
	if err := p.configure(); err != nil {
		return fmt.Errorf("failed to configure wall profiler: %w", err)
	}

	// Attach to perf events on each CPU (same as CPU profiler)
	attached, err := p.attachPerfEvents(sampleRate)
	if err != nil {
		return fmt.Errorf("failed to attach perf events: %w", err)
	}

	p.log.Info("wall profiler BPF attached",
		"attached_cpus", attached,
		"sample_rate", sampleRate)

	// Start ring buffer reader for streaming samples
	if p.objs != nil && p.objs.WallEvents != nil {
		rd, err := ringbuf.NewReader(p.objs.WallEvents)
		if err != nil {
			p.log.Warn("failed to create ring buffer reader", "error", err)
		} else {
			p.ringReader = rd
			go p.processRingBuffer(ctx)
		}
	}

	p.running = true
	return nil
}

// Stop stops wall clock profiling
func (p *WallProfiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.log.Info("stopping wall clock profiler")

	close(p.stopCh)

	// Close ring buffer reader
	if p.ringReader != nil {
		_ = p.ringReader.Close()
	}

	// Close perf event file descriptors
	for _, fd := range p.perfFDs {
		_ = unix.Close(fd)
	}
	p.perfFDs = nil

	// Close eBPF objects
	if p.objs != nil {
		_ = p.objs.Close()
		p.objs = nil
	}

	p.running = false
	return nil
}

// AddTargetPID dynamically adds a PID to the BPF target PID map
func (p *WallProfiler) AddTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.WallTargetPids != nil {
		return p.objs.WallTargetPids.Put(uint32(pid), uint8(1))
	}
	return nil
}

// RemoveTargetPID removes a PID from the BPF target PID map
func (p *WallProfiler) RemoveTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.WallTargetPids != nil {
		return p.objs.WallTargetPids.Delete(uint32(pid))
	}
	return nil
}

// Collect gathers wall clock profile data
func (p *WallProfiler) Collect(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	collectStart := time.Now()
	profile := NewProfile(ProfileTypeWall)

	sampleRate := p.config.WallSampleRate
	if sampleRate <= 0 {
		sampleRate = 19
	}
	profile.Metadata["sample_rate"] = fmt.Sprintf("%d", sampleRate)

	// Read aggregated counts from the BPF map
	if p.objs == nil || p.objs.WallCounts == nil {
		p.log.Debug("wall profiler counts map is nil, returning empty profile")
		return profile, nil
	}

	var key WallProfilerWallKey
	var value WallProfilerWallValue
	var sampleCount int
	const maxSamples = 10000
	keysToDelete := make([]WallProfilerWallKey, 0, maxSamples)

	iter := p.objs.WallCounts.Iterate()
	for iter.Next(&key, &value) {
		if sampleCount >= maxSamples {
			p.log.Warn("wall profiler hit max sample limit", "max", maxSamples)
			break
		}

		sample := StackSample{
			PID:   key.Pid,
			TGID:  key.Tid,
			Comm:  nullTermString(int8SliceToBytes(key.Comm[:])),
			Value: int64(value.TotalWallNs),
			Count: int64(value.Count),
		}

		// Store additional wall time breakdown in sample metadata
		// WallTime = CPUTime + OffCPUTime
		sample.WallTimeNs = value.TotalWallNs
		sample.CPUTimeNs = value.TotalCpuNs
		sample.OffCPUTimeNs = value.TotalOffcpuNs

		// Resolve user stack trace
		if key.UserStackId >= 0 {
			sample.Frames = p.resolveStackWithPID(key.UserStackId, key.Pid)
		}

		// Resolve kernel stack
		if key.KernelStackId >= 0 {
			kernelFrames := p.resolveStackWithPID(key.KernelStackId, 0)
			for i := range kernelFrames {
				kernelFrames[i].IsKernel = true
			}
			sample.Frames = append(sample.Frames, kernelFrames...)
		}

		profile.AddSample(sample)
		keysToDelete = append(keysToDelete, key)
		sampleCount++
	}

	if err := iter.Err(); err != nil {
		p.log.Warn("error iterating wall counts", "error", err)
		return profile, nil
	}

	// Clear collected samples from BPF map
	deleted := 0
	for _, k := range keysToDelete {
		if err := p.objs.WallCounts.Delete(&k); err != nil {
			if deleted == 0 {
				p.log.Debug("error deleting wall count", "error", err)
			}
		} else {
			deleted++
		}
	}

	profile.Duration = p.config.CollectionInterval
	if profile.Duration == 0 {
		profile.Duration = time.Since(collectStart)
	}

	p.log.Debug("collected wall clock profile samples", "count", sampleCount, "deleted", deleted)
	return profile, nil
}

// loadBPF loads the eBPF program using generated code
func (p *WallProfiler) loadBPF() error {
	p.log.Info("loading wall profiler BPF program")

	// Remove memory lock limit for BPF operations
	if err := rlimit.RemoveMemlock(); err != nil {
		p.log.Warn("failed to remove memlock rlimit, BPF loading may fail", "error", err)
	}

	p.objs = &WallProfilerObjects{}
	if err := LoadWallProfilerObjects(p.objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}

	p.log.Info("wall BPF objects loaded successfully")
	return nil
}

// configure sets up the profiler configuration in the BPF map
func (p *WallProfiler) configure() error {
	if p.objs == nil || p.objs.WallCfg == nil {
		return fmt.Errorf("BPF config map not loaded")
	}

	sampleRate := p.config.WallSampleRate
	if sampleRate <= 0 {
		sampleRate = 19
	}

	// Sample interval in nanoseconds
	sampleIntervalNs := uint64(1e9 / sampleRate)

	cfg := WallProfilerWallConfig{
		SampleIntervalNs: sampleIntervalNs,
	}

	if len(p.config.TargetPIDs) > 0 && p.config.TargetPIDs[0] != 0xFFFFFFFF {
		cfg.TargetPid = p.config.TargetPIDs[0]
	}

	// Tell BPF whether userspace has process filters active
	if p.config.FilterActive {
		cfg.FilterActive = 1
	}

	if err := p.objs.WallCfg.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("failed to configure BPF: %w", err)
	}

	// Populate target PIDs map
	if len(p.config.TargetPIDs) > 0 && p.objs.WallTargetPids != nil {
		for _, pid := range p.config.TargetPIDs {
			if pid == 0xFFFFFFFF {
				continue
			}
			if err := p.objs.WallTargetPids.Put(uint32(pid), uint8(1)); err != nil {
				p.log.Warn("failed to add wall target PID", "pid", pid, "error", err)
			}
		}
	}

	p.log.Info("wall BPF configured",
		"sample_interval_ns", sampleIntervalNs,
		"target_pids", len(p.config.TargetPIDs),
		"filter_active", p.config.FilterActive)
	return nil
}

// attachPerfEvents attaches the BPF program to perf events for each CPU
func (p *WallProfiler) attachPerfEvents(sampleRate int) (int, error) {
	if p.objs == nil || p.objs.ProfileWall == nil {
		return 0, fmt.Errorf("BPF program not loaded")
	}

	numCPUs := runtime.NumCPU()
	attached := 0

	// Create perf event on each CPU
	for cpu := 0; cpu < numCPUs; cpu++ {
		attr := &unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: uint64(sampleRate),
			Bits:   unix.PerfBitFreq,
		}

		fd, err := unix.PerfEventOpen(attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			p.log.Warn("failed to open perf event", "cpu", cpu, "error", err)
			continue
		}

		// Attach BPF program to perf event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, p.objs.ProfileWall.FD()); err != nil {
			p.log.Warn("failed to attach BPF to perf event", "cpu", cpu, "error", err)
			_ = unix.Close(fd)
			continue
		}

		// Enable the perf event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			p.log.Warn("failed to enable perf event", "cpu", cpu, "error", err)
			_ = unix.Close(fd)
			continue
		}

		p.perfFDs = append(p.perfFDs, fd)
		attached++
	}

	if attached == 0 {
		return 0, fmt.Errorf("failed to attach to any CPU")
	}

	return attached, nil
}

// resolveStackWithPID resolves a BPF stack trace to function names
func (p *WallProfiler) resolveStackWithPID(stackID int32, pid uint32) []ResolvedFrame {
	if stackID < 0 || p.objs == nil || p.objs.WallStacks == nil {
		return nil
	}

	var addrs [127]uint64
	if err := p.objs.WallStacks.Lookup(uint32(stackID), &addrs); err != nil {
		return nil
	}

	var frames []ResolvedFrame
	for _, addr := range addrs {
		if addr == 0 {
			break
		}

		frame := ResolvedFrame{
			Address: addr,
		}

		// Try to resolve the address
		if p.resolver != nil {
			if resolved, err := p.resolver.Resolve(pid, addr); err == nil && resolved.Function != "" {
				frame.Function = resolved.Function
				frame.ShortName = resolved.ShortName
				frame.Module = resolved.Module
				frame.File = resolved.File
				frame.Line = resolved.Line
				frame.Inlined = resolved.Inlined
				frame.Resolved = true
				frame.Class = resolved.Class
			}
		}

		if !frame.Resolved {
			frame.Function = fmt.Sprintf("[unresolved] 0x%x", addr)
		}

		frames = append(frames, frame)
	}

	return frames
}

// processRingBuffer reads samples from the BPF ring buffer
func (p *WallProfiler) processRingBuffer(ctx context.Context) {
	if p.ringReader == nil {
		return
	}

	p.log.Debug("starting wall profiler ring buffer reader")

	var sampleCount uint64
	var emptyReads uint64
	lastStatsLog := time.Now()

	for {
		select {
		case <-p.stopCh:
			p.log.Debug("wall ring buffer reader stopped")
			return
		case <-ctx.Done():
			p.log.Debug("wall ring buffer reader context cancelled")
			return
		default:
		}

		record, err := p.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			emptyReads++
			continue
		}

		if len(record.RawSample) > 0 {
			sampleCount++
		}

		// Log stats periodically
		if time.Since(lastStatsLog) > 30*time.Second {
			p.log.Debug("wall ring buffer stats",
				"samples", sampleCount, "empty_reads", emptyReads)
			lastStatsLog = time.Now()
		}
	}
}

// MemoryProfiler handles memory allocation profiling using uprobes on malloc/free
type MemoryProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects - uses generated types from bpf2go
	objs *AllocProfilerObjects

	// Uprobe executable handle
	libcExe *link.Executable

	// Uprobe links
	mallocLink  link.Link
	freeLink    link.Link
	callocLink  link.Link
	reallocLink link.Link

	// Ring buffer reader
	ringReader *ringbuf.Reader

	// Symbol resolver for address symbolization
	resolver *SymbolResolver

	// State
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewMemoryProfiler creates a new memory profiler
func NewMemoryProfiler(cfg Config, log *slog.Logger, resolver *SymbolResolver) (*MemoryProfiler, error) {
	// Use provided resolver (shared across profilers) or create new one
	if resolver == nil {
		var err error
		resolver, err = NewSymbolResolver(log)
		if err != nil {
			log.Warn("failed to create symbol resolver for memory profiler", "error", err)
			resolver = nil // Continue without symbol resolution
		}
	}

	return &MemoryProfiler{
		config:   cfg,
		log:      log.With("profiler", "memory"),
		stopCh:   make(chan struct{}),
		resolver: resolver,
	}, nil
}

// Start starts memory profiling
func (p *MemoryProfiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	p.log.Info("starting memory profiler",
		"min_alloc_size", p.config.MinAllocSize)

	// Load BPF program
	if err := p.loadBPF(); err != nil {
		return fmt.Errorf("failed to load memory profiler BPF: %w", err)
	}

	// Configure the profiler
	if err := p.configure(); err != nil {
		_ = p.objs.Close()
		return fmt.Errorf("failed to configure memory profiler: %w", err)
	}

	// Attach uprobes to libc
	if err := p.attachUprobes(); err != nil {
		_ = p.objs.Close()
		return fmt.Errorf("failed to attach uprobes: %w", err)
	}

	// Start ring buffer reader
	if p.objs.AllocEvents != nil {
		rd, err := ringbuf.NewReader(p.objs.AllocEvents)
		if err != nil {
			p.log.Warn("failed to create ring buffer reader", "error", err)
		} else {
			p.ringReader = rd
			go p.processRingBuffer(ctx)
		}
	}

	p.running = true
	p.log.Info("memory profiler started")
	return nil
}

// Stop stops memory profiling
func (p *MemoryProfiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.log.Info("stopping memory profiler")
	close(p.stopCh)

	if p.ringReader != nil {
		_ = p.ringReader.Close()
	}

	// Close uprobe links
	for _, l := range []link.Link{p.mallocLink, p.freeLink, p.callocLink, p.reallocLink} {
		if l != nil {
			_ = l.Close()
		}
	}
	p.mallocLink = nil
	p.freeLink = nil
	p.callocLink = nil
	p.reallocLink = nil

	if p.objs != nil {
		_ = p.objs.Close()
		p.objs = nil
	}

	p.running = false
	return nil
}

// AddTargetPID dynamically adds a PID to the BPF target PID map
func (p *MemoryProfiler) AddTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.AllocTargetPids != nil {
		return p.objs.AllocTargetPids.Put(uint32(pid), uint8(1))
	}
	return nil
}

// RemoveTargetPID removes a PID from the BPF target PID map
func (p *MemoryProfiler) RemoveTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.AllocTargetPids != nil {
		return p.objs.AllocTargetPids.Delete(uint32(pid))
	}
	return nil
}

// loadBPF loads the BPF program
func (p *MemoryProfiler) loadBPF() error {
	p.log.Info("loading memory profiler BPF program")

	// Remove memory lock limit for BPF operations
	if err := rlimit.RemoveMemlock(); err != nil {
		p.log.Warn("failed to remove memlock rlimit, BPF loading may fail", "error", err)
	}

	p.objs = &AllocProfilerObjects{}
	if err := LoadAllocProfilerObjects(p.objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}

	p.log.Info("memory BPF objects loaded successfully")
	return nil
}

// configure sets up the profiler configuration
func (p *MemoryProfiler) configure() error {
	if p.objs == nil || p.objs.AllocCfg == nil {
		return fmt.Errorf("BPF config map not loaded")
	}

	minSize := p.config.MinAllocSize
	if minSize == 0 {
		minSize = 1024 // Default 1KB minimum
	}

	cfg := AllocProfilerAllocConfig{
		MinSize:      minSize,
		TrackFree:    1,
		TrackCalloc:  1,
		TrackRealloc: 1,
		TrackMmap:    0, // mmap requires kprobe, more complex
	}

	if len(p.config.TargetPIDs) > 0 && p.config.TargetPIDs[0] != 0xFFFFFFFF {
		cfg.TargetPid = p.config.TargetPIDs[0]
	}

	// Tell BPF whether userspace has process filters active
	if p.config.FilterActive {
		cfg.FilterActive = 1
	}

	if err := p.objs.AllocCfg.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("failed to configure BPF: %w", err)
	}

	// Populate target PIDs map
	if len(p.config.TargetPIDs) > 0 && p.objs.AllocTargetPids != nil {
		for _, pid := range p.config.TargetPIDs {
			if pid == 0xFFFFFFFF {
				continue
			}
			if err := p.objs.AllocTargetPids.Put(uint32(pid), uint8(1)); err != nil {
				p.log.Warn("failed to add alloc target PID", "pid", pid, "error", err)
			}
		}
	}

	p.log.Info("memory BPF configured",
		"min_size", minSize,
		"target_pids", len(p.config.TargetPIDs),
		"filter_active", p.config.FilterActive)
	return nil
}

// findLibcForPID finds the libc path used by a specific process from /proc/<pid>/maps
// Returns the path accessible from the host (via /proc/<pid>/root for containers)
func findLibcForPID(pid uint32) (string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", mapsPath, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Look for libc.so entries (glibc or musl)
		// Format: address perms offset dev inode pathname
		// e.g., 7f8b7c000000-7f8b7c200000 r-xp 00000000 fd:00 12345 /lib64/libc.so.6
		if strings.Contains(line, "libc") && strings.Contains(line, ".so") {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				libcPath := fields[5]
				// For containerized processes, access via /proc/<pid>/root
				containerPath := fmt.Sprintf("/proc/%d/root%s", pid, libcPath)
				if _, err := os.Stat(containerPath); err == nil {
					return containerPath, nil
				}
				// Fallback to direct path (host process)
				if _, err := os.Stat(libcPath); err == nil {
					return libcPath, nil
				}
			}
		}
	}
	return "", fmt.Errorf("libc not found in /proc/%d/maps", pid)
}

// attachUprobes attaches uprobes to libc allocation functions
func (p *MemoryProfiler) attachUprobes() error {
	var libcPath string
	var err error

	// If we have target PIDs, find libc from one of them (for container support)
	if len(p.config.TargetPIDs) > 0 && p.config.TargetPIDs[0] != 0xFFFFFFFF {
		for _, pid := range p.config.TargetPIDs {
			if pid == 0 || pid == 0xFFFFFFFF {
				continue
			}
			libcPath, err = findLibcForPID(pid)
			if err == nil {
				p.log.Info("found libc for target process", "pid", pid, "libc", libcPath)
				break
			}
			p.log.Debug("failed to find libc for pid", "pid", pid, "error", err)
		}
	}

	// Fallback to common host paths if no target PID libc found
	if libcPath == "" {
		hostPaths := []string{
			"/lib/x86_64-linux-gnu/libc.so.6",
			"/lib64/libc.so.6",
			"/usr/lib/x86_64-linux-gnu/libc.so.6",
			"/lib/aarch64-linux-gnu/libc.so.6",
			"/usr/lib/libc.so.6",
			"/lib/libc.so.6",
			"/lib/libc.musl-x86_64.so.1",     // Alpine musl
			"/lib/ld-musl-x86_64.so.1",       // Alpine musl alternative
			"/usr/lib/libc.musl-x86_64.so.1", // musl in /usr
			"/lib/libc.musl-aarch64.so.1",    // Alpine ARM64
			"/lib/ld-musl-aarch64.so.1",      // Alpine ARM64 alternative
		}
		for _, path := range hostPaths {
			if _, err := os.Stat(path); err == nil {
				libcPath = path
				break
			}
		}
	}

	if libcPath == "" {
		return fmt.Errorf("could not find libc for uprobe attachment")
	}

	exe, err := link.OpenExecutable(libcPath)
	if err != nil {
		return fmt.Errorf("failed to open libc at %s: %w", libcPath, err)
	}
	p.libcExe = exe

	// Attach malloc uprobe
	if p.objs.TraceMallocEnter != nil {
		l, err := exe.Uprobe("malloc", p.objs.TraceMallocEnter, nil)
		if err != nil {
			p.log.Warn("failed to attach malloc uprobe", "error", err)
		} else {
			p.mallocLink = l
		}
	}

	// Attach free uprobe
	if p.objs.TraceFree != nil {
		l, err := exe.Uprobe("free", p.objs.TraceFree, nil)
		if err != nil {
			p.log.Warn("failed to attach free uprobe", "error", err)
		} else {
			p.freeLink = l
		}
	}

	// Attach calloc uprobe
	if p.objs.TraceCallocEnter != nil {
		l, err := exe.Uprobe("calloc", p.objs.TraceCallocEnter, nil)
		if err != nil {
			p.log.Warn("failed to attach calloc uprobe", "error", err)
		} else {
			p.callocLink = l
		}
	}

	// Attach realloc uprobe
	if p.objs.TraceReallocEnter != nil {
		l, err := exe.Uprobe("realloc", p.objs.TraceReallocEnter, nil)
		if err != nil {
			p.log.Warn("failed to attach realloc uprobe", "error", err)
		} else {
			p.reallocLink = l
		}
	}

	attachedCount := 0
	if p.mallocLink != nil {
		attachedCount++
	}
	if p.freeLink != nil {
		attachedCount++
	}

	if attachedCount == 0 {
		return fmt.Errorf("no uprobes attached")
	}

	p.log.Info("memory uprobes attached", "libc", libcPath, "count", attachedCount)
	return nil
}

// CollectHeap gathers heap profile data (live allocations)
func (p *MemoryProfiler) CollectHeap(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	collectStart := time.Now()
	profile := NewProfile(ProfileTypeHeap)

	if p.objs == nil || p.objs.LiveAllocs == nil {
		return profile, nil
	}

	var addr uint64
	var info AllocProfilerAllocInfo
	var totalBytes uint64
	var allocCount int
	const maxAllocs = 10000
	addrsToDelete := make([]uint64, 0, maxAllocs)

	iter := p.objs.LiveAllocs.Iterate()
	for iter.Next(&addr, &info) {
		if allocCount >= maxAllocs {
			p.log.Warn("heap profiler hit max alloc limit", "max", maxAllocs)
			break
		}

		sample := StackSample{
			PID:   info.Pid,
			Value: int64(info.Size),
			Count: 1,
		}

		if info.StackId >= 0 {
			sample.Frames = p.resolveStackWithPID(info.StackId, info.Pid)
		}

		profile.AddSample(sample)
		totalBytes += info.Size
		addrsToDelete = append(addrsToDelete, addr)
		allocCount++
	}

	if err := iter.Err(); err != nil {
		p.log.Warn("error iterating live allocs", "error", err)
		profile.Metadata["total_bytes"] = fmt.Sprintf("%d", totalBytes)
		profile.Metadata["alloc_count"] = fmt.Sprintf("%d", allocCount)
		return profile, iter.Err()
	}

	// Clear collected allocations from BPF map
	deleted := 0
	for _, a := range addrsToDelete {
		if err := p.objs.LiveAllocs.Delete(&a); err != nil {
			if deleted == 0 {
				p.log.Debug("error deleting live alloc", "error", err)
			}
		} else {
			deleted++
		}
	}

	profile.Metadata["total_bytes"] = fmt.Sprintf("%d", totalBytes)
	profile.Metadata["alloc_count"] = fmt.Sprintf("%d", allocCount)

	// Set profile duration
	profile.Duration = p.config.CollectionInterval
	if profile.Duration == 0 {
		profile.Duration = time.Since(collectStart)
	}

	p.log.Debug("collected heap profile", "allocs", allocCount, "bytes", totalBytes, "deleted", deleted)
	return profile, nil
}

// CollectAllocs gathers allocation statistics (aggregated by stack)
func (p *MemoryProfiler) CollectAllocs(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	collectStart := time.Now()
	profile := NewProfile(ProfileTypeAllocCount)

	if p.objs == nil || p.objs.AllocStatsMap == nil {
		return profile, nil
	}

	var key AllocProfilerAllocKey
	var stats AllocProfilerAllocStats
	var sampleCount int
	const maxSamples = 10000
	keysToDelete := make([]AllocProfilerAllocKey, 0, maxSamples)

	iter := p.objs.AllocStatsMap.Iterate()
	for iter.Next(&key, &stats) {
		if sampleCount >= maxSamples {
			p.log.Warn("alloc stats hit max sample limit", "max", maxSamples)
			break
		}

		sample := StackSample{
			Value: int64(stats.TotalBytes),
			Count: int64(stats.AllocCount),
		}

		if key.StackId >= 0 {
			sample.Frames = p.resolveStack(key.StackId)
		}

		profile.AddSample(sample)
		keysToDelete = append(keysToDelete, key)
		sampleCount++
	}

	if err := iter.Err(); err != nil {
		p.log.Warn("error iterating alloc stats", "error", err)
		p.log.Debug("collected alloc stats", "samples", sampleCount)
		return profile, iter.Err()
	}

	// Clear collected stats from BPF map
	deleted := 0
	for _, k := range keysToDelete {
		if err := p.objs.AllocStatsMap.Delete(&k); err != nil {
			if deleted == 0 {
				p.log.Debug("error deleting alloc stat", "error", err)
			}
		} else {
			deleted++
		}
	}

	// Set profile duration
	profile.Duration = p.config.CollectionInterval
	if profile.Duration == 0 {
		profile.Duration = time.Since(collectStart)
	}

	p.log.Debug("collected alloc stats", "samples", sampleCount, "deleted", deleted)
	return profile, nil
}

// Collect implements the Profiler interface - collects heap profile
func (p *MemoryProfiler) Collect(ctx context.Context) (*Profile, error) {
	return p.CollectHeap(ctx)
}

// resolveStack resolves a stack trace from its ID
func (p *MemoryProfiler) resolveStack(stackID int32) []ResolvedFrame {
	return p.resolveStackWithPID(stackID, 0)
}

// resolveStackWithPID resolves a stack trace with PID context for proper symbol resolution
func (p *MemoryProfiler) resolveStackWithPID(stackID int32, pid uint32) []ResolvedFrame {
	if p.objs == nil || p.objs.AllocStacks == nil || stackID < 0 {
		return nil
	}

	var addrs [127]uint64
	if err := p.objs.AllocStacks.Lookup(uint32(stackID), &addrs); err != nil {
		return nil
	}

	// Extract non-zero addresses
	validAddrs := make([]uint64, 0, len(addrs))
	for _, addr := range addrs {
		if addr == 0 {
			break
		}
		validAddrs = append(validAddrs, addr)
	}

	if len(validAddrs) == 0 {
		return nil
	}

	// If no resolver available, return unresolved frames
	if p.resolver == nil {
		frames := make([]ResolvedFrame, len(validAddrs))
		for i, addr := range validAddrs {
			frames[i] = ResolvedFrame{
				Address:  addr,
				Function: fmt.Sprintf("0x%x", addr),
				Resolved: false,
			}
		}
		return frames
	}

	// Resolve addresses to symbols with PID context
	frames := make([]ResolvedFrame, 0, len(validAddrs))
	resolvedCount := 0
	for _, addr := range validAddrs {
		frame, err := p.resolver.Resolve(pid, addr)
		if err != nil || frame == nil {
			// Fallback to unresolved
			frames = append(frames, ResolvedFrame{
				Address:  addr,
				Function: fmt.Sprintf("[unknown] 0x%x", addr),
				Resolved: false,
			})
		} else {
			frames = append(frames, *frame)
			if frame.Resolved {
				resolvedCount++
			}
		}
	}

	// Log warning if no symbols were resolved
	if len(frames) > 0 && resolvedCount == 0 {
		p.log.Debug("no symbols resolved in memory stack",
			"pid", pid, "frame_count", len(frames))
	}

	return frames
}

// processRingBuffer reads allocation events from the ring buffer
func (p *MemoryProfiler) processRingBuffer(ctx context.Context) {
	p.log.Info("starting memory ring buffer processor")
	allocCount := 0
	freeCount := 0
	emptyReads := 0
	lastStatsLog := time.Now()

	for {
		select {
		case <-ctx.Done():
			p.log.Info("memory ring buffer processor stopped (context)",
				"allocs", allocCount, "frees", freeCount, "empty_reads", emptyReads)
			return
		case <-p.stopCh:
			p.log.Info("memory ring buffer processor stopped",
				"allocs", allocCount, "frees", freeCount, "empty_reads", emptyReads)
			return
		default:
		}

		record, err := p.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if len(record.RawSample) >= 8 {
			// Parse event to distinguish alloc vs free
			if len(record.RawSample) >= 3 && record.RawSample[2] == 1 {
				freeCount++
			} else {
				allocCount++
			}
			if emptyReads > 0 {
				p.log.Debug("memory ring buffer resumed", "consecutive_empty_reads", emptyReads)
				emptyReads = 0
			}
			if (allocCount+freeCount)%10000 == 0 {
				p.log.Debug("memory events processed", "allocs", allocCount, "frees", freeCount)
			}
		} else if len(record.RawSample) == 0 {
			emptyReads++
			backoff := emptyReads
			if backoff > 100 {
				backoff = 100
			}
			sleepTime := time.Duration(backoff) * time.Millisecond

			if emptyReads == 10 || emptyReads == 100 || emptyReads%1000 == 0 {
				p.log.Warn("memory ring buffer sustained empty reads",
					"consecutive_empty_reads", emptyReads, "backoff_ms", sleepTime.Milliseconds())
			}

			time.Sleep(sleepTime)
		}

		if time.Since(lastStatsLog) > 60*time.Second {
			p.log.Info("memory ring buffer stats",
				"allocs", allocCount, "frees", freeCount, "empty_reads", emptyReads)
			lastStatsLog = time.Now()
		}
	}
}

// MutexProfiler handles mutex contention profiling using uprobes on pthread_mutex_lock
type MutexProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects - uses generated types from bpf2go
	objs *MutexProfilerObjects

	// Uprobe executable handle
	libpthreadExe *link.Executable

	// Uprobe links
	lockEnterLink link.Link
	lockExitLink  link.Link
	unlockLink    link.Link

	// Ring buffer reader
	ringReader *ringbuf.Reader

	// Symbol resolver for address symbolization
	resolver *SymbolResolver

	// State
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewMutexProfiler creates a new mutex profiler
func NewMutexProfiler(cfg Config, log *slog.Logger, resolver *SymbolResolver) (*MutexProfiler, error) {
	// Use provided resolver (shared across profilers) or create new one
	if resolver == nil {
		var err error
		resolver, err = NewSymbolResolver(log)
		if err != nil {
			log.Warn("failed to create symbol resolver for mutex profiler", "error", err)
			resolver = nil // Continue without symbol resolution
		}
	}

	return &MutexProfiler{
		config:   cfg,
		log:      log.With("profiler", "mutex"),
		stopCh:   make(chan struct{}),
		resolver: resolver,
	}, nil
}

// Start starts mutex profiling
func (p *MutexProfiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	p.log.Info("starting mutex profiler",
		"threshold_ns", p.config.ContentionThresholdNs)

	// Load BPF program
	if err := p.loadBPF(); err != nil {
		return fmt.Errorf("failed to load mutex profiler BPF: %w", err)
	}

	// Configure the profiler
	if err := p.configure(); err != nil {
		p.objs.Close()
		return fmt.Errorf("failed to configure mutex profiler: %w", err)
	}

	// Attach uprobes
	if err := p.attachUprobes(); err != nil {
		p.objs.Close()
		return fmt.Errorf("failed to attach uprobes: %w", err)
	}

	// Start ring buffer reader
	if p.objs.MutexEvents != nil {
		rd, err := ringbuf.NewReader(p.objs.MutexEvents)
		if err != nil {
			p.log.Warn("failed to create ring buffer reader", "error", err)
		} else {
			p.ringReader = rd
			go p.processRingBuffer(ctx)
		}
	}

	p.running = true
	p.log.Info("mutex profiler started")
	return nil
}

// Stop stops mutex profiling
func (p *MutexProfiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.log.Info("stopping mutex profiler")
	close(p.stopCh)

	if p.ringReader != nil {
		_ = p.ringReader.Close()
	}

	// Close uprobe links
	for _, l := range []link.Link{p.lockEnterLink, p.lockExitLink, p.unlockLink} {
		if l != nil {
			_ = l.Close()
		}
	}
	p.lockEnterLink = nil
	p.lockExitLink = nil
	p.unlockLink = nil

	if p.objs != nil {
		_ = p.objs.Close()
		p.objs = nil
	}

	p.running = false
	return nil
}

// AddTargetPID dynamically adds a PID to the BPF target PID map
func (p *MutexProfiler) AddTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.MutexTargetPids != nil {
		return p.objs.MutexTargetPids.Put(uint32(pid), uint8(1))
	}
	return nil
}

// RemoveTargetPID removes a PID from the BPF target PID map
func (p *MutexProfiler) RemoveTargetPID(pid uint32) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.objs != nil && p.objs.MutexTargetPids != nil {
		return p.objs.MutexTargetPids.Delete(uint32(pid))
	}
	return nil
}

// loadBPF loads the BPF program
func (p *MutexProfiler) loadBPF() error {
	p.log.Info("loading mutex profiler BPF program")

	// Remove memory lock limit for BPF operations
	if err := rlimit.RemoveMemlock(); err != nil {
		p.log.Warn("failed to remove memlock rlimit, BPF loading may fail", "error", err)
	}

	p.objs = &MutexProfilerObjects{}
	if err := LoadMutexProfilerObjects(p.objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}

	p.log.Info("mutex BPF objects loaded successfully")
	return nil
}

// configure sets up the profiler configuration
func (p *MutexProfiler) configure() error {
	if p.objs == nil || p.objs.MutexCfg == nil {
		return fmt.Errorf("BPF config map not loaded")
	}

	thresholdNs := p.config.ContentionThresholdNs
	if thresholdNs == 0 {
		thresholdNs = 1000000 // Default 1ms
	}

	cfg := MutexProfilerMutexConfig{
		ContentionThresholdNs: thresholdNs,
		HoldThresholdNs:       10000000, // Default 10ms hold warning
	}

	if len(p.config.TargetPIDs) > 0 && p.config.TargetPIDs[0] != 0xFFFFFFFF {
		cfg.TargetPid = p.config.TargetPIDs[0]
	}

	// Tell BPF whether userspace has process filters active
	if p.config.FilterActive {
		cfg.FilterActive = 1
	}

	if err := p.objs.MutexCfg.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("failed to configure BPF: %w", err)
	}

	// Populate target PIDs map
	if len(p.config.TargetPIDs) > 0 && p.objs.MutexTargetPids != nil {
		for _, pid := range p.config.TargetPIDs {
			if pid == 0xFFFFFFFF {
				continue
			}
			if err := p.objs.MutexTargetPids.Put(uint32(pid), uint8(1)); err != nil {
				p.log.Warn("failed to add mutex target PID", "pid", pid, "error", err)
			}
		}
	}

	p.log.Info("mutex BPF configured",
		"threshold_ns", thresholdNs,
		"target_pids", len(p.config.TargetPIDs),
		"filter_active", p.config.FilterActive)
	return nil
}

// attachUprobes attaches uprobes to pthread mutex functions
func (p *MutexProfiler) attachUprobes() error {
	// Find libpthread path (often in libc on modern systems)
	libPath := "/lib/x86_64-linux-gnu/libpthread.so.0"
	// Try common paths including musl (Alpine) where pthread is in libc
	for _, path := range []string{
		"/lib/x86_64-linux-gnu/libpthread.so.0",
		"/lib64/libpthread.so.0",
		"/lib/aarch64-linux-gnu/libpthread.so.0",
		"/lib/x86_64-linux-gnu/libc.so.6", // pthread often in libc now
		"/lib64/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/lib/libc.so.6",
		"/lib/libc.musl-x86_64.so.1",     // Alpine musl (pthread is in libc)
		"/lib/ld-musl-x86_64.so.1",       // Alpine musl alternative
		"/usr/lib/libc.musl-x86_64.so.1", // musl in /usr
		"/lib/libc.musl-aarch64.so.1",    // Alpine ARM64
		"/lib/ld-musl-aarch64.so.1",      // Alpine ARM64 alternative
	} {
		if _, err := os.Stat(path); err == nil {
			libPath = path
			break
		}
	}

	exe, err := link.OpenExecutable(libPath)
	if err != nil {
		return fmt.Errorf("failed to open libpthread at %s: %w", libPath, err)
	}
	p.libpthreadExe = exe

	// Attach pthread_mutex_lock enter uprobe
	if p.objs.TraceMutexLockEnter != nil {
		l, err := exe.Uprobe("pthread_mutex_lock", p.objs.TraceMutexLockEnter, nil)
		if err != nil {
			p.log.Warn("failed to attach pthread_mutex_lock enter uprobe", "error", err)
		} else {
			p.lockEnterLink = l
		}
	}

	// Attach pthread_mutex_lock exit uretprobe
	if p.objs.TraceMutexLockExit != nil {
		l, err := exe.Uretprobe("pthread_mutex_lock", p.objs.TraceMutexLockExit, nil)
		if err != nil {
			p.log.Warn("failed to attach pthread_mutex_lock exit uretprobe", "error", err)
		} else {
			p.lockExitLink = l
		}
	}

	// Attach pthread_mutex_unlock uprobe
	if p.objs.TraceMutexUnlock != nil {
		l, err := exe.Uprobe("pthread_mutex_unlock", p.objs.TraceMutexUnlock, nil)
		if err != nil {
			p.log.Warn("failed to attach pthread_mutex_unlock uprobe", "error", err)
		} else {
			p.unlockLink = l
		}
	}

	attachedCount := 0
	if p.lockEnterLink != nil {
		attachedCount++
	}
	if p.lockExitLink != nil {
		attachedCount++
	}
	if p.unlockLink != nil {
		attachedCount++
	}

	if attachedCount == 0 {
		return fmt.Errorf("no uprobes attached")
	}

	p.log.Info("mutex uprobes attached", "lib", libPath, "count", attachedCount)
	return nil
}

// Collect gathers mutex contention profile data
func (p *MutexProfiler) Collect(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	collectStart := time.Now()
	profile := NewProfile(ProfileTypeMutex)
	profile.Metadata["threshold_ns"] = fmt.Sprintf("%d", p.config.ContentionThresholdNs)

	if p.objs == nil || p.objs.MutexStatsMap == nil {
		return profile, nil
	}

	var key MutexProfilerMutexKey
	var stats MutexProfilerMutexStats
	var sampleCount int
	const maxSamples = 10000
	keysToDelete := make([]MutexProfilerMutexKey, 0, maxSamples)

	iter := p.objs.MutexStatsMap.Iterate()
	for iter.Next(&key, &stats) {
		if sampleCount >= maxSamples {
			p.log.Warn("mutex profiler hit max sample limit", "max", maxSamples)
			break
		}

		sample := StackSample{
			Value:    int64(stats.TotalWaitNs),
			Count:    int64(stats.ContentionCount),
			LockAddr: key.LockAddr, // Preserve lock address
		}

		if key.StackId >= 0 {
			sample.Frames = p.resolveStack(key.StackId)
		}

		profile.AddSample(sample)
		keysToDelete = append(keysToDelete, key)
		sampleCount++
	}

	if err := iter.Err(); err != nil {
		p.log.Warn("error iterating mutex stats", "error", err)
		p.log.Debug("collected mutex contention samples", "count", sampleCount)
		return profile, nil
	}

	// Clear collected stats from BPF map
	deleted := 0
	for _, k := range keysToDelete {
		if err := p.objs.MutexStatsMap.Delete(&k); err != nil {
			if deleted == 0 {
				p.log.Debug("error deleting mutex stat", "error", err)
			}
		} else {
			deleted++
		}
	}

	// Set profile duration
	profile.Duration = p.config.CollectionInterval
	if profile.Duration == 0 {
		profile.Duration = time.Since(collectStart)
	}

	p.log.Debug("collected mutex contention samples", "count", sampleCount, "deleted", deleted)
	return profile, nil
}

// resolveStack resolves a stack trace from its ID
func (p *MutexProfiler) resolveStack(stackID int32) []ResolvedFrame {
	return p.resolveStackWithPID(stackID, 0)
}

// resolveStackWithPID resolves a stack trace with PID context for proper symbol resolution
func (p *MutexProfiler) resolveStackWithPID(stackID int32, pid uint32) []ResolvedFrame {
	if p.objs == nil || p.objs.MutexStacks == nil || stackID < 0 {
		return nil
	}

	var addrs [127]uint64
	if err := p.objs.MutexStacks.Lookup(uint32(stackID), &addrs); err != nil {
		return nil
	}

	// Extract non-zero addresses
	validAddrs := make([]uint64, 0, len(addrs))
	for _, addr := range addrs {
		if addr == 0 {
			break
		}
		validAddrs = append(validAddrs, addr)
	}

	if len(validAddrs) == 0 {
		return nil
	}

	// If no resolver available, return unresolved frames
	if p.resolver == nil {
		frames := make([]ResolvedFrame, len(validAddrs))
		for i, addr := range validAddrs {
			frames[i] = ResolvedFrame{
				Address:  addr,
				Function: fmt.Sprintf("0x%x", addr),
				Resolved: false,
			}
		}
		return frames
	}

	// Resolve addresses to symbols with PID context
	frames := make([]ResolvedFrame, 0, len(validAddrs))
	resolvedCount := 0
	for _, addr := range validAddrs {
		frame, err := p.resolver.Resolve(pid, addr)
		if err != nil || frame == nil {
			// Fallback to unresolved
			frames = append(frames, ResolvedFrame{
				Address:  addr,
				Function: fmt.Sprintf("[unknown] 0x%x", addr),
				Resolved: false,
			})
		} else {
			frames = append(frames, *frame)
			if frame.Resolved {
				resolvedCount++
			}
		}
	}

	// Log warning if no symbols were resolved
	if len(frames) > 0 && resolvedCount == 0 {
		p.log.Debug("no symbols resolved in mutex stack",
			"pid", pid, "frame_count", len(frames))
	}

	return frames
}

// processRingBuffer reads contention events from the ring buffer
func (p *MutexProfiler) processRingBuffer(ctx context.Context) {
	p.log.Info("starting mutex ring buffer processor")
	eventCount := 0
	emptyReads := 0
	lastStatsLog := time.Now()

	for {
		select {
		case <-ctx.Done():
			p.log.Info("mutex ring buffer processor stopped (context)",
				"events", eventCount, "empty_reads", emptyReads)
			return
		case <-p.stopCh:
			p.log.Info("mutex ring buffer processor stopped",
				"events", eventCount, "empty_reads", emptyReads)
			return
		default:
		}

		record, err := p.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if len(record.RawSample) >= 8 {
			eventCount++
			if emptyReads > 0 {
				p.log.Debug("mutex ring buffer resumed", "consecutive_empty_reads", emptyReads)
				emptyReads = 0
			}
			if eventCount%1000 == 0 {
				p.log.Debug("mutex events processed", "count", eventCount)
			}
		} else if len(record.RawSample) == 0 {
			emptyReads++
			backoff := emptyReads
			if backoff > 100 {
				backoff = 100
			}
			sleepTime := time.Duration(backoff) * time.Millisecond

			if emptyReads == 10 || emptyReads == 100 || emptyReads%1000 == 0 {
				p.log.Warn("mutex ring buffer sustained empty reads",
					"consecutive_empty_reads", emptyReads, "backoff_ms", sleepTime.Milliseconds())
			}

			time.Sleep(sleepTime)
		}

		if time.Since(lastStatsLog) > 60*time.Second {
			p.log.Info("mutex ring buffer stats",
				"events", eventCount, "empty_reads", emptyReads)
			lastStatsLog = time.Now()
		}
	}
}
