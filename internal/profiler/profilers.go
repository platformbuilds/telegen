// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// CPUProfiler handles CPU profiling using eBPF perf events
type CPUProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects
	coll   *ebpf.Collection
	stacks *ebpf.Map
	counts *ebpf.Map
	events *ebpf.Map //nolint:unused // used by eBPF
	cfgMap *ebpf.Map

	// Perf event links (one per CPU)
	links []link.Link

	// State
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// cpuProfilerConfig matches the eBPF config struct
type cpuProfilerConfig struct {
	TargetPID     uint32
	SampleRateHz  uint32
	CaptureKernel uint8
	CaptureUser   uint8
	_pad          [2]byte //nolint:unused // padding for struct alignment
}

// NewCPUProfiler creates a new CPU profiler
func NewCPUProfiler(cfg Config, log *slog.Logger) (*CPUProfiler, error) {
	return &CPUProfiler{
		config: cfg,
		log:    log.With("profiler", "cpu"),
		stopCh: make(chan struct{}),
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

	// Load eBPF collection
	// In production, this would load from embedded bytes
	// For now, we'll create the maps programmatically
	if err := p.loadBPF(); err != nil {
		return fmt.Errorf("failed to load CPU profiler BPF: %w", err)
	}

	// Configure the profiler
	if err := p.configure(); err != nil {
		return fmt.Errorf("failed to configure CPU profiler: %w", err)
	}

	// Attach to perf events on each CPU
	if err := p.attachPerfEvents(); err != nil {
		return fmt.Errorf("failed to attach perf events: %w", err)
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

	// Detach perf event links
	for _, l := range p.links {
		_ = l.Close()
	}
	p.links = nil

	// Close eBPF collection
	if p.coll != nil {
		p.coll.Close()
		p.coll = nil
	}

	p.running = false
	return nil
}

// Collect gathers current CPU profile data
func (p *CPUProfiler) Collect(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	profile := NewProfile(ProfileTypeCPU)
	profile.Metadata["sample_rate"] = fmt.Sprintf("%d", p.config.SampleRate)

	// Read aggregated counts from the map
	if p.counts == nil {
		return profile, nil
	}

	var key StackKey
	var value StackCount

	iter := p.counts.Iterate()
	for iter.Next(&key, &value) {
		sample := StackSample{
			PID:       key.PID,
			TGID:      key.TGID,
			Comm:      nullTermString(key.Comm[:]),
			Value:     int64(value.Count),
			Count:     int64(value.Count),
			FirstSeen: time.Unix(0, int64(value.FirstSeenNs)),
			LastSeen:  time.Unix(0, int64(value.LastSeenNs)),
		}

		// Resolve stack traces
		if key.UserStackID >= 0 && p.stacks != nil {
			sample.Frames = p.resolveStack(key.UserStackID)
		}

		profile.AddSample(sample)
	}

	return profile, iter.Err()
}

// loadBPF loads the eBPF program
func (p *CPUProfiler) loadBPF() error {
	// In production, this would use go:embed to load compiled BPF
	// For now, create placeholder maps

	const maxStackDepth = 127
	const maxEntries = 65536

	// Create stack trace map
	stackSpec := &ebpf.MapSpec{
		Name:       "cpu_stacks",
		Type:       ebpf.StackTrace,
		KeySize:    4,
		ValueSize:  uint32(maxStackDepth * 8),
		MaxEntries: maxEntries,
	}
	stacks, err := ebpf.NewMap(stackSpec)
	if err != nil {
		return fmt.Errorf("failed to create stacks map: %w", err)
	}
	p.stacks = stacks

	// Create counts map
	countsSpec := &ebpf.MapSpec{
		Name:       "cpu_stack_counts",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(StackKey{})),
		ValueSize:  uint32(unsafe.Sizeof(StackCount{})),
		MaxEntries: maxEntries,
	}
	counts, err := ebpf.NewMap(countsSpec)
	if err != nil {
		return fmt.Errorf("failed to create counts map: %w", err)
	}
	p.counts = counts

	// Create config map
	cfgSpec := &ebpf.MapSpec{
		Name:       "cpu_profiler_cfg",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(cpuProfilerConfig{})),
		MaxEntries: 1,
	}
	cfgMap, err := ebpf.NewMap(cfgSpec)
	if err != nil {
		return fmt.Errorf("failed to create config map: %w", err)
	}
	p.cfgMap = cfgMap

	return nil
}

// configure sets up the profiler configuration
func (p *CPUProfiler) configure() error {
	if p.cfgMap == nil {
		return nil
	}

	cfg := cpuProfilerConfig{
		SampleRateHz:  uint32(p.config.SampleRate),
		CaptureKernel: 1,
		CaptureUser:   1,
	}

	if len(p.config.TargetPIDs) > 0 {
		cfg.TargetPID = p.config.TargetPIDs[0]
	}

	return p.cfgMap.Put(uint32(0), cfg)
}

// attachPerfEvents attaches the BPF program to perf events on each CPU
func (p *CPUProfiler) attachPerfEvents() error {
	numCPUs := runtime.NumCPU()
	p.links = make([]link.Link, 0, numCPUs)

	// Calculate sampling period from rate
	// period = 1 / rate in nanoseconds
	period := time.Second / time.Duration(p.config.SampleRate)

	for cpu := 0; cpu < numCPUs; cpu++ {
		// Create perf event
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: uint64(period.Nanoseconds()),
			Bits:   unix.PerfBitFreq,
		}

		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			// Non-fatal: some CPUs might be offline
			p.log.Warn("failed to open perf event", "cpu", cpu, "error", err)
			continue
		}

		// Note: In production, we'd attach the BPF program here
		// For now, just close the fd since we don't have the actual program
		_ = unix.Close(fd)
	}

	return nil
}

// resolveStack resolves a stack trace from its ID
func (p *CPUProfiler) resolveStack(stackID int32) []ResolvedFrame {
	if p.stacks == nil || stackID < 0 {
		return nil
	}

	// Read stack trace from map
	var addrs [127]uint64
	if err := p.stacks.Lookup(uint32(stackID), &addrs); err != nil {
		return nil
	}

	frames := make([]ResolvedFrame, 0)
	for _, addr := range addrs {
		if addr == 0 {
			break
		}
		frames = append(frames, ResolvedFrame{
			Address:  addr,
			Function: fmt.Sprintf("0x%x", addr), // Placeholder - real resolution in SymbolResolver
		})
	}

	return frames
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

// OffCPUProfiler handles off-CPU profiling
type OffCPUProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects
	coll   *ebpf.Collection
	stacks *ebpf.Map //nolint:unused // used by eBPF
	counts *ebpf.Map
	starts *ebpf.Map //nolint:unused // used by eBPF
	events *ebpf.Map //nolint:unused // used by eBPF

	// Tracepoint links
	schedLink link.Link

	// State
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewOffCPUProfiler creates a new off-CPU profiler
func NewOffCPUProfiler(cfg Config, log *slog.Logger) (*OffCPUProfiler, error) {
	return &OffCPUProfiler{
		config: cfg,
		log:    log.With("profiler", "offcpu"),
		stopCh: make(chan struct{}),
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

	// Load eBPF program (placeholder for now)
	if err := p.loadBPF(); err != nil {
		return fmt.Errorf("failed to load off-CPU profiler BPF: %w", err)
	}

	p.running = true
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

	if p.schedLink != nil {
		_ = p.schedLink.Close()
	}

	if p.coll != nil {
		p.coll.Close()
	}

	p.running = false
	return nil
}

// Collect gathers off-CPU profile data
func (p *OffCPUProfiler) Collect(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	profile := NewProfile(ProfileTypeOffCPU)

	if p.counts == nil {
		return profile, nil
	}

	var key OffCPUKey
	var value OffCPUValue

	iter := p.counts.Iterate()
	for iter.Next(&key, &value) {
		sample := StackSample{
			PID:         key.PID,
			TGID:        key.TGID,
			Comm:        nullTermString(key.Comm[:]),
			Value:       int64(value.TotalTimeNs),
			Count:       int64(value.Count),
			BlockReason: BlockReason(key.BlockReason),
		}

		profile.AddSample(sample)
	}

	return profile, iter.Err()
}

// loadBPF loads the eBPF program
func (p *OffCPUProfiler) loadBPF() error {
	// Placeholder - in production this would load compiled BPF
	return nil
}

// WallProfiler handles wall clock profiling
type WallProfiler struct {
	config  Config
	log     *slog.Logger
	running bool
	mu      sync.RWMutex
}

// NewWallProfiler creates a new wall clock profiler
func NewWallProfiler(cfg Config, log *slog.Logger) (*WallProfiler, error) {
	return &WallProfiler{
		config: cfg,
		log:    log.With("profiler", "wall"),
	}, nil
}

// Start starts wall clock profiling
func (p *WallProfiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("starting wall clock profiler")
	p.running = true
	return nil
}

// Stop stops wall clock profiling
func (p *WallProfiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("stopping wall clock profiler")
	p.running = false
	return nil
}

// Collect gathers wall clock profile data
func (p *WallProfiler) Collect(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	return NewProfile(ProfileTypeWall), nil
}

// MemoryProfiler handles memory allocation profiling
type MemoryProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects
	stacks    *ebpf.Map //nolint:unused // used by eBPF
	pending   *ebpf.Map //nolint:unused // used by eBPF
	liveAlloc *ebpf.Map
	stats     *ebpf.Map //nolint:unused // used by eBPF
	events    *ebpf.Map //nolint:unused // used by eBPF

	// State
	mu      sync.RWMutex
	running bool
}

// NewMemoryProfiler creates a new memory profiler
func NewMemoryProfiler(cfg Config, log *slog.Logger) (*MemoryProfiler, error) {
	return &MemoryProfiler{
		config: cfg,
		log:    log.With("profiler", "memory"),
	}, nil
}

// Start starts memory profiling
func (p *MemoryProfiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("starting memory profiler",
		"min_alloc_size", p.config.MinAllocSize)
	p.running = true
	return nil
}

// Stop stops memory profiling
func (p *MemoryProfiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("stopping memory profiler")
	p.running = false
	return nil
}

// CollectHeap gathers heap profile data
func (p *MemoryProfiler) CollectHeap(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	profile := NewProfile(ProfileTypeHeap)

	// Read live allocations
	if p.liveAlloc == nil {
		return profile, nil
	}

	// In production, iterate live allocations map
	return profile, nil
}

// CollectAllocs gathers allocation count profile
func (p *MemoryProfiler) CollectAllocs(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	return NewProfile(ProfileTypeAllocCount), nil
}

// MutexProfiler handles mutex contention profiling
type MutexProfiler struct {
	config Config
	log    *slog.Logger

	// eBPF objects
	stacks  *ebpf.Map //nolint:unused // used by eBPF
	states  *ebpf.Map //nolint:unused // used by eBPF
	pending *ebpf.Map //nolint:unused // used by eBPF
	stats   *ebpf.Map
	events  *ebpf.Map //nolint:unused // used by eBPF

	// State
	mu      sync.RWMutex
	running bool
}

// NewMutexProfiler creates a new mutex profiler
func NewMutexProfiler(cfg Config, log *slog.Logger) (*MutexProfiler, error) {
	return &MutexProfiler{
		config: cfg,
		log:    log.With("profiler", "mutex"),
	}, nil
}

// Start starts mutex profiling
func (p *MutexProfiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("starting mutex profiler",
		"threshold_ns", p.config.ContentionThresholdNs)
	p.running = true
	return nil
}

// Stop stops mutex profiling
func (p *MutexProfiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("stopping mutex profiler")
	p.running = false
	return nil
}

// Collect gathers mutex contention profile data
func (p *MutexProfiler) Collect(ctx context.Context) (*Profile, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return nil, nil
	}

	profile := NewProfile(ProfileTypeMutex)

	if p.stats == nil {
		return profile, nil
	}

	var key MutexKey
	var value MutexStats

	iter := p.stats.Iterate()
	for iter.Next(&key, &value) {
		sample := StackSample{
			Value: int64(value.TotalWaitNs),
			Count: int64(value.ContentionCount),
		}
		profile.AddSample(sample)
	}

	return profile, iter.Err()
}
