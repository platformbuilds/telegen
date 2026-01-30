// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package framework provides ML framework profiling integration.
// Task: ML-015 - PyTorch/TensorFlow Profiler Integration
package framework

import (
	"context"
	"sync"
	"time"
)

// Profiler provides ML framework profiling capabilities
type Profiler struct {
	mu     sync.RWMutex
	config ProfilerConfig

	// Active profiling sessions
	sessions map[string]*ProfileSession

	// Collected metrics
	metrics *FrameworkMetrics

	// Event channel
	eventCh chan ProfileEvent

	// Done channel
	done chan struct{}
}

// ProfilerConfig holds profiler configuration
type ProfilerConfig struct {
	// Enable PyTorch profiling
	EnablePyTorch bool

	// Enable TensorFlow profiling
	EnableTensorFlow bool

	// Enable JAX profiling
	EnableJAX bool

	// Enable ONNX Runtime profiling
	EnableONNX bool

	// Profiling detail level
	DetailLevel DetailLevel

	// Sample rate for operator profiling (0-1)
	SampleRate float64

	// Enable memory profiling
	EnableMemoryProfiling bool

	// Enable CUDA profiling (requires GPU)
	EnableCUDAProfiling bool

	// Event buffer size
	EventBufferSize int
}

// DetailLevel represents the profiling detail level
type DetailLevel int

const (
	DetailLevelMinimal  DetailLevel = 0 // Basic timing only
	DetailLevelStandard DetailLevel = 1 // Timing + memory
	DetailLevelDetailed DetailLevel = 2 // Full operator tracing
)

// FrameworkType represents the ML framework
type FrameworkType int

const (
	FrameworkUnknown    FrameworkType = 0
	FrameworkPyTorch    FrameworkType = 1
	FrameworkTensorFlow FrameworkType = 2
	FrameworkJAX        FrameworkType = 3
	FrameworkONNX       FrameworkType = 4
)

// ProfileSession represents an active profiling session
type ProfileSession struct {
	// Session ID
	ID string

	// Process ID
	PID uint32

	// Framework being profiled
	Framework FrameworkType

	// Start time
	StartTime time.Time

	// End time (if completed)
	EndTime time.Time

	// Session state
	State SessionState

	// Collected events
	Events []ProfileEvent

	// Aggregated metrics
	Metrics *SessionMetrics
}

// SessionState represents the session state
type SessionState int

const (
	SessionStateActive    SessionState = 0
	SessionStateCompleted SessionState = 1
	SessionStateError     SessionState = 2
)

// ProfileEvent represents a profiling event
type ProfileEvent struct {
	// Timestamp
	Timestamp time.Time

	// Event type
	Type EventType

	// Framework
	Framework FrameworkType

	// Operator/kernel name
	Name string

	// Category (e.g., "forward", "backward", "optimizer")
	Category string

	// Duration in nanoseconds
	DurationNs uint64

	// CUDA time in nanoseconds (if applicable)
	CUDATimeNs uint64

	// Memory metrics
	CPUMemoryBytes  int64
	CUDAMemoryBytes int64

	// Input shapes (serialized)
	InputShapes string

	// Thread ID
	ThreadID uint32

	// Stack trace (if enabled)
	StackTrace string

	// Custom attributes
	Attributes map[string]string
}

// EventType represents the type of profiling event
type EventType int

const (
	EventTypeOperator    EventType = 0
	EventTypeKernel      EventType = 1
	EventTypeMemory      EventType = 2
	EventTypeDataLoading EventType = 3
	EventTypeOptimizer   EventType = 4
	EventTypeCheckpoint  EventType = 5
	EventTypeDistributed EventType = 6
	EventTypeCustom      EventType = 7
)

// SessionMetrics holds aggregated session metrics
type SessionMetrics struct {
	// Total duration
	TotalDurationNs uint64

	// Operator statistics
	OperatorStats map[string]*OperatorStats

	// Memory statistics
	PeakCPUMemory  int64
	PeakCUDAMemory int64

	// Kernel statistics
	TotalKernels   uint64
	TotalKernelNs  uint64
	KernelOverhead float64

	// Data loading statistics
	DataLoadingNs  uint64
	DataLoadingPct float64

	// Bottleneck analysis
	Bottlenecks []Bottleneck
}

// OperatorStats holds per-operator statistics
type OperatorStats struct {
	// Operator name
	Name string

	// Call count
	Count uint64

	// Total time
	TotalNs uint64

	// Min/max/avg time
	MinNs uint64
	MaxNs uint64
	AvgNs float64

	// CUDA time
	CUDATotalNs uint64
	CUDAAvgNs   float64

	// Memory impact
	MemoryDeltaBytes int64

	// Percentage of total time
	TimePct float64
}

// Bottleneck represents a detected performance bottleneck
type Bottleneck struct {
	// Bottleneck type
	Type BottleneckType

	// Severity (0-100)
	Severity int

	// Description
	Description string

	// Affected operators
	Operators []string

	// Recommendation
	Recommendation string
}

// BottleneckType represents the type of bottleneck
type BottleneckType int

const (
	BottleneckCPUBound        BottleneckType = 0
	BottleneckGPUBound        BottleneckType = 1
	BottleneckMemoryBound     BottleneckType = 2
	BottleneckDataLoading     BottleneckType = 3
	BottleneckSynchronization BottleneckType = 4
	BottleneckCommunication   BottleneckType = 5
)

// FrameworkMetrics holds aggregated framework metrics
type FrameworkMetrics struct {
	// Per-framework metrics
	PyTorch    *FrameworkStats
	TensorFlow *FrameworkStats
	JAX        *FrameworkStats
	ONNX       *FrameworkStats
}

// FrameworkStats holds per-framework statistics
type FrameworkStats struct {
	// Framework type
	Framework FrameworkType

	// Active sessions
	ActiveSessions int

	// Completed sessions
	CompletedSessions int

	// Total profiled time
	TotalProfiledNs uint64

	// Total operators profiled
	TotalOperators uint64

	// Top operators by time
	TopOperators []*OperatorStats
}

// NewProfiler creates a new ML framework profiler
func NewProfiler(config ProfilerConfig) *Profiler {
	if config.EventBufferSize == 0 {
		config.EventBufferSize = 10000
	}
	if config.SampleRate == 0 {
		config.SampleRate = 1.0
	}

	return &Profiler{
		config:   config,
		sessions: make(map[string]*ProfileSession),
		metrics: &FrameworkMetrics{
			PyTorch:    &FrameworkStats{Framework: FrameworkPyTorch},
			TensorFlow: &FrameworkStats{Framework: FrameworkTensorFlow},
			JAX:        &FrameworkStats{Framework: FrameworkJAX},
			ONNX:       &FrameworkStats{Framework: FrameworkONNX},
		},
		eventCh: make(chan ProfileEvent, config.EventBufferSize),
		done:    make(chan struct{}),
	}
}

// Start begins profiling
func (p *Profiler) Start(ctx context.Context) error {
	go p.processEvents(ctx)
	return nil
}

// Stop stops profiling
func (p *Profiler) Stop() {
	close(p.done)
}

// StartSession starts a new profiling session
func (p *Profiler) StartSession(id string, framework FrameworkType, pid uint32) *ProfileSession {
	p.mu.Lock()
	defer p.mu.Unlock()

	session := &ProfileSession{
		ID:        id,
		PID:       pid,
		Framework: framework,
		StartTime: time.Now(),
		State:     SessionStateActive,
		Events:    make([]ProfileEvent, 0),
		Metrics:   &SessionMetrics{OperatorStats: make(map[string]*OperatorStats)},
	}

	p.sessions[id] = session

	// Update framework stats
	stats := p.getFrameworkStats(framework)
	if stats != nil {
		stats.ActiveSessions++
	}

	return session
}

// EndSession ends a profiling session
func (p *Profiler) EndSession(id string) *ProfileSession {
	p.mu.Lock()
	defer p.mu.Unlock()

	session, ok := p.sessions[id]
	if !ok {
		return nil
	}

	session.EndTime = time.Now()
	session.State = SessionStateCompleted

	// Calculate final metrics
	p.calculateSessionMetrics(session)

	// Update framework stats
	stats := p.getFrameworkStats(session.Framework)
	if stats != nil {
		stats.ActiveSessions--
		stats.CompletedSessions++
		stats.TotalProfiledNs += session.Metrics.TotalDurationNs
	}

	return session
}

// RecordEvent records a profiling event
func (p *Profiler) RecordEvent(sessionID string, event ProfileEvent) {
	select {
	case p.eventCh <- event:
	default:
		// Channel full, drop event
	}
}

// processEvents processes incoming profiling events
func (p *Profiler) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case event := <-p.eventCh:
			p.handleEvent(event)
		}
	}
}

// handleEvent handles a single profiling event
func (p *Profiler) handleEvent(event ProfileEvent) {
	// Update framework stats
	stats := p.getFrameworkStats(event.Framework)
	if stats != nil {
		stats.TotalOperators++
	}
}

// getFrameworkStats returns stats for a framework
func (p *Profiler) getFrameworkStats(framework FrameworkType) *FrameworkStats {
	switch framework {
	case FrameworkPyTorch:
		return p.metrics.PyTorch
	case FrameworkTensorFlow:
		return p.metrics.TensorFlow
	case FrameworkJAX:
		return p.metrics.JAX
	case FrameworkONNX:
		return p.metrics.ONNX
	default:
		return nil
	}
}

// calculateSessionMetrics calculates final metrics for a session
func (p *Profiler) calculateSessionMetrics(session *ProfileSession) {
	if len(session.Events) == 0 {
		return
	}

	var totalNs uint64
	var totalKernelNs uint64
	var dataLoadingNs uint64
	var peakCPU, peakCUDA int64

	for _, event := range session.Events {
		totalNs += event.DurationNs

		// Update operator stats
		stats, ok := session.Metrics.OperatorStats[event.Name]
		if !ok {
			stats = &OperatorStats{
				Name:  event.Name,
				MinNs: ^uint64(0),
			}
			session.Metrics.OperatorStats[event.Name] = stats
		}

		stats.Count++
		stats.TotalNs += event.DurationNs
		stats.CUDATotalNs += event.CUDATimeNs

		if event.DurationNs < stats.MinNs {
			stats.MinNs = event.DurationNs
		}
		if event.DurationNs > stats.MaxNs {
			stats.MaxNs = event.DurationNs
		}

		// Track kernel time
		if event.Type == EventTypeKernel {
			totalKernelNs += event.DurationNs
			session.Metrics.TotalKernels++
		}

		// Track data loading
		if event.Type == EventTypeDataLoading {
			dataLoadingNs += event.DurationNs
		}

		// Track memory peaks
		if event.CPUMemoryBytes > peakCPU {
			peakCPU = event.CPUMemoryBytes
		}
		if event.CUDAMemoryBytes > peakCUDA {
			peakCUDA = event.CUDAMemoryBytes
		}
	}

	session.Metrics.TotalDurationNs = totalNs
	session.Metrics.TotalKernelNs = totalKernelNs
	session.Metrics.DataLoadingNs = dataLoadingNs
	session.Metrics.PeakCPUMemory = peakCPU
	session.Metrics.PeakCUDAMemory = peakCUDA

	if totalNs > 0 {
		session.Metrics.DataLoadingPct = float64(dataLoadingNs) / float64(totalNs) * 100
		session.Metrics.KernelOverhead = float64(totalNs-totalKernelNs) / float64(totalNs) * 100
	}

	// Calculate averages and percentages
	for _, stats := range session.Metrics.OperatorStats {
		if stats.Count > 0 {
			stats.AvgNs = float64(stats.TotalNs) / float64(stats.Count)
			stats.CUDAAvgNs = float64(stats.CUDATotalNs) / float64(stats.Count)
		}
		if totalNs > 0 {
			stats.TimePct = float64(stats.TotalNs) / float64(totalNs) * 100
		}
	}

	// Detect bottlenecks
	session.Metrics.Bottlenecks = p.detectBottlenecks(session.Metrics)
}

// detectBottlenecks analyzes metrics to detect performance bottlenecks
func (p *Profiler) detectBottlenecks(metrics *SessionMetrics) []Bottleneck {
	var bottlenecks []Bottleneck

	// Check for data loading bottleneck
	if metrics.DataLoadingPct > 20 {
		bottlenecks = append(bottlenecks, Bottleneck{
			Type:           BottleneckDataLoading,
			Severity:       int(metrics.DataLoadingPct),
			Description:    "Data loading consuming significant time",
			Recommendation: "Consider using more workers, prefetching, or optimizing data pipeline",
		})
	}

	// Check for kernel overhead
	if metrics.KernelOverhead > 30 {
		bottlenecks = append(bottlenecks, Bottleneck{
			Type:           BottleneckCPUBound,
			Severity:       int(metrics.KernelOverhead),
			Description:    "High CPU overhead between GPU kernels",
			Recommendation: "Consider using CUDA graphs, larger batch sizes, or fused operations",
		})
	}

	return bottlenecks
}

// GetSession returns a profiling session by ID
func (p *Profiler) GetSession(id string) *ProfileSession {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if session, ok := p.sessions[id]; ok {
		return session
	}
	return nil
}

// GetMetrics returns aggregated framework metrics
func (p *Profiler) GetMetrics() *FrameworkMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.metrics
}
