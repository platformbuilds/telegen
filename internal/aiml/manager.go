// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package aiml provides AI/ML observability for Telegen.
// Task: ML-016 - AI/ML Metrics Manager
package aiml

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/aiml/framework"
	"github.com/platformbuilds/telegen/internal/aiml/llm"
	"github.com/platformbuilds/telegen/internal/aiml/nvidia"
)

// Manager orchestrates AI/ML metrics collection
type Manager struct {
	mu     sync.RWMutex
	config ManagerConfig

	// Component collectors
	gpuCollector   *nvidia.Collector
	tokenCollector *llm.TokenCollector
	profiler       *framework.Profiler

	// Aggregated metrics
	metrics *AIMLMetrics

	// Event channels
	eventCh chan Event

	// State
	running bool
	done    chan struct{}
}

// ManagerConfig holds manager configuration
type ManagerConfig struct {
	// Enable NVIDIA GPU collection
	EnableGPU bool

	// Enable LLM token collection
	EnableLLM bool

	// Enable ML framework profiling
	EnableFramework bool

	// Collection interval
	CollectionInterval time.Duration

	// GPU collector config
	GPUConfig nvidia.CollectorConfig

	// Token collector config
	TokenConfig llm.TokenCollectorConfig

	// Framework profiler config
	FrameworkConfig framework.ProfilerConfig

	// Enable cost tracking
	EnableCostTracking bool

	// Event buffer size
	EventBufferSize int
}

// AIMLMetrics holds aggregated AI/ML metrics
type AIMLMetrics struct {
	// Timestamp
	Timestamp time.Time

	// GPU metrics (per device)
	GPUs map[int]*nvidia.GPUMetrics

	// LLM token metrics (per model)
	LLM map[string]*llm.TokenMetrics

	// Framework metrics
	Framework *framework.FrameworkMetrics

	// Cost summary
	Cost *CostSummary

	// Health status
	Health *HealthStatus
}

// CostSummary holds cost summary across all AI/ML usage
type CostSummary struct {
	// Time period
	StartTime time.Time
	EndTime   time.Time

	// GPU costs (based on cloud pricing estimates)
	GPUCostUSD float64

	// LLM API costs
	LLMCostUSD float64

	// Total cost
	TotalCostUSD float64

	// Per-model breakdown
	PerModelCost map[string]float64

	// Per-GPU breakdown
	PerGPUCost map[int]float64
}

// HealthStatus represents overall AI/ML infrastructure health
type HealthStatus struct {
	// Overall status
	Status HealthLevel

	// Component status
	GPUHealth       HealthLevel
	LLMHealth       HealthLevel
	FrameworkHealth HealthLevel

	// Issues detected
	Issues []HealthIssue
}

// HealthLevel represents health status level
type HealthLevel int

const (
	HealthLevelHealthy   HealthLevel = 0
	HealthLevelDegraded  HealthLevel = 1
	HealthLevelUnhealthy HealthLevel = 2
	HealthLevelUnknown   HealthLevel = 3
)

// HealthIssue represents a detected health issue
type HealthIssue struct {
	// Component affected
	Component string

	// Issue severity
	Severity HealthLevel

	// Description
	Description string

	// Timestamp
	Timestamp time.Time

	// Recommended action
	Recommendation string
}

// Event represents an AI/ML event
type Event struct {
	// Event type
	Type EventType

	// Timestamp
	Timestamp time.Time

	// Source component
	Source string

	// Event data
	Data interface{}
}

// EventType represents the type of AI/ML event
type EventType int

const (
	EventTypeGPUMetrics     EventType = 0
	EventTypeLLMRequest     EventType = 1
	EventTypeFrameworkEvent EventType = 2
	EventTypeHealthChange   EventType = 3
	EventTypeCostAlert      EventType = 4
)

// DefaultConfig returns default manager configuration
func DefaultConfig() ManagerConfig {
	return ManagerConfig{
		EnableGPU:          true,
		EnableLLM:          true,
		EnableFramework:    false, // Opt-in due to overhead
		CollectionInterval: 10 * time.Second,
		GPUConfig: nvidia.CollectorConfig{
			CollectInterval:      10 * time.Second,
			CollectProcessInfo:   true,
			CollectPCIeMetrics:   true,
			CollectNVLinkMetrics: true,
			CollectMIGMetrics:    true,
			CollectECCMetrics:    true,
			DeviceIndex:          -1,
		},
		TokenConfig: llm.TokenCollectorConfig{
			AggregationInterval:  10 * time.Second,
			TrackRequests:        true,
			MaxTrackedRequests:   10000,
			EnableCostEstimation: true,
		},
		FrameworkConfig: framework.ProfilerConfig{
			EnablePyTorch:    true,
			EnableTensorFlow: true,
			DetailLevel:      framework.DetailLevelStandard,
			SampleRate:       0.1,
		},
		EnableCostTracking: true,
		EventBufferSize:    1000,
	}
}

// NewManager creates a new AI/ML metrics manager
func NewManager(config ManagerConfig) (*Manager, error) {
	m := &Manager{
		config:  config,
		metrics: &AIMLMetrics{},
		eventCh: make(chan Event, config.EventBufferSize),
		done:    make(chan struct{}),
	}

	// Initialize GPU collector if enabled
	if config.EnableGPU {
		m.gpuCollector = nvidia.NewCollector(config.GPUConfig)
	}

	// Initialize token collector if enabled
	if config.EnableLLM {
		m.tokenCollector = llm.NewTokenCollector(config.TokenConfig)
	}

	// Initialize framework profiler if enabled
	if config.EnableFramework {
		m.profiler = framework.NewProfiler(config.FrameworkConfig)
	}

	return m, nil
}

// Start begins AI/ML metrics collection
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.mu.Unlock()

	// Start GPU collector
	if m.gpuCollector != nil {
		if err := m.gpuCollector.Start(ctx); err != nil {
			slog.Warn("failed to start GPU collector", "error", err)
		}
	}

	// Start token collector
	if m.tokenCollector != nil {
		if err := m.tokenCollector.Start(ctx); err != nil {
			slog.Warn("failed to start token collector", "error", err)
		}
	}

	// Start framework profiler
	if m.profiler != nil {
		if err := m.profiler.Start(ctx); err != nil {
			slog.Warn("failed to start profiler", "error", err)
		}
	}

	// Start collection loop
	go m.collectionLoop(ctx)

	// Start event processor
	go m.processEvents(ctx)

	return nil
}

// Stop stops AI/ML metrics collection
func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	m.mu.Unlock()

	close(m.done)

	// Stop components
	if m.gpuCollector != nil {
		m.gpuCollector.Stop()
	}
	if m.tokenCollector != nil {
		m.tokenCollector.Stop()
	}
	if m.profiler != nil {
		m.profiler.Stop()
	}

	return nil
}

// collectionLoop runs the periodic collection loop
func (m *Manager) collectionLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			m.collect()
		}
	}
}

// collect collects metrics from all components
func (m *Manager) collect() {
	m.mu.Lock()
	defer m.mu.Unlock()

	metrics := &AIMLMetrics{
		Timestamp: time.Now(),
		GPUs:      make(map[int]*nvidia.GPUMetrics),
		LLM:       make(map[string]*llm.TokenMetrics),
	}

	// Collect GPU metrics
	if m.gpuCollector != nil {
		gpuMetrics := m.gpuCollector.GetMetrics()
		for i, gm := range gpuMetrics {
			metrics.GPUs[i] = gm
		}
	}

	// Collect LLM metrics
	if m.tokenCollector != nil {
		llmMetrics := m.tokenCollector.GetMetrics()
		for k, v := range llmMetrics {
			metrics.LLM[k] = v
		}
	}

	// Collect framework metrics
	if m.profiler != nil {
		metrics.Framework = m.profiler.GetMetrics()
	}

	// Calculate health status
	metrics.Health = m.calculateHealth(metrics)

	// Calculate costs if enabled
	if m.config.EnableCostTracking {
		metrics.Cost = m.calculateCosts(metrics)
	}

	m.metrics = metrics
}

// calculateHealth calculates overall health status
func (m *Manager) calculateHealth(metrics *AIMLMetrics) *HealthStatus {
	health := &HealthStatus{
		Status:          HealthLevelHealthy,
		GPUHealth:       HealthLevelUnknown,
		LLMHealth:       HealthLevelUnknown,
		FrameworkHealth: HealthLevelUnknown,
		Issues:          make([]HealthIssue, 0),
	}

	// Check GPU health
	if len(metrics.GPUs) > 0 {
		health.GPUHealth = HealthLevelHealthy

		for idx, gpu := range metrics.GPUs {
			// Check for high temperature
			if gpu.Power.Temperature > 85 {
				health.GPUHealth = HealthLevelDegraded
				health.Issues = append(health.Issues, HealthIssue{
					Component:      "GPU",
					Severity:       HealthLevelDegraded,
					Description:    "GPU temperature above 85°C",
					Timestamp:      time.Now(),
					Recommendation: "Check cooling and reduce workload",
				})
			}

			// Check for memory pressure
			if gpu.Memory.Utilization > 95 {
				health.GPUHealth = HealthLevelDegraded
				health.Issues = append(health.Issues, HealthIssue{
					Component:      "GPU",
					Severity:       HealthLevelDegraded,
					Description:    "GPU memory above 95% on device " + string(rune('0'+idx)),
					Timestamp:      time.Now(),
					Recommendation: "Reduce batch size or use gradient checkpointing",
				})
			}

			// Check for ECC errors
			if nvidia.HasUncorrectableErrors(&gpu.ECC) {
				health.GPUHealth = HealthLevelUnhealthy
				health.Issues = append(health.Issues, HealthIssue{
					Component:      "GPU",
					Severity:       HealthLevelUnhealthy,
					Description:    "Uncorrectable ECC errors detected",
					Timestamp:      time.Now(),
					Recommendation: "Schedule GPU replacement",
				})
			}
		}
	}

	// Check LLM health
	if len(metrics.LLM) > 0 {
		health.LLMHealth = HealthLevelHealthy

		for model, llmMetrics := range metrics.LLM {
			// Check error rate
			if llmMetrics.RequestCount > 0 {
				errorRate := float64(llmMetrics.ErrorCount) / float64(llmMetrics.RequestCount)
				if errorRate > 0.1 {
					health.LLMHealth = HealthLevelDegraded
					health.Issues = append(health.Issues, HealthIssue{
						Component:      "LLM",
						Severity:       HealthLevelDegraded,
						Description:    "High error rate for model " + model,
						Timestamp:      time.Now(),
						Recommendation: "Check API quotas and rate limits",
					})
				}
			}

			// Check throttling
			if llmMetrics.ThrottledCount > 0 {
				health.Issues = append(health.Issues, HealthIssue{
					Component:      "LLM",
					Severity:       HealthLevelDegraded,
					Description:    "Rate limiting detected for model " + model,
					Timestamp:      time.Now(),
					Recommendation: "Increase rate limits or implement request queuing",
				})
			}
		}
	}

	// Determine overall status
	if health.GPUHealth == HealthLevelUnhealthy || health.LLMHealth == HealthLevelUnhealthy {
		health.Status = HealthLevelUnhealthy
	} else if health.GPUHealth == HealthLevelDegraded || health.LLMHealth == HealthLevelDegraded {
		health.Status = HealthLevelDegraded
	}

	return health
}

// calculateCosts calculates cost summary
func (m *Manager) calculateCosts(metrics *AIMLMetrics) *CostSummary {
	cost := &CostSummary{
		StartTime:    metrics.Timestamp.Add(-m.config.CollectionInterval),
		EndTime:      metrics.Timestamp,
		PerModelCost: make(map[string]float64),
		PerGPUCost:   make(map[int]float64),
	}

	// Aggregate LLM costs
	for model, llmMetrics := range metrics.LLM {
		cost.LLMCostUSD += llmMetrics.EstimatedCostUSD
		cost.PerModelCost[model] = llmMetrics.EstimatedCostUSD
	}

	// Estimate GPU costs (simplified - based on hourly rates)
	// In production, this would use actual cloud pricing APIs
	for idx := range metrics.GPUs {
		// Assume $2/hr for GPU (simplified estimate)
		hourlyRate := 2.0
		intervalHours := m.config.CollectionInterval.Hours()
		gpuCost := hourlyRate * intervalHours
		cost.GPUCostUSD += gpuCost
		cost.PerGPUCost[idx] = gpuCost
	}

	cost.TotalCostUSD = cost.GPUCostUSD + cost.LLMCostUSD

	return cost
}

// processEvents processes incoming events
func (m *Manager) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case event := <-m.eventCh:
			m.handleEvent(event)
		}
	}
}

// handleEvent handles a single event
func (m *Manager) handleEvent(event Event) {
	// Process event based on type
	switch event.Type {
	case EventTypeGPUMetrics:
		// Handle GPU metrics event
	case EventTypeLLMRequest:
		// Handle LLM request event
	case EventTypeFrameworkEvent:
		// Handle framework event
	case EventTypeHealthChange:
		// Handle health change
	case EventTypeCostAlert:
		// Handle cost alert
	}
}

// GetMetrics returns current AI/ML metrics
func (m *Manager) GetMetrics() *AIMLMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics
}

// GetGPUCollector returns the GPU collector
func (m *Manager) GetGPUCollector() *nvidia.Collector {
	return m.gpuCollector
}

// GetTokenCollector returns the token collector
func (m *Manager) GetTokenCollector() *llm.TokenCollector {
	return m.tokenCollector
}

// GetProfiler returns the framework profiler
func (m *Manager) GetProfiler() *framework.Profiler {
	return m.profiler
}

// RecordLLMEvent records an LLM event
func (m *Manager) RecordLLMEvent(event llm.TokenEvent) {
	if m.tokenCollector != nil {
		m.tokenCollector.RecordEvent(event)
	}
}
