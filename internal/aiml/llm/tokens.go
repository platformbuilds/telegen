// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package llm provides LLM token metrics collection for AI observability.
// Task: ML-010 - LLM Token Metrics Collector
package llm

import (
	"context"
	"sync"
	"time"
)

// TokenCollector collects LLM token usage metrics
type TokenCollector struct {
	mu     sync.RWMutex
	config TokenCollectorConfig

	// Aggregated metrics by model/provider
	metrics map[string]*TokenMetrics

	// Request tracking
	requests map[string]*RequestInfo

	// Channel for incoming token events
	eventCh chan TokenEvent

	// Done channel
	done chan struct{}
}

// TokenCollectorConfig holds configuration for token collection
type TokenCollectorConfig struct {
	// Collection interval for aggregation
	AggregationInterval time.Duration

	// Enable per-request tracking
	TrackRequests bool

	// Maximum requests to track
	MaxTrackedRequests int

	// Enable cost estimation
	EnableCostEstimation bool

	// Custom pricing overrides
	PricingOverrides map[string]TokenPricing
}

// TokenMetrics holds aggregated token metrics for a model
type TokenMetrics struct {
	// Model identifier (e.g., "gpt-4", "claude-3-opus")
	Model string

	// Provider (e.g., "openai", "anthropic", "azure")
	Provider string

	// Token counts
	PromptTokens     uint64
	CompletionTokens uint64
	TotalTokens      uint64

	// Request counts
	RequestCount   uint64
	SuccessCount   uint64
	ErrorCount     uint64
	ThrottledCount uint64

	// Latency statistics (in milliseconds)
	TotalLatencyMs uint64
	MinLatencyMs   uint64
	MaxLatencyMs   uint64
	AvgLatencyMs   float64

	// Time to first token (TTFT) statistics
	TotalTTFTMs uint64
	MinTTFTMs   uint64
	MaxTTFTMs   uint64
	AvgTTFTMs   float64

	// Tokens per second
	TokensPerSecond float64

	// Cost estimation (if enabled)
	EstimatedCostUSD float64

	// Last updated timestamp
	LastUpdated time.Time
}

// RequestInfo holds information about a specific LLM request
type RequestInfo struct {
	// Unique request ID
	RequestID string

	// Model and provider
	Model    string
	Provider string

	// Timestamps
	StartTime      time.Time
	EndTime        time.Time
	FirstTokenTime time.Time

	// Token counts
	PromptTokens     uint32
	CompletionTokens uint32

	// Request metadata
	Temperature      float32
	MaxTokens        uint32
	TopP             float32
	FrequencyPenalty float32
	PresencePenalty  float32

	// Response status
	Status       RequestStatus
	ErrorMessage string
	FinishReason string

	// Streaming info
	IsStreaming bool
	ChunkCount  uint32
}

// RequestStatus represents the status of an LLM request
type RequestStatus int

const (
	RequestStatusPending   RequestStatus = 0
	RequestStatusCompleted RequestStatus = 1
	RequestStatusError     RequestStatus = 2
	RequestStatusThrottled RequestStatus = 3
	RequestStatusCanceled  RequestStatus = 4
)

// TokenEvent represents a token usage event
type TokenEvent struct {
	// Event type
	Type TokenEventType

	// Timestamp
	Timestamp time.Time

	// Request information
	RequestID string
	Model     string
	Provider  string

	// Token counts
	PromptTokens     uint32
	CompletionTokens uint32

	// Timing information
	LatencyMs uint32
	TTFTMs    uint32

	// Status
	Status       RequestStatus
	ErrorMessage string
	FinishReason string

	// Metadata
	IsStreaming bool
	ChunkIndex  uint32
}

// TokenEventType represents the type of token event
type TokenEventType int

const (
	TokenEventRequestStart    TokenEventType = 0
	TokenEventFirstToken      TokenEventType = 1
	TokenEventStreamChunk     TokenEventType = 2
	TokenEventRequestComplete TokenEventType = 3
	TokenEventRequestError    TokenEventType = 4
)

// NewTokenCollector creates a new token collector
func NewTokenCollector(config TokenCollectorConfig) *TokenCollector {
	if config.AggregationInterval == 0 {
		config.AggregationInterval = 10 * time.Second
	}
	if config.MaxTrackedRequests == 0 {
		config.MaxTrackedRequests = 10000
	}

	return &TokenCollector{
		config:   config,
		metrics:  make(map[string]*TokenMetrics),
		requests: make(map[string]*RequestInfo),
		eventCh:  make(chan TokenEvent, 1000),
		done:     make(chan struct{}),
	}
}

// Start begins token collection
func (tc *TokenCollector) Start(ctx context.Context) error {
	go tc.processEvents(ctx)
	return nil
}

// Stop stops token collection
func (tc *TokenCollector) Stop() {
	close(tc.done)
}

// RecordEvent records a token event
func (tc *TokenCollector) RecordEvent(event TokenEvent) {
	select {
	case tc.eventCh <- event:
	default:
		// Channel full, drop event
	}
}

// processEvents processes incoming token events
func (tc *TokenCollector) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tc.done:
			return
		case event := <-tc.eventCh:
			tc.handleEvent(event)
		}
	}
}

// handleEvent handles a single token event
func (tc *TokenCollector) handleEvent(event TokenEvent) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Get or create metrics for this model/provider
	key := event.Provider + "/" + event.Model
	m, ok := tc.metrics[key]
	if !ok {
		m = &TokenMetrics{
			Model:        event.Model,
			Provider:     event.Provider,
			MinLatencyMs: ^uint64(0), // Max uint64
			MinTTFTMs:    ^uint64(0),
		}
		tc.metrics[key] = m
	}

	switch event.Type {
	case TokenEventRequestStart:
		tc.handleRequestStart(event, m)
	case TokenEventFirstToken:
		tc.handleFirstToken(event, m)
	case TokenEventStreamChunk:
		tc.handleStreamChunk(event, m)
	case TokenEventRequestComplete:
		tc.handleRequestComplete(event, m)
	case TokenEventRequestError:
		tc.handleRequestError(event, m)
	}

	m.LastUpdated = event.Timestamp
}

func (tc *TokenCollector) handleRequestStart(event TokenEvent, m *TokenMetrics) {
	m.RequestCount++

	if tc.config.TrackRequests && len(tc.requests) < tc.config.MaxTrackedRequests {
		tc.requests[event.RequestID] = &RequestInfo{
			RequestID:   event.RequestID,
			Model:       event.Model,
			Provider:    event.Provider,
			StartTime:   event.Timestamp,
			IsStreaming: event.IsStreaming,
			Status:      RequestStatusPending,
		}
	}
}

func (tc *TokenCollector) handleFirstToken(event TokenEvent, m *TokenMetrics) {
	ttft := uint64(event.TTFTMs)
	m.TotalTTFTMs += ttft
	if ttft < m.MinTTFTMs {
		m.MinTTFTMs = ttft
	}
	if ttft > m.MaxTTFTMs {
		m.MaxTTFTMs = ttft
	}

	if req, ok := tc.requests[event.RequestID]; ok {
		req.FirstTokenTime = event.Timestamp
	}
}

func (tc *TokenCollector) handleStreamChunk(event TokenEvent, m *TokenMetrics) {
	if req, ok := tc.requests[event.RequestID]; ok {
		req.ChunkCount++
	}
}

func (tc *TokenCollector) handleRequestComplete(event TokenEvent, m *TokenMetrics) {
	m.SuccessCount++
	m.PromptTokens += uint64(event.PromptTokens)
	m.CompletionTokens += uint64(event.CompletionTokens)
	m.TotalTokens += uint64(event.PromptTokens) + uint64(event.CompletionTokens)

	latency := uint64(event.LatencyMs)
	m.TotalLatencyMs += latency
	if latency < m.MinLatencyMs {
		m.MinLatencyMs = latency
	}
	if latency > m.MaxLatencyMs {
		m.MaxLatencyMs = latency
	}

	// Update averages
	if m.SuccessCount > 0 {
		m.AvgLatencyMs = float64(m.TotalLatencyMs) / float64(m.SuccessCount)
		m.AvgTTFTMs = float64(m.TotalTTFTMs) / float64(m.SuccessCount)
	}

	// Calculate tokens per second
	if latency > 0 {
		m.TokensPerSecond = float64(event.CompletionTokens) / (float64(latency) / 1000.0)
	}

	// Update cost if enabled
	if tc.config.EnableCostEstimation {
		m.EstimatedCostUSD += tc.estimateCost(event.Model, event.Provider,
			event.PromptTokens, event.CompletionTokens)
	}

	if req, ok := tc.requests[event.RequestID]; ok {
		req.EndTime = event.Timestamp
		req.PromptTokens = event.PromptTokens
		req.CompletionTokens = event.CompletionTokens
		req.Status = RequestStatusCompleted
		req.FinishReason = event.FinishReason
	}
}

func (tc *TokenCollector) handleRequestError(event TokenEvent, m *TokenMetrics) {
	if event.Status == RequestStatusThrottled {
		m.ThrottledCount++
	} else {
		m.ErrorCount++
	}

	if req, ok := tc.requests[event.RequestID]; ok {
		req.EndTime = event.Timestamp
		req.Status = event.Status
		req.ErrorMessage = event.ErrorMessage
	}
}

// estimateCost estimates the cost for a request
func (tc *TokenCollector) estimateCost(model, provider string, promptTokens, completionTokens uint32) float64 {
	key := provider + "/" + model
	if pricing, ok := tc.config.PricingOverrides[key]; ok {
		return calculateCost(promptTokens, completionTokens, pricing)
	}
	if pricing, ok := DefaultPricing[key]; ok {
		return calculateCost(promptTokens, completionTokens, pricing)
	}
	return 0
}

// GetMetrics returns all collected metrics
func (tc *TokenCollector) GetMetrics() map[string]*TokenMetrics {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	result := make(map[string]*TokenMetrics, len(tc.metrics))
	for k, v := range tc.metrics {
		copy := *v
		result[k] = &copy
	}
	return result
}

// GetRequest returns information about a specific request
func (tc *TokenCollector) GetRequest(requestID string) *RequestInfo {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if req, ok := tc.requests[requestID]; ok {
		copy := *req
		return &copy
	}
	return nil
}
