// Package pipeline provides circuit breaker functionality for endpoint health management.
package pipeline

import (
	"sync"
	"sync/atomic"
	"time"
)

// CircuitState represents the state of a circuit breaker.
type CircuitState int32

const (
	// CircuitClosed is the normal state - requests flow through.
	CircuitClosed CircuitState = iota
	// CircuitOpen is the failure state - requests are rejected.
	CircuitOpen
	// CircuitHalfOpen is the testing state - limited requests allowed.
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig configures the circuit breaker behavior.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures to trip the circuit.
	// Default: 5
	FailureThreshold int

	// SuccessThreshold is the number of consecutive successes in half-open to close.
	// Default: 2
	SuccessThreshold int

	// OpenDuration is how long the circuit stays open before entering half-open.
	// Default: 60s
	OpenDuration time.Duration

	// HalfOpenMaxConcurrent is the max concurrent requests in half-open state.
	// Default: 1
	HalfOpenMaxConcurrent int

	// OnStateChange is called when the circuit state changes.
	OnStateChange func(endpoint string, from, to CircuitState)
}

// DefaultCircuitBreakerConfig returns sensible defaults.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold:      5,
		SuccessThreshold:      2,
		OpenDuration:          60 * time.Second,
		HalfOpenMaxConcurrent: 1,
	}
}

// CircuitBreaker implements the circuit breaker pattern for an endpoint.
type CircuitBreaker struct {
	config   CircuitBreakerConfig
	endpoint string

	mu                 sync.Mutex
	state              CircuitState
	consecutiveFailure int
	consecutiveSuccess int
	lastFailureTime    time.Time
	halfOpenInFlight   int

	// Stats
	totalSuccess atomic.Int64
	totalFailure atomic.Int64
	totalRejected atomic.Int64
}

// NewCircuitBreaker creates a new circuit breaker for an endpoint.
func NewCircuitBreaker(endpoint string, config CircuitBreakerConfig) *CircuitBreaker {
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold == 0 {
		config.SuccessThreshold = 2
	}
	if config.OpenDuration == 0 {
		config.OpenDuration = 60 * time.Second
	}
	if config.HalfOpenMaxConcurrent == 0 {
		config.HalfOpenMaxConcurrent = 1
	}

	return &CircuitBreaker{
		config:   config,
		endpoint: endpoint,
		state:    CircuitClosed,
	}
}

// Allow checks if a request should be allowed.
// Returns true if the request can proceed, false if it should be rejected.
// Call RecordSuccess or RecordFailure after the request completes.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if we should transition to half-open.
		if time.Since(cb.lastFailureTime) >= cb.config.OpenDuration {
			cb.transitionTo(CircuitHalfOpen)
			cb.halfOpenInFlight++
			return true
		}
		cb.totalRejected.Add(1)
		return false

	case CircuitHalfOpen:
		// Allow limited concurrent requests in half-open.
		if cb.halfOpenInFlight < cb.config.HalfOpenMaxConcurrent {
			cb.halfOpenInFlight++
			return true
		}
		cb.totalRejected.Add(1)
		return false

	default:
		return false
	}
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.totalSuccess.Add(1)
	cb.consecutiveFailure = 0

	switch cb.state {
	case CircuitClosed:
		// Stay closed.

	case CircuitHalfOpen:
		cb.halfOpenInFlight--
		cb.consecutiveSuccess++
		if cb.consecutiveSuccess >= cb.config.SuccessThreshold {
			cb.transitionTo(CircuitClosed)
		}

	case CircuitOpen:
		// Shouldn't happen, but handle gracefully.
	}
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.totalFailure.Add(1)
	cb.consecutiveSuccess = 0
	cb.consecutiveFailure++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitClosed:
		if cb.consecutiveFailure >= cb.config.FailureThreshold {
			cb.transitionTo(CircuitOpen)
		}

	case CircuitHalfOpen:
		cb.halfOpenInFlight--
		// Any failure in half-open immediately opens the circuit.
		cb.transitionTo(CircuitOpen)

	case CircuitOpen:
		// Stay open, update last failure time.
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// Stats returns circuit breaker statistics.
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.Lock()
	state := cb.state
	consecutiveFailure := cb.consecutiveFailure
	cb.mu.Unlock()

	return CircuitBreakerStats{
		Endpoint:           cb.endpoint,
		State:              state,
		TotalSuccess:       cb.totalSuccess.Load(),
		TotalFailure:       cb.totalFailure.Load(),
		TotalRejected:      cb.totalRejected.Load(),
		ConsecutiveFailure: consecutiveFailure,
	}
}

// transitionTo transitions the circuit to a new state.
// Must be called with mutex held.
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	if cb.state == newState {
		return
	}

	oldState := cb.state
	cb.state = newState

	// Reset counters on transition.
	switch newState {
	case CircuitClosed:
		cb.consecutiveFailure = 0
		cb.consecutiveSuccess = 0
	case CircuitHalfOpen:
		cb.consecutiveSuccess = 0
		cb.halfOpenInFlight = 0
	case CircuitOpen:
		cb.consecutiveSuccess = 0
	}

	if cb.config.OnStateChange != nil {
		// Call callback outside of lock to avoid deadlock.
		go cb.config.OnStateChange(cb.endpoint, oldState, newState)
	}
}

// CircuitBreakerStats holds circuit breaker statistics.
type CircuitBreakerStats struct {
	Endpoint           string
	State              CircuitState
	TotalSuccess       int64
	TotalFailure       int64
	TotalRejected      int64
	ConsecutiveFailure int
}
