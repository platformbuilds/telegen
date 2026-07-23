package pipeline

import (
	"sync"
	"sync/atomic"
	"time"
)

type CircuitState int32

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
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

type CircuitBreakerConfig struct {
	FailureThreshold      int
	SuccessThreshold      int
	OpenDuration          time.Duration
	HalfOpenMaxConcurrent int
	OnStateChange         func(endpoint string, from, to CircuitState)
}

func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold:      5,
		SuccessThreshold:      2,
		OpenDuration:          60 * time.Second,
		HalfOpenMaxConcurrent: 1,
	}
}

type CircuitBreaker struct {
	config   CircuitBreakerConfig
	endpoint string

	mu                 sync.Mutex
	state              CircuitState
	consecutiveFailure int
	consecutiveSuccess int
	lastFailureTime    time.Time
	halfOpenInFlight   int

	totalSuccess  atomic.Int64
	totalFailure  atomic.Int64
	totalRejected atomic.Int64
}

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

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailureTime) >= cb.config.OpenDuration {
			cb.transitionTo(CircuitHalfOpen)
			cb.halfOpenInFlight++
			return true
		}
		cb.totalRejected.Add(1)
		return false
	case CircuitHalfOpen:
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

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.totalSuccess.Add(1)
	cb.consecutiveFailure = 0
	if cb.state == CircuitHalfOpen {
		cb.halfOpenInFlight--
		cb.consecutiveSuccess++
		if cb.consecutiveSuccess >= cb.config.SuccessThreshold {
			cb.transitionTo(CircuitClosed)
		}
	}
}

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
		cb.transitionTo(CircuitOpen)
	}
}

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

type CircuitBreakerStats struct {
	Endpoint           string
	State              CircuitState
	TotalSuccess       int64
	TotalFailure       int64
	TotalRejected      int64
	ConsecutiveFailure int
}

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

func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	if cb.state == newState {
		return
	}
	oldState := cb.state
	cb.state = newState
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
		go cb.config.OnStateChange(cb.endpoint, oldState, newState)
	}
}
