package pipeline

import (
	"sync"
	"testing"
	"time"
)

func TestCircuitBreaker_InitialState(t *testing.T) {
	cb := NewCircuitBreaker("test", DefaultCircuitBreakerConfig())

	if cb.State() != CircuitClosed {
		t.Errorf("expected initial state to be closed, got %v", cb.State())
	}

	if !cb.Allow() {
		t.Error("expected Allow() to return true in closed state")
	}
}

func TestCircuitBreaker_TransitionToOpen(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 3,
		OpenDuration:     100 * time.Millisecond,
	}
	cb := NewCircuitBreaker("test", config)

	// Record failures below threshold.
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure()
	if cb.State() != CircuitClosed {
		t.Error("expected state to still be closed")
	}

	// Trigger threshold.
	cb.Allow()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected state to be open, got %v", cb.State())
	}

	// Should reject requests.
	if cb.Allow() {
		t.Error("expected Allow() to return false in open state")
	}
}

func TestCircuitBreaker_TransitionToHalfOpen(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		OpenDuration:     50 * time.Millisecond,
	}
	cb := NewCircuitBreaker("test", config)

	// Trip the circuit.
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatal("expected circuit to be open")
	}

	// Wait for open duration.
	time.Sleep(60 * time.Millisecond)

	// Should transition to half-open.
	if !cb.Allow() {
		t.Error("expected Allow() to return true after open duration")
	}
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected state to be half-open, got %v", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenToClosed(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		OpenDuration:     10 * time.Millisecond,
	}
	cb := NewCircuitBreaker("test", config)

	// Trip the circuit.
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure()

	// Wait for open duration.
	time.Sleep(20 * time.Millisecond)

	// Transition to half-open.
	cb.Allow()

	// Record successes.
	cb.RecordSuccess()
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected state to be half-open after 1 success, got %v", cb.State())
	}

	// Allow another request in half-open.
	cb.Allow()
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("expected state to be closed after 2 successes, got %v", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenToOpen(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		OpenDuration:     10 * time.Millisecond,
	}
	cb := NewCircuitBreaker("test", config)

	// Trip the circuit.
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure()

	// Wait and transition to half-open.
	time.Sleep(20 * time.Millisecond)
	cb.Allow()

	// Single failure in half-open should go back to open.
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected state to be open after failure in half-open, got %v", cb.State())
	}
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 3,
	}
	cb := NewCircuitBreaker("test", config)

	// 2 failures, then success.
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordSuccess()

	// 2 more failures shouldn't trip.
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure()

	if cb.State() != CircuitClosed {
		t.Error("expected circuit to still be closed")
	}

	// One more should trip.
	cb.Allow()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Error("expected circuit to be open")
	}
}

func TestCircuitBreaker_HalfOpenConcurrencyLimit(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold:      2,
		HalfOpenMaxConcurrent: 1,
		OpenDuration:          10 * time.Millisecond,
	}
	cb := NewCircuitBreaker("test", config)

	// Trip.
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure()

	// Wait and transition to half-open.
	time.Sleep(20 * time.Millisecond)

	// First request allowed.
	if !cb.Allow() {
		t.Error("expected first request to be allowed in half-open")
	}

	// Second should be rejected while first in flight.
	if cb.Allow() {
		t.Error("expected second request to be rejected in half-open")
	}

	// Complete first request.
	cb.RecordSuccess()

	// Now another should be allowed.
	if !cb.Allow() {
		t.Error("expected next request to be allowed after first completed")
	}
}

func TestCircuitBreaker_Stats(t *testing.T) {
	cb := NewCircuitBreaker("test", DefaultCircuitBreakerConfig())

	for i := 0; i < 5; i++ {
		cb.Allow()
		cb.RecordSuccess()
	}
	for i := 0; i < 3; i++ {
		cb.Allow()
		cb.RecordFailure()
	}

	stats := cb.Stats()
	if stats.TotalSuccess != 5 {
		t.Errorf("expected 5 successes, got %d", stats.TotalSuccess)
	}
	if stats.TotalFailure != 3 {
		t.Errorf("expected 3 failures, got %d", stats.TotalFailure)
	}
	if stats.Endpoint != "test" {
		t.Errorf("expected endpoint 'test', got %s", stats.Endpoint)
	}
}

func TestCircuitBreaker_StateChangedCallback(t *testing.T) {
	var mu sync.Mutex
	var changes []struct{ from, to CircuitState }

	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		OpenDuration:     10 * time.Millisecond,
		OnStateChange: func(endpoint string, from, to CircuitState) {
			mu.Lock()
			changes = append(changes, struct{ from, to CircuitState }{from, to})
			mu.Unlock()
		},
	}
	cb := NewCircuitBreaker("test", config)

	// Trip.
	cb.Allow()
	cb.RecordFailure()
	cb.Allow()
	cb.RecordFailure()

	// Wait for callback.
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(changes) != 1 || changes[0].from != CircuitClosed || changes[0].to != CircuitOpen {
		t.Errorf("expected open transition, got %v", changes)
	}
	mu.Unlock()
}

func TestCircuitBreakerState_String(t *testing.T) {
	tests := []struct {
		state    CircuitState
		expected string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}

	for _, tc := range tests {
		if got := tc.state.String(); got != tc.expected {
			t.Errorf("expected %s, got %s", tc.expected, got)
		}
	}
}
