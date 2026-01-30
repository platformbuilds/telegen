// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"time"
)

// Retryer handles retry logic with exponential backoff.
type Retryer struct {
	cfg RetryConfig
	log *slog.Logger
	rng *rand.Rand
}

// NewRetryer creates a new retryer.
func NewRetryer(cfg RetryConfig, log *slog.Logger) *Retryer {
	return &Retryer{
		cfg: cfg,
		log: log.With("component", "retryer"),
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// RetryableFunc is a function that can be retried.
type RetryableFunc func(ctx context.Context, attempt int) error

// Do executes the function with retry logic.
func (r *Retryer) Do(ctx context.Context, fn RetryableFunc) error {
	if !r.cfg.Enabled {
		return fn(ctx, 0)
	}

	startTime := time.Now()
	var lastErr error
	attempt := 0

	for {
		// Check context before attempting
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled before attempt %d: %w", attempt, err)
		}

		// Check if we've exceeded max elapsed time
		if r.cfg.MaxElapsedTime > 0 && time.Since(startTime) > r.cfg.MaxElapsedTime {
			if lastErr != nil {
				return fmt.Errorf("max elapsed time exceeded: %w", lastErr)
			}
			return fmt.Errorf("max elapsed time exceeded")
		}

		// Execute the function
		err := fn(ctx, attempt)
		if err == nil {
			if attempt > 0 {
				r.log.Debug("operation succeeded after retry", "attempts", attempt+1)
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !r.isRetryable(err) {
			r.log.Debug("non-retryable error", "error", err)
			return err
		}

		// Calculate backoff duration
		backoff := r.calculateBackoff(attempt, err)

		r.log.Debug("retrying after backoff",
			"attempt", attempt+1,
			"backoff", backoff,
			"error", err,
		)

		// Wait for backoff or context cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during backoff: %w", ctx.Err())
		case <-time.After(backoff):
			// Continue to next attempt
		}

		attempt++
	}
}

// DoWithResult executes a function that returns a result with retry logic.
func DoWithResult[T any](r *Retryer, ctx context.Context, fn func(ctx context.Context, attempt int) (T, error)) (T, error) {
	var result T

	err := r.Do(ctx, func(ctx context.Context, attempt int) error {
		var err error
		result, err = fn(ctx, attempt)
		return err
	})

	return result, err
}

// isRetryable determines if an error is retryable.
func (r *Retryer) isRetryable(err error) bool {
	// Check for RetryableError
	var retryable *RetryableError
	if errors.As(err, &retryable) {
		return retryable.Retryable
	}

	// Check for context errors (not retryable)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Default to retryable for unknown errors (conservative approach)
	return true
}

// calculateBackoff calculates the backoff duration for the given attempt.
func (r *Retryer) calculateBackoff(attempt int, err error) time.Duration {
	// Check if error specifies a retry-after duration
	var retryable *RetryableError
	if errors.As(err, &retryable) && retryable.RetryAfter > 0 {
		// Use the server-specified retry-after, but cap it at max interval
		if retryable.RetryAfter > r.cfg.MaxInterval {
			return r.cfg.MaxInterval
		}
		return retryable.RetryAfter
	}

	// Calculate exponential backoff
	backoff := float64(r.cfg.InitialInterval) * math.Pow(r.cfg.Multiplier, float64(attempt))

	// Apply randomization factor (jitter)
	if r.cfg.RandomizationFactor > 0 {
		jitterRange := backoff * r.cfg.RandomizationFactor
		jitter := (r.rng.Float64() * 2 * jitterRange) - jitterRange
		backoff += jitter
	}

	// Ensure backoff is within bounds
	if backoff < float64(r.cfg.InitialInterval) {
		backoff = float64(r.cfg.InitialInterval)
	}
	if backoff > float64(r.cfg.MaxInterval) {
		backoff = float64(r.cfg.MaxInterval)
	}

	return time.Duration(backoff)
}

// RetryableError wraps an error with retry information.
type RetryableError struct {
	Err        error
	Retryable  bool
	RetryAfter time.Duration
}

// Error returns the error message.
func (e *RetryableError) Error() string {
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *RetryableError) Unwrap() error {
	return e.Err
}

// NewRetryableError creates a new retryable error.
func NewRetryableError(err error, retryable bool) *RetryableError {
	return &RetryableError{
		Err:       err,
		Retryable: retryable,
	}
}

// NewRetryableErrorWithAfter creates a retryable error with a retry-after duration.
func NewRetryableErrorWithAfter(err error, retryAfter time.Duration) *RetryableError {
	return &RetryableError{
		Err:        err,
		Retryable:  true,
		RetryAfter: retryAfter,
	}
}

// RetryPolicy defines a custom retry policy.
type RetryPolicy interface {
	// ShouldRetry returns whether the error should be retried.
	ShouldRetry(err error, attempt int) bool
	// BackoffDuration returns the backoff duration for the attempt.
	BackoffDuration(attempt int) time.Duration
}

// ExponentialBackoffPolicy implements exponential backoff.
type ExponentialBackoffPolicy struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	MaxElapsedTime  time.Duration
	rng             *rand.Rand
}

// NewExponentialBackoffPolicy creates a new exponential backoff policy.
func NewExponentialBackoffPolicy(cfg RetryConfig) *ExponentialBackoffPolicy {
	return &ExponentialBackoffPolicy{
		InitialInterval: cfg.InitialInterval,
		MaxInterval:     cfg.MaxInterval,
		Multiplier:      cfg.Multiplier,
		MaxElapsedTime:  cfg.MaxElapsedTime,
		rng:             rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ShouldRetry returns whether the error should be retried.
func (p *ExponentialBackoffPolicy) ShouldRetry(err error, attempt int) bool {
	// Check for RetryableError
	var retryable *RetryableError
	if errors.As(err, &retryable) {
		return retryable.Retryable
	}

	// Default to retryable
	return true
}

// BackoffDuration returns the backoff duration for the attempt.
func (p *ExponentialBackoffPolicy) BackoffDuration(attempt int) time.Duration {
	backoff := float64(p.InitialInterval) * math.Pow(p.Multiplier, float64(attempt))

	// Cap at max interval
	if backoff > float64(p.MaxInterval) {
		backoff = float64(p.MaxInterval)
	}

	return time.Duration(backoff)
}

// LinearBackoffPolicy implements linear backoff.
type LinearBackoffPolicy struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Increment       time.Duration
}

// ShouldRetry returns whether the error should be retried.
func (p *LinearBackoffPolicy) ShouldRetry(err error, attempt int) bool {
	var retryable *RetryableError
	if errors.As(err, &retryable) {
		return retryable.Retryable
	}

	return true
}

// BackoffDuration returns the backoff duration for the attempt.
func (p *LinearBackoffPolicy) BackoffDuration(attempt int) time.Duration {
	backoff := p.InitialInterval + time.Duration(attempt)*p.Increment

	if backoff > p.MaxInterval {
		backoff = p.MaxInterval
	}

	return backoff
}

// NoRetryPolicy disables retries.
type NoRetryPolicy struct{}

// ShouldRetry always returns false.
func (p *NoRetryPolicy) ShouldRetry(err error, attempt int) bool {
	return false
}

// BackoffDuration returns zero.
func (p *NoRetryPolicy) BackoffDuration(attempt int) time.Duration {
	return 0
}
