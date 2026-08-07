package helpers

import (
	"context"
	"math/rand/v2"
	"time"
)

const (
	jitterMinFactor = 0.5
	jitterMaxDelta  = 0.5
)

// JitteredExponentialBackoff returns capped exponential backoff with jitter in [0.5, 1.0].
func JitteredExponentialBackoff(attempt int, initial, max time.Duration, multiplier float64) time.Duration {
	if initial <= 0 {
		initial = time.Millisecond
	}
	if max <= 0 || max < initial {
		max = initial
	}
	if multiplier < 1 {
		multiplier = 1
	}

	backoff := initial
	for i := 1; i < attempt; i++ {
		next := time.Duration(float64(backoff) * multiplier)
		if next <= 0 || next > max {
			backoff = max
			break
		}
		backoff = next
	}
	if backoff > max {
		backoff = max
	}

	jitterFactor := jitterMinFactor + rand.Float64()*jitterMaxDelta
	jittered := time.Duration(float64(backoff) * jitterFactor)
	if jittered <= 0 {
		return time.Millisecond
	}
	return jittered
}

// SleepWithContext sleeps for d unless ctx is canceled first.
func SleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
