// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// SamplingType defines the type of sampling to use
type SamplingType string

const (
	// SamplingNone disables sampling (100% of traces)
	SamplingNone SamplingType = "none"

	// SamplingHeadBased samples at trace start (parent-based)
	SamplingHeadBased SamplingType = "head"

	// SamplingTailBased samples after trace completes (for error/latency)
	SamplingTailBased SamplingType = "tail"

	// SamplingProbabilistic samples based on trace ID hash
	SamplingProbabilistic SamplingType = "probabilistic"

	// SamplingRateLimited limits the number of traces per second
	SamplingRateLimited SamplingType = "rate_limited"
)

// SamplingConfig holds sampling configuration
type SamplingConfig struct {
	// Type of sampling
	Type SamplingType `mapstructure:"type"`

	// Ratio for probabilistic sampling (0.0 - 1.0)
	Ratio float64 `mapstructure:"ratio"`

	// RateLimit for rate-limited sampling (traces per second)
	RateLimit float64 `mapstructure:"rate_limit"`

	// TailSampling configuration for tail-based sampling
	TailSampling TailSamplingConfig `mapstructure:"tail_sampling"`
}

// TailSamplingConfig holds tail-based sampling configuration
type TailSamplingConfig struct {
	// DecisionWaitSeconds is how long to wait for a trace to complete
	DecisionWaitSeconds int `mapstructure:"decision_wait_seconds"`

	// NumTraces is the number of traces to keep in memory
	NumTraces int `mapstructure:"num_traces"`

	// Policies define when to sample
	Policies []TailSamplingPolicy `mapstructure:"policies"`
}

// TailSamplingPolicy defines a tail-based sampling policy
type TailSamplingPolicy struct {
	// Name of the policy
	Name string `mapstructure:"name"`

	// Type of policy (always_sample, latency, status_code, rate_limiting, etc.)
	Type string `mapstructure:"type"`

	// Config for the policy
	Config map[string]interface{} `mapstructure:"config"`
}

// SamplingProcessor implements signal sampling
type SamplingProcessor struct {
	name   string
	config SamplingConfig
	log    *slog.Logger
	st     *selftelemetry.Metrics

	// For probabilistic sampling
	threshold uint64

	// For rate-limited sampling
	rateLimiter *rateLimiter

	// Statistics
	sampled  atomic.Int64
	rejected atomic.Int64
}

// NewSamplingProcessor creates a new sampling processor
func NewSamplingProcessor(name string, config SamplingConfig, log *slog.Logger, st *selftelemetry.Metrics) *SamplingProcessor {
	sp := &SamplingProcessor{
		name:   name,
		config: config,
		log:    log.With("component", "sampling", "name", name),
		st:     st,
	}

	// Calculate threshold for probabilistic sampling
	// We use a 64-bit hash and compare against threshold
	if config.Ratio > 0 && config.Ratio <= 1.0 {
		sp.threshold = uint64(config.Ratio * float64(^uint64(0)))
	}

	// Initialize rate limiter if needed
	if config.Type == SamplingRateLimited && config.RateLimit > 0 {
		sp.rateLimiter = newRateLimiter(config.RateLimit)
	}

	return sp
}

func (p *SamplingProcessor) Name() string { return p.name }

// Process applies sampling to the signal
func (p *SamplingProcessor) Process(ctx context.Context, signal Signal) (Signal, error) {
	switch p.config.Type {
	case SamplingNone:
		return signal, nil

	case SamplingHeadBased:
		return p.headBasedSample(signal)

	case SamplingTailBased:
		// Tail-based sampling is more complex and typically done in a separate component
		return signal, nil

	case SamplingProbabilistic:
		return p.probabilisticSample(signal)

	case SamplingRateLimited:
		return p.rateLimitedSample(signal)

	default:
		return signal, nil
	}
}

// probabilisticSample samples based on a hash of the signal
func (p *SamplingProcessor) probabilisticSample(signal Signal) (Signal, error) {
	// Get a sampling key from the signal (e.g., trace ID)
	key := p.getSamplingKey(signal)
	hash := hashKey(key)

	if hash < p.threshold {
		p.sampled.Add(1)
		if p.st != nil {
			p.st.SamplerAccepted.WithLabelValues(p.name).Inc()
		}
		return signal, nil
	}

	p.rejected.Add(1)
	if p.st != nil {
		p.st.SamplerRejected.WithLabelValues(p.name).Inc()
	}
	return nil, nil
}

// headBasedSample samples based on parent sampling decision
func (p *SamplingProcessor) headBasedSample(signal Signal) (Signal, error) {
	// Check if parent was sampled (if available in signal)
	// For now, fall back to probabilistic
	return p.probabilisticSample(signal)
}

// rateLimitedSample applies rate limiting
func (p *SamplingProcessor) rateLimitedSample(signal Signal) (Signal, error) {
	if p.rateLimiter == nil {
		return signal, nil
	}

	if p.rateLimiter.Allow() {
		p.sampled.Add(1)
		if p.st != nil {
			p.st.SamplerAccepted.WithLabelValues(p.name).Inc()
		}
		return signal, nil
	}

	p.rejected.Add(1)
	if p.st != nil {
		p.st.SamplerRejected.WithLabelValues(p.name).Inc()
	}
	return nil, nil
}

// getSamplingKey extracts a key for sampling decisions
func (p *SamplingProcessor) getSamplingKey(signal Signal) string {
	// This would typically extract trace ID or similar
	// For now, use type conversion if available
	if sk, ok := signal.(interface{ SamplingKey() string }); ok {
		return sk.SamplingKey()
	}
	return fmt.Sprintf("%p", signal)
}

// Stats returns sampling statistics
func (p *SamplingProcessor) Stats() (sampled, rejected int64) {
	return p.sampled.Load(), p.rejected.Load()
}

// hashKey computes a consistent hash for a key
func hashKey(key string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	return h.Sum64()
}

// rateLimiter implements a simple token bucket rate limiter
type rateLimiter struct {
	mu        sync.Mutex
	rate      float64
	tokens    float64
	maxTokens float64
	lastTime  int64 //nolint:unused // reserved for time-based token refill
}

func newRateLimiter(rate float64) *rateLimiter {
	return &rateLimiter{
		rate:      rate,
		tokens:    rate, // Start with a full bucket
		maxTokens: rate, // Max 1 second of tokens
	}
}

func (r *rateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Simplified implementation - in production would use time-based token refill
	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

func (r *rateLimiter) Refill() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens = r.maxTokens
}

func init() {
	// Register sampling processor factory
	RegisterProcessor("sampling", func(config map[string]interface{}) (Processor, error) {
		cfg := SamplingConfig{
			Type:  SamplingProbabilistic,
			Ratio: 1.0,
		}

		if t, ok := config["type"].(string); ok {
			cfg.Type = SamplingType(t)
		}
		if r, ok := config["ratio"].(float64); ok {
			cfg.Ratio = r
		}
		if rl, ok := config["rate_limit"].(float64); ok {
			cfg.RateLimit = rl
		}

		name := "sampling"
		if n, ok := config["name"].(string); ok {
			name = n
		}

		return NewSamplingProcessor(name, cfg, slog.Default(), nil), nil
	})
}
