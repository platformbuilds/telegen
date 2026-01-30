// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// Exemplar represents a metric exemplar linking metrics to traces.
type Exemplar struct {
	// Value is the exemplar value.
	Value float64

	// Timestamp is when the exemplar was recorded.
	Timestamp time.Time

	// TraceID links to the trace.
	TraceID TraceID

	// SpanID links to the span.
	SpanID SpanID

	// FilteredAttributes are additional attributes.
	FilteredAttributes map[string]interface{}
}

// NewExemplar creates a new exemplar.
func NewExemplar(value float64) *Exemplar {
	return &Exemplar{
		Value:              value,
		Timestamp:          time.Now(),
		FilteredAttributes: make(map[string]interface{}),
	}
}

// WithTraceContext sets the trace context.
func (e *Exemplar) WithTraceContext(tc *TraceContext) *Exemplar {
	if tc != nil {
		e.TraceID = tc.TraceID
		e.SpanID = tc.SpanID
	}
	return e
}

// WithTimestamp sets the timestamp.
func (e *Exemplar) WithTimestamp(ts time.Time) *Exemplar {
	e.Timestamp = ts
	return e
}

// WithAttribute sets a filtered attribute.
func (e *Exemplar) WithAttribute(key string, value interface{}) *Exemplar {
	e.FilteredAttributes[key] = value
	return e
}

// WithAttributes sets multiple filtered attributes.
func (e *Exemplar) WithAttributes(attrs map[string]interface{}) *Exemplar {
	for k, v := range attrs {
		e.FilteredAttributes[k] = v
	}
	return e
}

// IsValid returns whether the exemplar has valid trace context.
func (e *Exemplar) IsValid() bool {
	return e.TraceID.IsValid() && e.SpanID.IsValid()
}

// ExemplarReservoir collects exemplars for a metric.
type ExemplarReservoir interface {
	// Offer offers a measurement to the reservoir.
	Offer(ctx context.Context, value float64, attrs map[string]interface{})

	// Collect returns and clears collected exemplars.
	Collect() []*Exemplar
}

// SimpleExemplarReservoir is a simple fixed-size reservoir.
type SimpleExemplarReservoir struct {
	mu        sync.Mutex
	exemplars []*Exemplar
	maxSize   int
}

// NewSimpleExemplarReservoir creates a simple reservoir.
func NewSimpleExemplarReservoir(maxSize int) *SimpleExemplarReservoir {
	return &SimpleExemplarReservoir{
		exemplars: make([]*Exemplar, 0, maxSize),
		maxSize:   maxSize,
	}
}

// Offer offers a measurement to the reservoir.
func (r *SimpleExemplarReservoir) Offer(ctx context.Context, value float64, attrs map[string]interface{}) {
	tc := TraceContextFromContext(ctx)
	if tc == nil || !tc.TraceID.IsValid() {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	exemplar := NewExemplar(value).
		WithTraceContext(tc).
		WithAttributes(attrs)

	if len(r.exemplars) < r.maxSize {
		r.exemplars = append(r.exemplars, exemplar)
	} else {
		// Replace oldest
		r.exemplars = append(r.exemplars[1:], exemplar)
	}
}

// Collect returns and clears collected exemplars.
func (r *SimpleExemplarReservoir) Collect() []*Exemplar {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := r.exemplars
	r.exemplars = make([]*Exemplar, 0, r.maxSize)
	return result
}

// RandomExemplarReservoir uses random sampling.
type RandomExemplarReservoir struct {
	mu        sync.Mutex
	exemplars []*Exemplar
	maxSize   int
	count     int64
	rng       *rand.Rand
}

// NewRandomExemplarReservoir creates a random sampling reservoir.
func NewRandomExemplarReservoir(maxSize int) *RandomExemplarReservoir {
	return &RandomExemplarReservoir{
		exemplars: make([]*Exemplar, maxSize),
		maxSize:   maxSize,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Offer offers a measurement using reservoir sampling.
func (r *RandomExemplarReservoir) Offer(ctx context.Context, value float64, attrs map[string]interface{}) {
	tc := TraceContextFromContext(ctx)
	if tc == nil || !tc.TraceID.IsValid() {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.count++

	exemplar := NewExemplar(value).
		WithTraceContext(tc).
		WithAttributes(attrs)

	if int(r.count) <= r.maxSize {
		r.exemplars[r.count-1] = exemplar
	} else {
		// Reservoir sampling: replace with probability maxSize/count
		idx := r.rng.Int63n(r.count)
		if idx < int64(r.maxSize) {
			r.exemplars[idx] = exemplar
		}
	}
}

// Collect returns and clears collected exemplars.
func (r *RandomExemplarReservoir) Collect() []*Exemplar {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]*Exemplar, 0, r.maxSize)
	for _, e := range r.exemplars {
		if e != nil {
			result = append(result, e)
		}
	}

	r.exemplars = make([]*Exemplar, r.maxSize)
	r.count = 0

	return result
}

// AlignedExemplarReservoir aligns exemplars to histogram buckets.
type AlignedExemplarReservoir struct {
	mu        sync.Mutex
	buckets   []float64
	exemplars []*Exemplar
}

// NewAlignedExemplarReservoir creates a bucket-aligned reservoir.
func NewAlignedExemplarReservoir(buckets []float64) *AlignedExemplarReservoir {
	return &AlignedExemplarReservoir{
		buckets:   buckets,
		exemplars: make([]*Exemplar, len(buckets)+1),
	}
}

// Offer offers a measurement aligned to histogram buckets.
func (r *AlignedExemplarReservoir) Offer(ctx context.Context, value float64, attrs map[string]interface{}) {
	tc := TraceContextFromContext(ctx)
	if tc == nil || !tc.TraceID.IsValid() {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Find bucket
	bucketIdx := len(r.buckets)
	for i, bound := range r.buckets {
		if value <= bound {
			bucketIdx = i
			break
		}
	}

	exemplar := NewExemplar(value).
		WithTraceContext(tc).
		WithAttributes(attrs)

	r.exemplars[bucketIdx] = exemplar
}

// Collect returns and clears collected exemplars.
func (r *AlignedExemplarReservoir) Collect() []*Exemplar {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]*Exemplar, 0, len(r.exemplars))
	for _, e := range r.exemplars {
		if e != nil {
			result = append(result, e)
		}
	}

	r.exemplars = make([]*Exemplar, len(r.buckets)+1)
	return result
}

// ExemplarFilter determines which measurements become exemplars.
type ExemplarFilter interface {
	// ShouldSample returns whether the measurement should become an exemplar.
	ShouldSample(ctx context.Context, value float64) bool
}

// AlwaysSampleFilter always samples.
type AlwaysSampleFilter struct{}

// ShouldSample always returns true.
func (f *AlwaysSampleFilter) ShouldSample(ctx context.Context, value float64) bool {
	return true
}

// TraceSampleFilter only samples when trace context is present.
type TraceSampleFilter struct{}

// ShouldSample returns true if trace context is present and sampled.
func (f *TraceSampleFilter) ShouldSample(ctx context.Context, value float64) bool {
	tc := TraceContextFromContext(ctx)
	return tc != nil && tc.TraceID.IsValid() && tc.Flags.IsSampled()
}

// RatioSampleFilter samples at a given ratio.
type RatioSampleFilter struct {
	ratio float64
	rng   *rand.Rand
	mu    sync.Mutex
}

// NewRatioSampleFilter creates a ratio-based filter.
func NewRatioSampleFilter(ratio float64) *RatioSampleFilter {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	return &RatioSampleFilter{
		ratio: ratio,
		rng:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ShouldSample returns true based on ratio.
func (f *RatioSampleFilter) ShouldSample(ctx context.Context, value float64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.rng.Float64() < f.ratio
}

// CompositeExemplarFilter combines multiple filters.
type CompositeExemplarFilter struct {
	filters []ExemplarFilter
	mode    CompositeMode
}

// CompositeMode defines how filters are combined.
type CompositeMode int

const (
	// CompositeModeAnd requires all filters to pass.
	CompositeModeAnd CompositeMode = iota
	// CompositeModeOr requires any filter to pass.
	CompositeModeOr
)

// NewCompositeExemplarFilter creates a composite filter.
func NewCompositeExemplarFilter(mode CompositeMode, filters ...ExemplarFilter) *CompositeExemplarFilter {
	return &CompositeExemplarFilter{
		filters: filters,
		mode:    mode,
	}
}

// ShouldSample applies composite logic.
func (f *CompositeExemplarFilter) ShouldSample(ctx context.Context, value float64) bool {
	if len(f.filters) == 0 {
		return true
	}

	switch f.mode {
	case CompositeModeAnd:
		for _, filter := range f.filters {
			if !filter.ShouldSample(ctx, value) {
				return false
			}
		}
		return true
	case CompositeModeOr:
		for _, filter := range f.filters {
			if filter.ShouldSample(ctx, value) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// ExemplarCollector collects exemplars with filtering.
type ExemplarCollector struct {
	reservoir ExemplarReservoir
	filter    ExemplarFilter
}

// NewExemplarCollector creates a new collector.
func NewExemplarCollector(reservoir ExemplarReservoir, filter ExemplarFilter) *ExemplarCollector {
	if filter == nil {
		filter = &TraceSampleFilter{}
	}

	return &ExemplarCollector{
		reservoir: reservoir,
		filter:    filter,
	}
}

// Record records a measurement.
func (c *ExemplarCollector) Record(ctx context.Context, value float64, attrs map[string]interface{}) {
	if c.filter.ShouldSample(ctx, value) {
		c.reservoir.Offer(ctx, value, attrs)
	}
}

// Collect returns collected exemplars.
func (c *ExemplarCollector) Collect() []*Exemplar {
	return c.reservoir.Collect()
}

// MetricExemplars holds exemplars for a metric.
type MetricExemplars struct {
	// MetricName is the metric name.
	MetricName string

	// Exemplars are the collected exemplars.
	Exemplars []*Exemplar
}

// ExemplarStore stores exemplars for metrics.
type ExemplarStore struct {
	mu         sync.RWMutex
	collectors map[string]*ExemplarCollector
	factory    ExemplarReservoirFactory
}

// ExemplarReservoirFactory creates reservoirs.
type ExemplarReservoirFactory func() ExemplarReservoir

// NewExemplarStore creates a new exemplar store.
func NewExemplarStore(factory ExemplarReservoirFactory) *ExemplarStore {
	if factory == nil {
		factory = func() ExemplarReservoir {
			return NewSimpleExemplarReservoir(1)
		}
	}

	return &ExemplarStore{
		collectors: make(map[string]*ExemplarCollector),
		factory:    factory,
	}
}

// Record records a measurement for a metric.
func (s *ExemplarStore) Record(ctx context.Context, metricName string, value float64, attrs map[string]interface{}) {
	s.mu.RLock()
	collector, ok := s.collectors[metricName]
	s.mu.RUnlock()

	if !ok {
		s.mu.Lock()
		collector, ok = s.collectors[metricName]
		if !ok {
			collector = NewExemplarCollector(s.factory(), nil)
			s.collectors[metricName] = collector
		}
		s.mu.Unlock()
	}

	collector.Record(ctx, value, attrs)
}

// Collect collects exemplars for a metric.
func (s *ExemplarStore) Collect(metricName string) []*Exemplar {
	s.mu.RLock()
	collector, ok := s.collectors[metricName]
	s.mu.RUnlock()

	if !ok {
		return nil
	}

	return collector.Collect()
}

// CollectAll collects all exemplars.
func (s *ExemplarStore) CollectAll() []*MetricExemplars {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*MetricExemplars, 0, len(s.collectors))
	for name, collector := range s.collectors {
		exemplars := collector.Collect()
		if len(exemplars) > 0 {
			result = append(result, &MetricExemplars{
				MetricName: name,
				Exemplars:  exemplars,
			})
		}
	}

	return result
}
