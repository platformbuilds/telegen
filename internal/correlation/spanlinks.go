// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"time"
)

// SpanLink represents a link between spans.
type SpanLink struct {
	// TraceID of the linked span.
	TraceID TraceID

	// SpanID of the linked span.
	SpanID SpanID

	// TraceState of the linked span.
	TraceState string

	// Attributes of the link.
	Attributes map[string]interface{}

	// DroppedAttributesCount is the count of dropped attributes.
	DroppedAttributesCount uint32

	// Flags contains link flags.
	Flags SpanLinkFlags
}

// SpanLinkFlags contains flags for span links.
type SpanLinkFlags uint32

const (
	// SpanLinkFlagNone indicates no special handling.
	SpanLinkFlagNone SpanLinkFlags = 0

	// SpanLinkFlagSampled indicates the linked span was sampled.
	SpanLinkFlagSampled SpanLinkFlags = 1 << 0
)

// NewSpanLink creates a new span link.
func NewSpanLink(traceID TraceID, spanID SpanID) *SpanLink {
	return &SpanLink{
		TraceID:    traceID,
		SpanID:     spanID,
		Attributes: make(map[string]interface{}),
	}
}

// WithTraceState sets the trace state.
func (l *SpanLink) WithTraceState(traceState string) *SpanLink {
	l.TraceState = traceState
	return l
}

// WithAttribute sets an attribute on the link.
func (l *SpanLink) WithAttribute(key string, value interface{}) *SpanLink {
	l.Attributes[key] = value
	return l
}

// WithAttributes sets multiple attributes on the link.
func (l *SpanLink) WithAttributes(attrs map[string]interface{}) *SpanLink {
	for k, v := range attrs {
		l.Attributes[k] = v
	}
	return l
}

// WithFlags sets the link flags.
func (l *SpanLink) WithFlags(flags SpanLinkFlags) *SpanLink {
	l.Flags = flags
	return l
}

// IsValid returns whether the link has valid trace and span IDs.
func (l *SpanLink) IsValid() bool {
	return l.TraceID.IsValid() && l.SpanID.IsValid()
}

// SpanLinkBuilder builds span links.
type SpanLinkBuilder struct {
	links []*SpanLink
}

// NewSpanLinkBuilder creates a new span link builder.
func NewSpanLinkBuilder() *SpanLinkBuilder {
	return &SpanLinkBuilder{
		links: make([]*SpanLink, 0),
	}
}

// AddLink adds a link to the builder.
func (b *SpanLinkBuilder) AddLink(link *SpanLink) *SpanLinkBuilder {
	b.links = append(b.links, link)
	return b
}

// AddLinkFromContext adds a link from a trace context.
func (b *SpanLinkBuilder) AddLinkFromContext(tc *TraceContext) *SpanLinkBuilder {
	if tc == nil {
		return b
	}

	link := NewSpanLink(tc.TraceID, tc.SpanID)
	link.TraceState = tc.TraceState

	if tc.Flags.IsSampled() {
		link.Flags |= SpanLinkFlagSampled
	}

	b.links = append(b.links, link)
	return b
}

// AddLinkWithAttributes adds a link with attributes.
func (b *SpanLinkBuilder) AddLinkWithAttributes(traceID TraceID, spanID SpanID, attrs map[string]interface{}) *SpanLinkBuilder {
	link := NewSpanLink(traceID, spanID)
	link.Attributes = attrs
	b.links = append(b.links, link)
	return b
}

// Build returns the built links.
func (b *SpanLinkBuilder) Build() []*SpanLink {
	return b.links
}

// SpanEvent represents an event in a span.
type SpanEvent struct {
	// Name of the event.
	Name string

	// Timestamp of the event.
	Timestamp time.Time

	// Attributes of the event.
	Attributes map[string]interface{}

	// DroppedAttributesCount is the count of dropped attributes.
	DroppedAttributesCount uint32
}

// NewSpanEvent creates a new span event.
func NewSpanEvent(name string) *SpanEvent {
	return &SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: make(map[string]interface{}),
	}
}

// WithTimestamp sets the event timestamp.
func (e *SpanEvent) WithTimestamp(ts time.Time) *SpanEvent {
	e.Timestamp = ts
	return e
}

// WithAttribute sets an attribute on the event.
func (e *SpanEvent) WithAttribute(key string, value interface{}) *SpanEvent {
	e.Attributes[key] = value
	return e
}

// WithAttributes sets multiple attributes on the event.
func (e *SpanEvent) WithAttributes(attrs map[string]interface{}) *SpanEvent {
	for k, v := range attrs {
		e.Attributes[k] = v
	}
	return e
}

// Span represents a span for correlation.
type Span struct {
	// TraceID of the span.
	TraceID TraceID

	// SpanID of the span.
	SpanID SpanID

	// ParentSpanID is the parent span's ID.
	ParentSpanID SpanID

	// Name is the span name.
	Name string

	// Kind is the span kind.
	Kind SpanKind

	// StartTime is when the span started.
	StartTime time.Time

	// EndTime is when the span ended.
	EndTime time.Time

	// Attributes are span attributes.
	Attributes map[string]interface{}

	// Events are span events.
	Events []*SpanEvent

	// Links are span links.
	Links []*SpanLink

	// Status is the span status.
	Status SpanStatus

	// StatusMessage is the status message.
	StatusMessage string

	// TraceState is the W3C trace state.
	TraceState string

	// DroppedAttributesCount is the count of dropped attributes.
	DroppedAttributesCount uint32

	// DroppedEventsCount is the count of dropped events.
	DroppedEventsCount uint32

	// DroppedLinksCount is the count of dropped links.
	DroppedLinksCount uint32

	// InstrumentationScope contains scope info.
	InstrumentationScope *InstrumentationScope
}

// SpanKind represents the span kind.
type SpanKind int

const (
	// SpanKindUnspecified is unspecified.
	SpanKindUnspecified SpanKind = iota
	// SpanKindInternal is an internal span.
	SpanKindInternal
	// SpanKindServer is a server span.
	SpanKindServer
	// SpanKindClient is a client span.
	SpanKindClient
	// SpanKindProducer is a producer span.
	SpanKindProducer
	// SpanKindConsumer is a consumer span.
	SpanKindConsumer
)

// String returns the string representation.
func (k SpanKind) String() string {
	switch k {
	case SpanKindInternal:
		return "INTERNAL"
	case SpanKindServer:
		return "SERVER"
	case SpanKindClient:
		return "CLIENT"
	case SpanKindProducer:
		return "PRODUCER"
	case SpanKindConsumer:
		return "CONSUMER"
	default:
		return "UNSPECIFIED"
	}
}

// SpanStatus represents the span status.
type SpanStatus int

const (
	// SpanStatusUnset is unset.
	SpanStatusUnset SpanStatus = iota
	// SpanStatusOK indicates success.
	SpanStatusOK
	// SpanStatusError indicates an error.
	SpanStatusError
)

// String returns the string representation.
func (s SpanStatus) String() string {
	switch s {
	case SpanStatusOK:
		return "OK"
	case SpanStatusError:
		return "ERROR"
	default:
		return "UNSET"
	}
}

// InstrumentationScope represents the instrumentation scope.
type InstrumentationScope struct {
	// Name is the scope name.
	Name string

	// Version is the scope version.
	Version string

	// Attributes are scope attributes.
	Attributes map[string]interface{}

	// DroppedAttributesCount is the count of dropped attributes.
	DroppedAttributesCount uint32
}

// SpanBuilder builds spans.
type SpanBuilder struct {
	span *Span
}

// NewSpanBuilder creates a new span builder.
func NewSpanBuilder(name string) *SpanBuilder {
	return &SpanBuilder{
		span: &Span{
			SpanID:     NewSpanID(),
			Name:       name,
			Kind:       SpanKindInternal,
			StartTime:  time.Now(),
			Attributes: make(map[string]interface{}),
			Events:     make([]*SpanEvent, 0),
			Links:      make([]*SpanLink, 0),
		},
	}
}

// WithTraceID sets the trace ID.
func (b *SpanBuilder) WithTraceID(traceID TraceID) *SpanBuilder {
	b.span.TraceID = traceID
	return b
}

// WithSpanID sets the span ID.
func (b *SpanBuilder) WithSpanID(spanID SpanID) *SpanBuilder {
	b.span.SpanID = spanID
	return b
}

// WithParentSpanID sets the parent span ID.
func (b *SpanBuilder) WithParentSpanID(parentSpanID SpanID) *SpanBuilder {
	b.span.ParentSpanID = parentSpanID
	return b
}

// WithKind sets the span kind.
func (b *SpanBuilder) WithKind(kind SpanKind) *SpanBuilder {
	b.span.Kind = kind
	return b
}

// WithStartTime sets the start time.
func (b *SpanBuilder) WithStartTime(t time.Time) *SpanBuilder {
	b.span.StartTime = t
	return b
}

// WithEndTime sets the end time.
func (b *SpanBuilder) WithEndTime(t time.Time) *SpanBuilder {
	b.span.EndTime = t
	return b
}

// WithAttribute sets an attribute.
func (b *SpanBuilder) WithAttribute(key string, value interface{}) *SpanBuilder {
	b.span.Attributes[key] = value
	return b
}

// WithAttributes sets multiple attributes.
func (b *SpanBuilder) WithAttributes(attrs map[string]interface{}) *SpanBuilder {
	for k, v := range attrs {
		b.span.Attributes[k] = v
	}
	return b
}

// WithEvent adds an event.
func (b *SpanBuilder) WithEvent(event *SpanEvent) *SpanBuilder {
	b.span.Events = append(b.span.Events, event)
	return b
}

// WithLink adds a link.
func (b *SpanBuilder) WithLink(link *SpanLink) *SpanBuilder {
	b.span.Links = append(b.span.Links, link)
	return b
}

// WithLinks adds multiple links.
func (b *SpanBuilder) WithLinks(links []*SpanLink) *SpanBuilder {
	b.span.Links = append(b.span.Links, links...)
	return b
}

// WithStatus sets the status.
func (b *SpanBuilder) WithStatus(status SpanStatus, message string) *SpanBuilder {
	b.span.Status = status
	b.span.StatusMessage = message
	return b
}

// WithStatusOK sets status to OK.
func (b *SpanBuilder) WithStatusOK() *SpanBuilder {
	b.span.Status = SpanStatusOK
	return b
}

// WithStatusError sets status to Error.
func (b *SpanBuilder) WithStatusError(message string) *SpanBuilder {
	b.span.Status = SpanStatusError
	b.span.StatusMessage = message
	return b
}

// WithTraceState sets the trace state.
func (b *SpanBuilder) WithTraceState(traceState string) *SpanBuilder {
	b.span.TraceState = traceState
	return b
}

// WithInstrumentationScope sets the instrumentation scope.
func (b *SpanBuilder) WithInstrumentationScope(scope *InstrumentationScope) *SpanBuilder {
	b.span.InstrumentationScope = scope
	return b
}

// Build returns the built span.
func (b *SpanBuilder) Build() *Span {
	if b.span.EndTime.IsZero() {
		b.span.EndTime = time.Now()
	}
	return b.span
}

// SpanCorrelator correlates spans across services.
type SpanCorrelator struct {
	// Cache for trace contexts.
	cache *TraceContextCache

	// Propagator for context propagation.
	propagator Propagator
}

// NewSpanCorrelator creates a new span correlator.
func NewSpanCorrelator(cacheSize int) *SpanCorrelator {
	return &SpanCorrelator{
		cache:      NewTraceContextCache(cacheSize),
		propagator: NewW3CTraceContextPropagator(),
	}
}

// WithPropagator sets the propagator.
func (c *SpanCorrelator) WithPropagator(propagator Propagator) *SpanCorrelator {
	c.propagator = propagator
	return c
}

// RegisterSpan registers a span for correlation.
func (c *SpanCorrelator) RegisterSpan(span *Span) {
	tc := &TraceContext{
		TraceID:    span.TraceID,
		SpanID:     span.SpanID,
		TraceState: span.TraceState,
	}

	// Store by span ID
	c.cache.Set(span.SpanID.String(), tc)
}

// GetTraceContext returns the trace context for a span ID.
func (c *SpanCorrelator) GetTraceContext(spanID SpanID) (*TraceContext, bool) {
	return c.cache.Get(spanID.String())
}

// LinkSpans creates a link between two spans.
func (c *SpanCorrelator) LinkSpans(from, to *Span) *SpanLink {
	return NewSpanLink(to.TraceID, to.SpanID).
		WithAttribute("link.source.span_id", from.SpanID.String()).
		WithAttribute("link.source.trace_id", from.TraceID.String())
}

// CreateChildSpan creates a child span.
func (c *SpanCorrelator) CreateChildSpan(parent *Span, name string) *Span {
	return NewSpanBuilder(name).
		WithTraceID(parent.TraceID).
		WithParentSpanID(parent.SpanID).
		WithTraceState(parent.TraceState).
		Build()
}

// CreateFollowFromSpan creates a follow-from span (causal but not parent-child).
func (c *SpanCorrelator) CreateFollowFromSpan(parent *Span, name string) *Span {
	link := NewSpanLink(parent.TraceID, parent.SpanID).
		WithAttribute("opentelemetry.link.relationship", "follows_from")

	return NewSpanBuilder(name).
		WithTraceID(parent.TraceID).
		WithLink(link).
		Build()
}
