// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package correlation provides signal correlation for OpenTelemetry.
package correlation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// TraceID represents a W3C Trace Context trace ID.
type TraceID [16]byte

// SpanID represents a W3C Trace Context span ID.
type SpanID [8]byte

// TraceFlags represents W3C Trace Context trace flags.
type TraceFlags byte

const (
	// FlagsSampled indicates the trace is sampled.
	FlagsSampled TraceFlags = 0x01
)

// TraceContext represents W3C Trace Context.
type TraceContext struct {
	TraceID    TraceID
	SpanID     SpanID
	Flags      TraceFlags
	TraceState string
}

// TraceParent represents the traceparent header value.
type TraceParent struct {
	Version    byte
	TraceID    TraceID
	SpanID     SpanID
	TraceFlags TraceFlags
}

// EmptyTraceID is an empty trace ID.
var EmptyTraceID TraceID

// EmptySpanID is an empty span ID.
var EmptySpanID SpanID

// IsValid returns whether the trace ID is valid (non-zero).
func (t TraceID) IsValid() bool {
	return t != EmptyTraceID
}

// String returns the hex string representation.
func (t TraceID) String() string {
	return hex.EncodeToString(t[:])
}

// MarshalJSON implements json.Marshaler.
func (t TraceID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, t.String())), nil
}

// IsValid returns whether the span ID is valid (non-zero).
func (s SpanID) IsValid() bool {
	return s != EmptySpanID
}

// String returns the hex string representation.
func (s SpanID) String() string {
	return hex.EncodeToString(s[:])
}

// MarshalJSON implements json.Marshaler.
func (s SpanID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// IsSampled returns whether the trace is sampled.
func (f TraceFlags) IsSampled() bool {
	return f&FlagsSampled != 0
}

// String returns the hex string representation.
func (f TraceFlags) String() string {
	return fmt.Sprintf("%02x", byte(f))
}

// NewTraceID generates a new random trace ID.
func NewTraceID() TraceID {
	var id TraceID
	_, _ = rand.Read(id[:])
	return id
}

// NewSpanID generates a new random span ID.
func NewSpanID() SpanID {
	var id SpanID
	_, _ = rand.Read(id[:])
	return id
}

// ParseTraceID parses a trace ID from a hex string.
func ParseTraceID(s string) (TraceID, error) {
	var id TraceID
	if len(s) != 32 {
		return id, fmt.Errorf("invalid trace ID length: %d", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("invalid trace ID hex: %w", err)
	}

	copy(id[:], b)
	return id, nil
}

// ParseSpanID parses a span ID from a hex string.
func ParseSpanID(s string) (SpanID, error) {
	var id SpanID
	if len(s) != 16 {
		return id, fmt.Errorf("invalid span ID length: %d", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("invalid span ID hex: %w", err)
	}

	copy(id[:], b)
	return id, nil
}

// ParseTraceParent parses a W3C traceparent header.
func ParseTraceParent(value string) (*TraceParent, error) {
	parts := strings.Split(value, "-")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid traceparent format")
	}

	// Version
	if len(parts[0]) != 2 {
		return nil, fmt.Errorf("invalid version length")
	}

	versionBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid version: %w", err)
	}

	version := versionBytes[0]

	// Check for unsupported version
	if version == 0xff {
		return nil, fmt.Errorf("unsupported version: %02x", version)
	}

	// Trace ID
	traceID, err := ParseTraceID(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parsing trace ID: %w", err)
	}

	// Span ID
	spanID, err := ParseSpanID(parts[2])
	if err != nil {
		return nil, fmt.Errorf("parsing span ID: %w", err)
	}

	// Flags
	if len(parts[3]) != 2 {
		return nil, fmt.Errorf("invalid flags length")
	}

	flagBytes, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid flags: %w", err)
	}

	flags := TraceFlags(flagBytes[0])

	return &TraceParent{
		Version:    version,
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: flags,
	}, nil
}

// String returns the W3C traceparent header value.
func (tp *TraceParent) String() string {
	return fmt.Sprintf("%02x-%s-%s-%02x",
		tp.Version,
		tp.TraceID.String(),
		tp.SpanID.String(),
		byte(tp.TraceFlags),
	)
}

// TraceState represents W3C tracestate header.
type TraceState struct {
	entries []TraceStateEntry
}

// TraceStateEntry is a single tracestate entry.
type TraceStateEntry struct {
	Key   string
	Value string
}

var traceStateKeyRegex = regexp.MustCompile(`^[a-z][a-z0-9_\-*/]{0,255}$`)
var traceStateVendorKeyRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-*/]{0,240}@[a-z][a-z0-9_\-*/]{0,13}$`)
var traceStateValueRegex = regexp.MustCompile(`^[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}[\x21-\x2b\x2d-\x3c\x3e-\x7e]$`)

// ParseTraceState parses a W3C tracestate header.
func ParseTraceState(value string) (*TraceState, error) {
	if value == "" {
		return &TraceState{}, nil
	}

	parts := strings.Split(value, ",")
	entries := make([]TraceStateEntry, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid tracestate entry: %s", part)
		}

		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		// Validate key
		if !traceStateKeyRegex.MatchString(key) && !traceStateVendorKeyRegex.MatchString(key) {
			return nil, fmt.Errorf("invalid tracestate key: %s", key)
		}

		// Validate value
		if val != "" && !traceStateValueRegex.MatchString(val) {
			return nil, fmt.Errorf("invalid tracestate value: %s", val)
		}

		entries = append(entries, TraceStateEntry{Key: key, Value: val})
	}

	// Limit to 32 entries per spec
	if len(entries) > 32 {
		entries = entries[:32]
	}

	return &TraceState{entries: entries}, nil
}

// Get returns the value for a key.
func (ts *TraceState) Get(key string) (string, bool) {
	for _, e := range ts.entries {
		if e.Key == key {
			return e.Value, true
		}
	}
	return "", false
}

// Set sets a value, prepending it to the list.
func (ts *TraceState) Set(key, value string) *TraceState {
	// Remove existing entry with same key
	newEntries := make([]TraceStateEntry, 0, len(ts.entries)+1)
	newEntries = append(newEntries, TraceStateEntry{Key: key, Value: value})

	for _, e := range ts.entries {
		if e.Key != key {
			newEntries = append(newEntries, e)
		}
	}

	// Limit to 32 entries
	if len(newEntries) > 32 {
		newEntries = newEntries[:32]
	}

	return &TraceState{entries: newEntries}
}

// Delete removes an entry.
func (ts *TraceState) Delete(key string) *TraceState {
	newEntries := make([]TraceStateEntry, 0, len(ts.entries))
	for _, e := range ts.entries {
		if e.Key != key {
			newEntries = append(newEntries, e)
		}
	}
	return &TraceState{entries: newEntries}
}

// String returns the W3C tracestate header value.
func (ts *TraceState) String() string {
	if len(ts.entries) == 0 {
		return ""
	}

	parts := make([]string, len(ts.entries))
	for i, e := range ts.entries {
		parts[i] = e.Key + "=" + e.Value
	}

	return strings.Join(parts, ",")
}

// contextKey is the key for trace context in context.Context.
type contextKey struct{}

var traceContextKey = contextKey{}

// ContextWithTraceContext returns a context with trace context.
func ContextWithTraceContext(ctx context.Context, tc *TraceContext) context.Context {
	return context.WithValue(ctx, traceContextKey, tc)
}

// TraceContextFromContext returns the trace context from context.
func TraceContextFromContext(ctx context.Context) *TraceContext {
	if tc, ok := ctx.Value(traceContextKey).(*TraceContext); ok {
		return tc
	}
	return nil
}

// Propagator handles trace context propagation.
type Propagator interface {
	// Inject injects trace context into carrier.
	Inject(ctx context.Context, carrier TextMapCarrier)
	// Extract extracts trace context from carrier.
	Extract(ctx context.Context, carrier TextMapCarrier) context.Context
	// Fields returns the header fields used.
	Fields() []string
}

// TextMapCarrier carries trace context as text.
type TextMapCarrier interface {
	// Get returns the value for a key.
	Get(key string) string
	// Set sets a key-value pair.
	Set(key, value string)
	// Keys returns all keys.
	Keys() []string
}

// W3CTraceContextPropagator implements W3C Trace Context propagation.
type W3CTraceContextPropagator struct{}

// NewW3CTraceContextPropagator creates a new propagator.
func NewW3CTraceContextPropagator() *W3CTraceContextPropagator {
	return &W3CTraceContextPropagator{}
}

// Inject injects trace context into carrier.
func (p *W3CTraceContextPropagator) Inject(ctx context.Context, carrier TextMapCarrier) {
	tc := TraceContextFromContext(ctx)
	if tc == nil || !tc.TraceID.IsValid() {
		return
	}

	tp := &TraceParent{
		Version:    0x00,
		TraceID:    tc.TraceID,
		SpanID:     tc.SpanID,
		TraceFlags: tc.Flags,
	}

	carrier.Set("traceparent", tp.String())

	if tc.TraceState != "" {
		carrier.Set("tracestate", tc.TraceState)
	}
}

// Extract extracts trace context from carrier.
func (p *W3CTraceContextPropagator) Extract(ctx context.Context, carrier TextMapCarrier) context.Context {
	traceparent := carrier.Get("traceparent")
	if traceparent == "" {
		return ctx
	}

	tp, err := ParseTraceParent(traceparent)
	if err != nil {
		return ctx
	}

	if !tp.TraceID.IsValid() || !tp.SpanID.IsValid() {
		return ctx
	}

	tc := &TraceContext{
		TraceID:    tp.TraceID,
		SpanID:     tp.SpanID,
		Flags:      tp.TraceFlags,
		TraceState: carrier.Get("tracestate"),
	}

	return ContextWithTraceContext(ctx, tc)
}

// Fields returns the header fields used.
func (p *W3CTraceContextPropagator) Fields() []string {
	return []string{"traceparent", "tracestate"}
}

// MapCarrier implements TextMapCarrier for map[string]string.
type MapCarrier map[string]string

// Get returns the value for a key.
func (c MapCarrier) Get(key string) string {
	return c[strings.ToLower(key)]
}

// Set sets a key-value pair.
func (c MapCarrier) Set(key, value string) {
	c[strings.ToLower(key)] = value
}

// Keys returns all keys.
func (c MapCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	return keys
}

// CompositePropagator combines multiple propagators.
type CompositePropagator struct {
	propagators []Propagator
}

// NewCompositePropagator creates a composite propagator.
func NewCompositePropagator(propagators ...Propagator) *CompositePropagator {
	return &CompositePropagator{propagators: propagators}
}

// Inject injects using all propagators.
func (p *CompositePropagator) Inject(ctx context.Context, carrier TextMapCarrier) {
	for _, prop := range p.propagators {
		prop.Inject(ctx, carrier)
	}
}

// Extract extracts using all propagators.
func (p *CompositePropagator) Extract(ctx context.Context, carrier TextMapCarrier) context.Context {
	for _, prop := range p.propagators {
		ctx = prop.Extract(ctx, carrier)
	}
	return ctx
}

// Fields returns all header fields.
func (p *CompositePropagator) Fields() []string {
	var fields []string
	seen := make(map[string]bool)

	for _, prop := range p.propagators {
		for _, f := range prop.Fields() {
			if !seen[f] {
				fields = append(fields, f)
				seen[f] = true
			}
		}
	}

	return fields
}

// TraceIDRatioBased implements ratio-based trace ID sampling.
type TraceIDRatioBased struct {
	ratio float64
	bound uint64
}

// NewTraceIDRatioBased creates a ratio-based sampler.
func NewTraceIDRatioBased(ratio float64) *TraceIDRatioBased {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	return &TraceIDRatioBased{
		ratio: ratio,
		bound: uint64(ratio * float64(1<<63)),
	}
}

// ShouldSample returns whether a trace ID should be sampled.
func (s *TraceIDRatioBased) ShouldSample(traceID TraceID) bool {
	// Use last 8 bytes of trace ID as random source
	x := uint64(traceID[8])<<56 |
		uint64(traceID[9])<<48 |
		uint64(traceID[10])<<40 |
		uint64(traceID[11])<<32 |
		uint64(traceID[12])<<24 |
		uint64(traceID[13])<<16 |
		uint64(traceID[14])<<8 |
		uint64(traceID[15])

	return x < s.bound
}

// TraceContextCache caches trace contexts for correlation.
type TraceContextCache struct {
	mu       sync.RWMutex
	contexts map[string]*TraceContext
	maxSize  int
}

// NewTraceContextCache creates a new cache.
func NewTraceContextCache(maxSize int) *TraceContextCache {
	return &TraceContextCache{
		contexts: make(map[string]*TraceContext),
		maxSize:  maxSize,
	}
}

// Set stores a trace context.
func (c *TraceContextCache) Set(key string, tc *TraceContext) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: clear half when full
	if len(c.contexts) >= c.maxSize {
		count := 0
		for k := range c.contexts {
			delete(c.contexts, k)
			count++
			if count >= c.maxSize/2 {
				break
			}
		}
	}

	c.contexts[key] = tc
}

// Get retrieves a trace context.
func (c *TraceContextCache) Get(key string) (*TraceContext, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tc, ok := c.contexts[key]
	return tc, ok
}

// Delete removes a trace context.
func (c *TraceContextCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.contexts, key)
}
