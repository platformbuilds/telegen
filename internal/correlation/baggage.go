// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// BaggageMember represents a single baggage member (key-value pair with optional metadata).
type BaggageMember struct {
	// Key is the member key.
	Key string

	// Value is the member value (percent-encoded).
	Value string

	// Properties are optional properties associated with this member.
	Properties []BaggageProperty
}

// BaggageProperty represents a property of a baggage member.
type BaggageProperty struct {
	Key   string
	Value string // Empty string means key-only property
}

// Baggage represents W3C Baggage header content.
// See: https://www.w3.org/TR/baggage/
type Baggage struct {
	members []BaggageMember
	mu      sync.RWMutex
}

// baggage key validation regex per W3C spec
var (
	baggageTokenRegex = regexp.MustCompile(`^[a-zA-Z0-9!#$%&'*+\-.^_\x60|~]+$`)
	baggageKeyRegex   = baggageTokenRegex
)

// NewBaggage creates an empty baggage.
func NewBaggage() *Baggage {
	return &Baggage{
		members: make([]BaggageMember, 0),
	}
}

// ParseBaggage parses a W3C baggage header value.
func ParseBaggage(value string) (*Baggage, error) {
	if value == "" {
		return NewBaggage(), nil
	}

	bag := NewBaggage()

	// Split by list-member delimiter (comma)
	memberStrs := strings.Split(value, ",")

	for _, memberStr := range memberStrs {
		memberStr = strings.TrimSpace(memberStr)
		if memberStr == "" {
			continue
		}

		member, err := parseBaggageMember(memberStr)
		if err != nil {
			// Per spec, skip invalid members
			continue
		}

		bag.members = append(bag.members, *member)
	}

	// W3C spec limits to 180 members, 4096 bytes per member, 8192 bytes total
	if len(bag.members) > 180 {
		bag.members = bag.members[:180]
	}

	return bag, nil
}

// parseBaggageMember parses a single baggage member.
func parseBaggageMember(memberStr string) (*BaggageMember, error) {
	// Split by property delimiter (semicolon)
	parts := strings.Split(memberStr, ";")
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty member")
	}

	// First part is key=value
	kv := strings.SplitN(parts[0], "=", 2)
	if len(kv) != 2 {
		return nil, fmt.Errorf("invalid key-value pair: %s", parts[0])
	}

	key := strings.TrimSpace(kv[0])
	encodedValue := strings.TrimSpace(kv[1])

	// Validate key
	if !baggageKeyRegex.MatchString(key) {
		return nil, fmt.Errorf("invalid baggage key: %s", key)
	}

	// Decode value (percent-encoded)
	value, err := url.QueryUnescape(encodedValue)
	if err != nil {
		value = encodedValue // Use raw value if decoding fails
	}

	member := &BaggageMember{
		Key:        key,
		Value:      value,
		Properties: make([]BaggageProperty, 0),
	}

	// Parse properties (remaining parts)
	for i := 1; i < len(parts); i++ {
		propStr := strings.TrimSpace(parts[i])
		if propStr == "" {
			continue
		}

		prop := parseBaggageProperty(propStr)
		member.Properties = append(member.Properties, prop)
	}

	return member, nil
}

// parseBaggageProperty parses a baggage property.
func parseBaggageProperty(propStr string) BaggageProperty {
	kv := strings.SplitN(propStr, "=", 2)
	key := strings.TrimSpace(kv[0])

	if len(kv) == 2 {
		return BaggageProperty{
			Key:   key,
			Value: strings.TrimSpace(kv[1]),
		}
	}

	return BaggageProperty{Key: key}
}

// Get returns the value for a key.
func (b *Baggage) Get(key string) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, m := range b.members {
		if m.Key == key {
			return m.Value, true
		}
	}
	return "", false
}

// Set sets a baggage member.
func (b *Baggage) Set(key, value string) error {
	if !baggageKeyRegex.MatchString(key) {
		return fmt.Errorf("invalid baggage key: %s", key)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Remove existing with same key
	newMembers := make([]BaggageMember, 0, len(b.members)+1)
	for _, m := range b.members {
		if m.Key != key {
			newMembers = append(newMembers, m)
		}
	}

	// Add new member
	newMembers = append(newMembers, BaggageMember{
		Key:   key,
		Value: value,
	})

	// Check limits
	if len(newMembers) > 180 {
		return fmt.Errorf("baggage member limit exceeded")
	}

	b.members = newMembers
	return nil
}

// SetWithProperties sets a baggage member with properties.
func (b *Baggage) SetWithProperties(key, value string, properties []BaggageProperty) error {
	if !baggageKeyRegex.MatchString(key) {
		return fmt.Errorf("invalid baggage key: %s", key)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Remove existing with same key
	newMembers := make([]BaggageMember, 0, len(b.members)+1)
	for _, m := range b.members {
		if m.Key != key {
			newMembers = append(newMembers, m)
		}
	}

	// Add new member
	newMembers = append(newMembers, BaggageMember{
		Key:        key,
		Value:      value,
		Properties: properties,
	})

	if len(newMembers) > 180 {
		return fmt.Errorf("baggage member limit exceeded")
	}

	b.members = newMembers
	return nil
}

// Delete removes a baggage member.
func (b *Baggage) Delete(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	newMembers := make([]BaggageMember, 0, len(b.members))
	for _, m := range b.members {
		if m.Key != key {
			newMembers = append(newMembers, m)
		}
	}
	b.members = newMembers
}

// Members returns all members.
func (b *Baggage) Members() []BaggageMember {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]BaggageMember, len(b.members))
	copy(result, b.members)
	return result
}

// Len returns the number of members.
func (b *Baggage) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.members)
}

// String returns the W3C baggage header value.
func (b *Baggage) String() string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.members) == 0 {
		return ""
	}

	parts := make([]string, len(b.members))
	for i, m := range b.members {
		parts[i] = m.String()
	}

	return strings.Join(parts, ",")
}

// String returns the member as a baggage header component.
func (m BaggageMember) String() string {
	// Percent-encode the value
	encodedValue := url.QueryEscape(m.Value)

	result := m.Key + "=" + encodedValue

	for _, p := range m.Properties {
		if p.Value != "" {
			result += ";" + p.Key + "=" + p.Value
		} else {
			result += ";" + p.Key
		}
	}

	return result
}

// ToMap converts baggage to a map.
func (b *Baggage) ToMap() map[string]string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[string]string, len(b.members))
	for _, m := range b.members {
		result[m.Key] = m.Value
	}
	return result
}

// FromMap creates baggage from a map.
func FromMap(m map[string]string) *Baggage {
	bag := NewBaggage()
	for k, v := range m {
		_ = bag.Set(k, v)
	}
	return bag
}

// baggageContextKey is the key for baggage in context.Context.
type baggageContextKey struct{}

var baggageKey = baggageContextKey{}

// ContextWithBaggage returns a context with baggage.
func ContextWithBaggage(ctx context.Context, bag *Baggage) context.Context {
	return context.WithValue(ctx, baggageKey, bag)
}

// BaggageFromContext returns the baggage from context.
func BaggageFromContext(ctx context.Context) *Baggage {
	if bag, ok := ctx.Value(baggageKey).(*Baggage); ok {
		return bag
	}
	return nil
}

// W3CBaggagePropagator implements W3C Baggage propagation.
type W3CBaggagePropagator struct{}

// NewW3CBaggagePropagator creates a new baggage propagator.
func NewW3CBaggagePropagator() *W3CBaggagePropagator {
	return &W3CBaggagePropagator{}
}

// Inject injects baggage into carrier.
func (p *W3CBaggagePropagator) Inject(ctx context.Context, carrier TextMapCarrier) {
	bag := BaggageFromContext(ctx)
	if bag == nil || bag.Len() == 0 {
		return
	}

	carrier.Set("baggage", bag.String())
}

// Extract extracts baggage from carrier.
func (p *W3CBaggagePropagator) Extract(ctx context.Context, carrier TextMapCarrier) context.Context {
	baggageHeader := carrier.Get("baggage")
	if baggageHeader == "" {
		return ctx
	}

	bag, err := ParseBaggage(baggageHeader)
	if err != nil {
		return ctx
	}

	return ContextWithBaggage(ctx, bag)
}

// Fields returns the header fields used.
func (p *W3CBaggagePropagator) Fields() []string {
	return []string{"baggage"}
}

// BaggageInterceptor intercepts and modifies baggage during propagation.
type BaggageInterceptor interface {
	// InterceptExtract is called after extracting baggage, allowing modification.
	InterceptExtract(bag *Baggage) *Baggage

	// InterceptInject is called before injecting baggage, allowing modification.
	InterceptInject(bag *Baggage) *Baggage
}

// InterceptingBaggagePropagator wraps a propagator with interceptors.
type InterceptingBaggagePropagator struct {
	inner       *W3CBaggagePropagator
	interceptor BaggageInterceptor
}

// NewInterceptingBaggagePropagator creates an intercepting propagator.
func NewInterceptingBaggagePropagator(interceptor BaggageInterceptor) *InterceptingBaggagePropagator {
	return &InterceptingBaggagePropagator{
		inner:       NewW3CBaggagePropagator(),
		interceptor: interceptor,
	}
}

// Inject injects baggage with interception.
func (p *InterceptingBaggagePropagator) Inject(ctx context.Context, carrier TextMapCarrier) {
	bag := BaggageFromContext(ctx)
	if bag != nil && p.interceptor != nil {
		bag = p.interceptor.InterceptInject(bag)
		ctx = ContextWithBaggage(ctx, bag)
	}
	p.inner.Inject(ctx, carrier)
}

// Extract extracts baggage with interception.
func (p *InterceptingBaggagePropagator) Extract(ctx context.Context, carrier TextMapCarrier) context.Context {
	ctx = p.inner.Extract(ctx, carrier)

	if p.interceptor != nil {
		bag := BaggageFromContext(ctx)
		if bag != nil {
			bag = p.interceptor.InterceptExtract(bag)
			ctx = ContextWithBaggage(ctx, bag)
		}
	}

	return ctx
}

// Fields returns the header fields used.
func (p *InterceptingBaggagePropagator) Fields() []string {
	return p.inner.Fields()
}

// BaggageCache caches baggage for correlation.
type BaggageCache struct {
	mu      sync.RWMutex
	cache   map[string]*Baggage
	maxSize int
}

// NewBaggageCache creates a new baggage cache.
func NewBaggageCache(maxSize int) *BaggageCache {
	return &BaggageCache{
		cache:   make(map[string]*Baggage),
		maxSize: maxSize,
	}
}

// Set stores baggage by trace ID.
func (c *BaggageCache) Set(traceID TraceID, bag *Baggage) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := traceID.String()

	// Simple eviction: clear half when full
	if len(c.cache) >= c.maxSize {
		count := 0
		for k := range c.cache {
			delete(c.cache, k)
			count++
			if count >= c.maxSize/2 {
				break
			}
		}
	}

	c.cache[key] = bag
}

// Get retrieves baggage by trace ID.
func (c *BaggageCache) Get(traceID TraceID) (*Baggage, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	bag, ok := c.cache[traceID.String()]
	return bag, ok
}

// Delete removes baggage.
func (c *BaggageCache) Delete(traceID TraceID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, traceID.String())
}

// MergeBaggage merges two baggage instances (b2 overwrites b1 on conflicts).
func MergeBaggage(b1, b2 *Baggage) *Baggage {
	if b1 == nil {
		return b2
	}
	if b2 == nil {
		return b1
	}

	result := NewBaggage()

	// Add all from b1
	for _, m := range b1.Members() {
		_ = result.SetWithProperties(m.Key, m.Value, m.Properties)
	}

	// Add/overwrite from b2
	for _, m := range b2.Members() {
		_ = result.SetWithProperties(m.Key, m.Value, m.Properties)
	}

	return result
}

// ValidateBaggageKey checks if a key is valid per W3C spec.
func ValidateBaggageKey(key string) bool {
	return baggageKeyRegex.MatchString(key)
}

// ValidateBaggageValue checks if a value is valid per W3C spec.
func ValidateBaggageValue(value string) bool {
	// Value can be any printable ASCII except comma, semicolon, and backslash
	for _, c := range value {
		if c < 32 || c > 126 || c == ',' || c == ';' || c == '\\' {
			return false
		}
	}
	return true
}
