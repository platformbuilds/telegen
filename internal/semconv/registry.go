// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package semconv provides OpenTelemetry semantic convention helpers for Telegen.
// This registry follows OTel semantic conventions v1.27.0.
package semconv

import (
	"sync"

	"go.opentelemetry.io/otel/attribute"
)

// Version is the semantic convention version this package implements.
const Version = "1.27.0"

// SchemaURL is the schema URL for this version of semantic conventions.
const SchemaURL = "https://opentelemetry.io/schemas/1.27.0"

// Registry is the central registry for all OpenTelemetry semantic conventions.
// It provides a unified interface to access and validate semantic convention attributes.
type Registry struct {
	mu sync.RWMutex

	// Registered attribute definitions
	attributes map[string]*AttributeDefinition

	// Registered metric definitions
	metrics map[string]*MetricDefinition

	// Registered span definitions
	spans map[string]*SpanDefinition
}

// AttributeDefinition defines a semantic convention attribute.
type AttributeDefinition struct {
	// Key is the attribute key
	Key string

	// Type is the attribute value type
	Type AttributeType

	// Requirement level (required, conditionally_required, recommended, opt_in)
	Requirement RequirementLevel

	// Brief description of the attribute
	Brief string

	// Note provides additional context
	Note string

	// Examples of valid values
	Examples []string

	// Deprecated indicates if this attribute is deprecated
	Deprecated bool

	// DeprecatedNote explains the deprecation
	DeprecatedNote string

	// Stability level (stable, experimental)
	Stability StabilityLevel
}

// MetricDefinition defines a semantic convention metric.
type MetricDefinition struct {
	// Name is the metric name
	Name string

	// Type is the metric instrument type
	Type MetricType

	// Unit is the metric unit
	Unit string

	// Brief description of the metric
	Brief string

	// Attributes that apply to this metric
	Attributes []string

	// Stability level
	Stability StabilityLevel
}

// SpanDefinition defines a semantic convention span.
type SpanDefinition struct {
	// Name is the span name
	Name string

	// Kind is the span kind (client, server, producer, consumer, internal)
	Kind SpanKind

	// Brief description
	Brief string

	// Attributes that apply to this span
	Attributes []string

	// Events that can be added to this span
	Events []string
}

// AttributeType represents the type of an attribute value.
type AttributeType string

const (
	AttributeTypeString      AttributeType = "string"
	AttributeTypeInt         AttributeType = "int"
	AttributeTypeDouble      AttributeType = "double"
	AttributeTypeBool        AttributeType = "boolean"
	AttributeTypeStringArray AttributeType = "string[]"
	AttributeTypeIntArray    AttributeType = "int[]"
	AttributeTypeDoubleArray AttributeType = "double[]"
	AttributeTypeBoolArray   AttributeType = "boolean[]"
)

// RequirementLevel indicates how required an attribute is.
type RequirementLevel string

const (
	RequirementRequired              RequirementLevel = "required"
	RequirementConditionallyRequired RequirementLevel = "conditionally_required"
	RequirementRecommended           RequirementLevel = "recommended"
	RequirementOptIn                 RequirementLevel = "opt_in"
)

// StabilityLevel indicates the stability of a semantic convention.
type StabilityLevel string

const (
	StabilityStable       StabilityLevel = "stable"
	StabilityExperimental StabilityLevel = "experimental"
	StabilityDeprecated   StabilityLevel = "deprecated"
)

// MetricType represents the type of metric instrument.
type MetricType string

const (
	MetricTypeCounter         MetricType = "counter"
	MetricTypeUpDownCounter   MetricType = "updowncounter"
	MetricTypeHistogram       MetricType = "histogram"
	MetricTypeGauge           MetricType = "gauge"
	MetricTypeObservableGauge MetricType = "observable_gauge"
)

// SpanKind represents the kind of span.
type SpanKind string

const (
	SpanKindClient   SpanKind = "client"
	SpanKindServer   SpanKind = "server"
	SpanKindProducer SpanKind = "producer"
	SpanKindConsumer SpanKind = "consumer"
	SpanKindInternal SpanKind = "internal"
)

// globalRegistry is the singleton registry instance
var globalRegistry *Registry
var registryOnce sync.Once

// Global returns the global semantic convention registry.
func Global() *Registry {
	registryOnce.Do(func() {
		globalRegistry = NewRegistry()
		globalRegistry.registerBuiltinConventions()
	})
	return globalRegistry
}

// NewRegistry creates a new semantic convention registry.
func NewRegistry() *Registry {
	return &Registry{
		attributes: make(map[string]*AttributeDefinition),
		metrics:    make(map[string]*MetricDefinition),
		spans:      make(map[string]*SpanDefinition),
	}
}

// RegisterAttribute registers an attribute definition.
func (r *Registry) RegisterAttribute(def *AttributeDefinition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attributes[def.Key] = def
}

// RegisterMetric registers a metric definition.
func (r *Registry) RegisterMetric(def *MetricDefinition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metrics[def.Name] = def
}

// RegisterSpan registers a span definition.
func (r *Registry) RegisterSpan(def *SpanDefinition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans[def.Name] = def
}

// GetAttribute returns an attribute definition by key.
func (r *Registry) GetAttribute(key string) (*AttributeDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.attributes[key]
	return def, ok
}

// GetMetric returns a metric definition by name.
func (r *Registry) GetMetric(name string) (*MetricDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.metrics[name]
	return def, ok
}

// GetSpan returns a span definition by name.
func (r *Registry) GetSpan(name string) (*SpanDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.spans[name]
	return def, ok
}

// AllAttributes returns all registered attribute definitions.
func (r *Registry) AllAttributes() []*AttributeDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	attrs := make([]*AttributeDefinition, 0, len(r.attributes))
	for _, def := range r.attributes {
		attrs = append(attrs, def)
	}
	return attrs
}

// AllMetrics returns all registered metric definitions.
func (r *Registry) AllMetrics() []*MetricDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	metrics := make([]*MetricDefinition, 0, len(r.metrics))
	for _, def := range r.metrics {
		metrics = append(metrics, def)
	}
	return metrics
}

// AllSpans returns all registered span definitions.
func (r *Registry) AllSpans() []*SpanDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	spans := make([]*SpanDefinition, 0, len(r.spans))
	for _, def := range r.spans {
		spans = append(spans, def)
	}
	return spans
}

// AttributesForCategory returns all attributes matching a category prefix.
func (r *Registry) AttributesForCategory(prefix string) []*AttributeDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	attrs := make([]*AttributeDefinition, 0)
	for key, def := range r.attributes {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			attrs = append(attrs, def)
		}
	}
	return attrs
}

// registerBuiltinConventions registers all built-in semantic conventions.
func (r *Registry) registerBuiltinConventions() {
	// Register resource attributes
	registerResourceAttributes(r)

	// Register HTTP attributes
	registerHTTPAttributes(r)

	// Register database attributes
	registerDatabaseAttributes(r)

	// Register network attributes
	registerNetworkAttributes(r)

	// Register process attributes
	registerProcessAttributes(r)

	// Register GenAI attributes
	registerGenAIAttributes(r)

	// Register metrics
	registerMetrics(r)
}

// AttributeBuilder helps build attribute key-value pairs.
type AttributeBuilder struct {
	attrs []attribute.KeyValue
}

// NewAttributeBuilder creates a new attribute builder.
func NewAttributeBuilder() *AttributeBuilder {
	return &AttributeBuilder{
		attrs: make([]attribute.KeyValue, 0, 16),
	}
}

// Add adds a string attribute.
func (b *AttributeBuilder) Add(key string, value string) *AttributeBuilder {
	if value != "" {
		b.attrs = append(b.attrs, attribute.String(key, value))
	}
	return b
}

// AddInt adds an integer attribute.
func (b *AttributeBuilder) AddInt(key string, value int64) *AttributeBuilder {
	b.attrs = append(b.attrs, attribute.Int64(key, value))
	return b
}

// AddFloat adds a float attribute.
func (b *AttributeBuilder) AddFloat(key string, value float64) *AttributeBuilder {
	b.attrs = append(b.attrs, attribute.Float64(key, value))
	return b
}

// AddBool adds a boolean attribute.
func (b *AttributeBuilder) AddBool(key string, value bool) *AttributeBuilder {
	b.attrs = append(b.attrs, attribute.Bool(key, value))
	return b
}

// AddStringSlice adds a string slice attribute.
func (b *AttributeBuilder) AddStringSlice(key string, value []string) *AttributeBuilder {
	if len(value) > 0 {
		b.attrs = append(b.attrs, attribute.StringSlice(key, value))
	}
	return b
}

// Build returns the built attributes.
func (b *AttributeBuilder) Build() []attribute.KeyValue {
	return b.attrs
}

// Merge merges another set of attributes.
func (b *AttributeBuilder) Merge(other []attribute.KeyValue) *AttributeBuilder {
	b.attrs = append(b.attrs, other...)
	return b
}
