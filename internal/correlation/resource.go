// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Resource represents a resource with attributes for signal correlation.
type Resource struct {
	// SchemaURL is the schema URL for the resource.
	SchemaURL string

	// Attributes are the resource attributes.
	Attributes map[string]interface{}
}

// NewResource creates a new resource.
func NewResource() *Resource {
	return &Resource{
		Attributes: make(map[string]interface{}),
	}
}

// WithSchemaURL sets the schema URL.
func (r *Resource) WithSchemaURL(url string) *Resource {
	r.SchemaURL = url
	return r
}

// WithAttribute sets an attribute.
func (r *Resource) WithAttribute(key string, value interface{}) *Resource {
	r.Attributes[key] = value
	return r
}

// WithAttributes sets multiple attributes.
func (r *Resource) WithAttributes(attrs map[string]interface{}) *Resource {
	for k, v := range attrs {
		r.Attributes[k] = v
	}
	return r
}

// ServiceName returns the service name.
func (r *Resource) ServiceName() string {
	if v, ok := r.Attributes[string(semconv.ServiceNameKey)].(string); ok {
		return v
	}
	return ""
}

// ServiceNamespace returns the service namespace.
func (r *Resource) ServiceNamespace() string {
	if v, ok := r.Attributes[string(semconv.ServiceNamespaceKey)].(string); ok {
		return v
	}
	return ""
}

// ServiceVersion returns the service version.
func (r *Resource) ServiceVersion() string {
	if v, ok := r.Attributes[string(semconv.ServiceVersionKey)].(string); ok {
		return v
	}
	return ""
}

// ServiceInstanceID returns the service instance ID.
func (r *Resource) ServiceInstanceID() string {
	if v, ok := r.Attributes[string(semconv.ServiceInstanceIDKey)].(string); ok {
		return v
	}
	return ""
}

// Merge merges another resource into this one (other takes precedence).
func (r *Resource) Merge(other *Resource) *Resource {
	if other == nil {
		return r
	}

	merged := NewResource()

	// Copy current attributes
	for k, v := range r.Attributes {
		merged.Attributes[k] = v
	}

	// Overlay other attributes
	for k, v := range other.Attributes {
		merged.Attributes[k] = v
	}

	// Use other's schema if present
	if other.SchemaURL != "" {
		merged.SchemaURL = other.SchemaURL
	} else {
		merged.SchemaURL = r.SchemaURL
	}

	return merged
}

// ToOTELAttributes converts to OTEL attributes.
func (r *Resource) ToOTELAttributes() []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(r.Attributes))
	for k, v := range r.Attributes {
		attrs = append(attrs, convertToAttribute(k, v))
	}
	return attrs
}

// ResourceIdentity provides a unique identity for a resource.
type ResourceIdentity struct {
	ServiceName      string
	ServiceNamespace string
	ServiceInstance  string
	HostID           string
	ContainerID      string
	PodName          string
	PodUID           string
	K8sNamespace     string
}

// Key returns a unique key for the identity.
func (ri *ResourceIdentity) Key() string {
	// Use service identity components for key
	key := ri.ServiceName
	if ri.ServiceNamespace != "" {
		key = ri.ServiceNamespace + "/" + key
	}
	if ri.K8sNamespace != "" {
		key = ri.K8sNamespace + ":" + key
	}
	if ri.ServiceInstance != "" {
		key = key + "@" + ri.ServiceInstance
	}
	return key
}

// ResourceCorrelator correlates resources across signals.
type ResourceCorrelator struct {
	mu        sync.RWMutex
	resources map[string]*Resource
	identity  map[string]*ResourceIdentity
	log       *slog.Logger

	// Default resource to use when none found
	defaultResource *Resource

	// Resource discovery callbacks
	onDiscover []func(*ResourceIdentity, *Resource)
}

// NewResourceCorrelator creates a new resource correlator.
func NewResourceCorrelator(log *slog.Logger) *ResourceCorrelator {
	if log == nil {
		log = slog.Default()
	}

	return &ResourceCorrelator{
		resources:       make(map[string]*Resource),
		identity:        make(map[string]*ResourceIdentity),
		log:             log.With("component", "resource_correlator"),
		defaultResource: NewResource(),
		onDiscover:      make([]func(*ResourceIdentity, *Resource), 0),
	}
}

// SetDefaultResource sets the default resource.
func (rc *ResourceCorrelator) SetDefaultResource(r *Resource) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.defaultResource = r
}

// OnDiscover registers a callback for resource discovery.
func (rc *ResourceCorrelator) OnDiscover(fn func(*ResourceIdentity, *Resource)) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.onDiscover = append(rc.onDiscover, fn)
}

// Register registers a resource with its identity.
func (rc *ResourceCorrelator) Register(identity *ResourceIdentity, resource *Resource) {
	if identity == nil || resource == nil {
		return
	}

	key := identity.Key()

	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.resources[key] = resource
	rc.identity[key] = identity

	// Notify callbacks
	for _, fn := range rc.onDiscover {
		go fn(identity, resource)
	}

	rc.log.Debug("registered resource",
		"key", key,
		"service", identity.ServiceName,
		"namespace", identity.ServiceNamespace,
	)
}

// Get retrieves a resource by identity key.
func (rc *ResourceCorrelator) Get(key string) (*Resource, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	r, ok := rc.resources[key]
	return r, ok
}

// GetByService retrieves a resource by service name.
func (rc *ResourceCorrelator) GetByService(serviceName, namespace string) (*Resource, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	// Try with namespace prefix first
	if namespace != "" {
		for key, id := range rc.identity {
			if id.ServiceName == serviceName && id.ServiceNamespace == namespace {
				return rc.resources[key], true
			}
		}
	}

	// Fall back to service name only
	for key, id := range rc.identity {
		if id.ServiceName == serviceName {
			return rc.resources[key], true
		}
	}

	return nil, false
}

// GetByContainerID retrieves a resource by container ID.
func (rc *ResourceCorrelator) GetByContainerID(containerID string) (*Resource, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	for key, id := range rc.identity {
		if id.ContainerID == containerID {
			return rc.resources[key], true
		}
	}

	return nil, false
}

// GetByPod retrieves a resource by pod information.
func (rc *ResourceCorrelator) GetByPod(namespace, podName string) (*Resource, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	for key, id := range rc.identity {
		if id.K8sNamespace == namespace && id.PodName == podName {
			return rc.resources[key], true
		}
	}

	return nil, false
}

// GetDefault returns the default resource.
func (rc *ResourceCorrelator) GetDefault() *Resource {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.defaultResource
}

// MergeWithDefault merges the given resource with the default.
func (rc *ResourceCorrelator) MergeWithDefault(r *Resource) *Resource {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.defaultResource.Merge(r)
}

// CorrelatedContext holds correlation information across signals.
type CorrelatedContext struct {
	// TraceContext is the trace context.
	TraceContext *TraceContext

	// Baggage is the baggage.
	Baggage *Baggage

	// Resource is the resource.
	Resource *Resource

	// Timestamp is when this context was created.
	Timestamp time.Time

	// Attributes are additional attributes.
	Attributes map[string]interface{}
}

// NewCorrelatedContext creates a new correlated context.
func NewCorrelatedContext() *CorrelatedContext {
	return &CorrelatedContext{
		Timestamp:  time.Now(),
		Attributes: make(map[string]interface{}),
	}
}

// WithTraceContext sets the trace context.
func (cc *CorrelatedContext) WithTraceContext(tc *TraceContext) *CorrelatedContext {
	cc.TraceContext = tc
	return cc
}

// WithBaggage sets the baggage.
func (cc *CorrelatedContext) WithBaggage(bag *Baggage) *CorrelatedContext {
	cc.Baggage = bag
	return cc
}

// WithResource sets the resource.
func (cc *CorrelatedContext) WithResource(r *Resource) *CorrelatedContext {
	cc.Resource = r
	return cc
}

// WithAttribute sets an attribute.
func (cc *CorrelatedContext) WithAttribute(key string, value interface{}) *CorrelatedContext {
	cc.Attributes[key] = value
	return cc
}

// IsValid returns whether the context has valid trace information.
func (cc *CorrelatedContext) IsValid() bool {
	return cc.TraceContext != nil && cc.TraceContext.TraceID.IsValid()
}

// correlatedContextKey is the key for correlated context in context.Context.
type correlatedContextKey struct{}

var corrCtxKey = correlatedContextKey{}

// ContextWithCorrelatedContext returns a context with correlated context.
func ContextWithCorrelatedContext(ctx context.Context, cc *CorrelatedContext) context.Context {
	return context.WithValue(ctx, corrCtxKey, cc)
}

// CorrelatedContextFromContext returns the correlated context from context.
func CorrelatedContextFromContext(ctx context.Context) *CorrelatedContext {
	if cc, ok := ctx.Value(corrCtxKey).(*CorrelatedContext); ok {
		return cc
	}
	return nil
}

// SignalCorrelator correlates traces, logs, and metrics.
type SignalCorrelator struct {
	resourceCorrelator *ResourceCorrelator
	traceCache         *TraceContextCache
	baggageCache       *BaggageCache
	logCorrelator      *LogTraceCorrelator
	exemplarStore      *ExemplarStore
	log                *slog.Logger
}

// NewSignalCorrelator creates a new signal correlator.
func NewSignalCorrelator(log *slog.Logger) *SignalCorrelator {
	if log == nil {
		log = slog.Default()
	}

	return &SignalCorrelator{
		resourceCorrelator: NewResourceCorrelator(log),
		traceCache:         NewTraceContextCache(10000),
		baggageCache:       NewBaggageCache(10000),
		logCorrelator:      GetGlobalLogTraceCorrelator(),
		exemplarStore:      GetGlobalExemplarStore(),
		log:                log.With("component", "signal_correlator"),
	}
}

// CorrelateSpan correlates a span with resource information.
func (sc *SignalCorrelator) CorrelateSpan(tc *TraceContext, serviceName, namespace string) *CorrelatedContext {
	cc := NewCorrelatedContext().WithTraceContext(tc)

	// Get resource
	if resource, ok := sc.resourceCorrelator.GetByService(serviceName, namespace); ok {
		cc.WithResource(resource)
	} else {
		cc.WithResource(sc.resourceCorrelator.GetDefault())
	}

	// Get baggage
	if bag, ok := sc.baggageCache.Get(tc.TraceID); ok {
		cc.WithBaggage(bag)
	}

	// Cache trace context
	sc.traceCache.Set(tc.TraceID.String(), tc)

	return cc
}

// CorrelateLog correlates a log with trace and resource information.
func (sc *SignalCorrelator) CorrelateLog(containerID string, timestamp time.Time, level string) *CorrelatedContext {
	cc := NewCorrelatedContext()
	cc.Timestamp = timestamp

	// Try to get trace context from log correlator
	traceIDStr, spanIDStr, found := sc.logCorrelator.LookupTraceContext(containerID, timestamp, time.Second)
	if found {
		traceID, err := ParseTraceID(traceIDStr)
		if err == nil {
			spanID, _ := ParseSpanID(spanIDStr)
			tc := &TraceContext{
				TraceID: traceID,
				SpanID:  spanID,
			}
			cc.WithTraceContext(tc)

			// Get baggage if we have trace context
			if bag, ok := sc.baggageCache.Get(tc.TraceID); ok {
				cc.WithBaggage(bag)
			}
		}
	}

	// Get resource by container ID
	if resource, ok := sc.resourceCorrelator.GetByContainerID(containerID); ok {
		cc.WithResource(resource)
	} else {
		cc.WithResource(sc.resourceCorrelator.GetDefault())
	}

	cc.WithAttribute("log.level", level)

	return cc
}

// CorrelateMetric correlates a metric with trace and resource information.
func (sc *SignalCorrelator) CorrelateMetric(metricName string, serviceName, namespace string, tc *TraceContext) *CorrelatedContext {
	cc := NewCorrelatedContext()

	if tc != nil && tc.TraceID.IsValid() {
		cc.WithTraceContext(tc)

		// Get baggage
		if bag, ok := sc.baggageCache.Get(tc.TraceID); ok {
			cc.WithBaggage(bag)
		}
	}

	// Get resource
	if resource, ok := sc.resourceCorrelator.GetByService(serviceName, namespace); ok {
		cc.WithResource(resource)
	} else {
		cc.WithResource(sc.resourceCorrelator.GetDefault())
	}

	cc.WithAttribute("metric.name", metricName)

	return cc
}

// RegisterResource registers a resource for correlation.
func (sc *SignalCorrelator) RegisterResource(identity *ResourceIdentity, resource *Resource) {
	sc.resourceCorrelator.Register(identity, resource)
}

// CacheBaggage caches baggage for a trace.
func (sc *SignalCorrelator) CacheBaggage(traceID TraceID, bag *Baggage) {
	sc.baggageCache.Set(traceID, bag)
}

// RecordExemplar records an exemplar for a metric.
func (sc *SignalCorrelator) RecordExemplar(ctx context.Context, metricName string, value float64, attrs map[string]interface{}) {
	sc.exemplarStore.Record(ctx, metricName, value, attrs)
}

// Global signal correlator
var (
	globalSignalCorrelator     *SignalCorrelator
	globalSignalCorrelatorOnce sync.Once
)

// GetGlobalSignalCorrelator returns the global signal correlator.
func GetGlobalSignalCorrelator() *SignalCorrelator {
	globalSignalCorrelatorOnce.Do(func() {
		globalSignalCorrelator = NewSignalCorrelator(nil)
	})
	return globalSignalCorrelator
}
