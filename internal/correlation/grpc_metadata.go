// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"context"
	"log/slog"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// GRPCMetadataKeys defines the keys used for context propagation in gRPC.
const (
	MetadataKeyTraceparent = "traceparent"
	MetadataKeyTracestate  = "tracestate"
	MetadataKeyBaggage     = "baggage"
)

// GRPCMetadataExtractor extracts context from gRPC metadata.
type GRPCMetadataExtractor struct {
	propagator *CompositePropagator
	log        *slog.Logger
}

// NewGRPCMetadataExtractor creates a new gRPC metadata extractor.
func NewGRPCMetadataExtractor(log *slog.Logger) *GRPCMetadataExtractor {
	if log == nil {
		log = slog.Default()
	}

	return &GRPCMetadataExtractor{
		propagator: NewCompositePropagator(
			NewW3CTraceContextPropagator(),
			NewW3CBaggagePropagator(),
		),
		log: log.With("component", "grpc_metadata_extractor"),
	}
}

// Extract extracts trace context and baggage from gRPC metadata.
func (e *GRPCMetadataExtractor) Extract(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	carrier := &GRPCMetadataCarrier{md: md}
	return e.propagator.Extract(ctx, carrier)
}

// GRPCMetadataInjector injects context into gRPC metadata.
type GRPCMetadataInjector struct {
	propagator *CompositePropagator
	log        *slog.Logger
}

// NewGRPCMetadataInjector creates a new gRPC metadata injector.
func NewGRPCMetadataInjector(log *slog.Logger) *GRPCMetadataInjector {
	if log == nil {
		log = slog.Default()
	}

	return &GRPCMetadataInjector{
		propagator: NewCompositePropagator(
			NewW3CTraceContextPropagator(),
			NewW3CBaggagePropagator(),
		),
		log: log.With("component", "grpc_metadata_injector"),
	}
}

// Inject injects trace context and baggage into outgoing gRPC context.
func (i *GRPCMetadataInjector) Inject(ctx context.Context) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}

	carrier := &GRPCMetadataCarrier{md: md}
	i.propagator.Inject(ctx, carrier)

	return metadata.NewOutgoingContext(ctx, carrier.md)
}

// GRPCMetadataCarrier implements TextMapCarrier for gRPC metadata.
type GRPCMetadataCarrier struct {
	md metadata.MD
}

// Get returns the first value for a key.
func (c *GRPCMetadataCarrier) Get(key string) string {
	values := c.md.Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// Set sets a key-value pair.
func (c *GRPCMetadataCarrier) Set(key, value string) {
	c.md.Set(key, value)
}

// Keys returns all keys.
func (c *GRPCMetadataCarrier) Keys() []string {
	keys := make([]string, 0, len(c.md))
	for k := range c.md {
		keys = append(keys, k)
	}
	return keys
}

// UnaryServerInterceptor creates a gRPC unary server interceptor for context propagation.
func UnaryServerInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	extractor := NewGRPCMetadataExtractor(log)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		ctx = extractor.Extract(ctx)

		// Record correlation for metrics
		if tc := TraceContextFromContext(ctx); tc != nil {
			RecordExemplar(ctx, "grpc.server.request.count", 1, map[string]interface{}{
				"rpc.method": info.FullMethod,
			})
		}

		return handler(ctx, req)
	}
}

// StreamServerInterceptor creates a gRPC stream server interceptor for context propagation.
func StreamServerInterceptor(log *slog.Logger) grpc.StreamServerInterceptor {
	extractor := NewGRPCMetadataExtractor(log)

	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := extractor.Extract(ss.Context())
		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}

		// Record correlation for metrics
		if tc := TraceContextFromContext(ctx); tc != nil {
			RecordExemplar(ctx, "grpc.server.stream.count", 1, map[string]interface{}{
				"rpc.method": info.FullMethod,
			})
		}

		return handler(srv, wrapped)
	}
}

// UnaryClientInterceptor creates a gRPC unary client interceptor for context propagation.
func UnaryClientInterceptor(log *slog.Logger) grpc.UnaryClientInterceptor {
	injector := NewGRPCMetadataInjector(log)

	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		ctx = injector.Inject(ctx)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor creates a gRPC stream client interceptor for context propagation.
func StreamClientInterceptor(log *slog.Logger) grpc.StreamClientInterceptor {
	injector := NewGRPCMetadataInjector(log)

	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		ctx = injector.Inject(ctx)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// wrappedServerStream wraps a grpc.ServerStream with a custom context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapper's context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// GRPCMetadataCache caches extracted metadata for correlation.
type GRPCMetadataCache struct {
	mu    sync.RWMutex
	cache map[string]*CorrelatedContext
	size  int
}

// NewGRPCMetadataCache creates a new metadata cache.
func NewGRPCMetadataCache(size int) *GRPCMetadataCache {
	if size <= 0 {
		size = 1000
	}

	return &GRPCMetadataCache{
		cache: make(map[string]*CorrelatedContext),
		size:  size,
	}
}

// Store stores a correlated context by trace ID.
func (c *GRPCMetadataCache) Store(tc *TraceContext, cc *CorrelatedContext) {
	if tc == nil || !tc.TraceID.IsValid() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction
	if len(c.cache) >= c.size {
		count := 0
		for k := range c.cache {
			delete(c.cache, k)
			count++
			if count >= c.size/2 {
				break
			}
		}
	}

	c.cache[tc.TraceID.String()] = cc
}

// Get retrieves a correlated context by trace ID.
func (c *GRPCMetadataCache) Get(traceID TraceID) (*CorrelatedContext, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cc, ok := c.cache[traceID.String()]
	return cc, ok
}

// ExtractAndCorrelate extracts metadata and creates a correlated context.
func ExtractAndCorrelate(ctx context.Context, serviceName, namespace string) *CorrelatedContext {
	extractor := NewGRPCMetadataExtractor(nil)
	ctx = extractor.Extract(ctx)

	correlator := GetGlobalSignalCorrelator()

	tc := TraceContextFromContext(ctx)
	bag := BaggageFromContext(ctx)

	cc := NewCorrelatedContext()
	if tc != nil {
		cc.WithTraceContext(tc)

		// Cache baggage by trace ID for later correlation
		if bag != nil {
			correlator.CacheBaggage(tc.TraceID, bag)
			cc.WithBaggage(bag)
		}
	}

	// Get resource by service
	if resource, ok := correlator.resourceCorrelator.GetByService(serviceName, namespace); ok {
		cc.WithResource(resource)
	}

	return cc
}

// GRPCBaggageKey defines common baggage keys for gRPC.
type GRPCBaggageKey string

const (
	// BaggageKeyUserID is a common baggage key for user identity.
	BaggageKeyUserID GRPCBaggageKey = "user.id"

	// BaggageKeyTenantID is a common baggage key for tenant identity.
	BaggageKeyTenantID GRPCBaggageKey = "tenant.id"

	// BaggageKeyRequestID is a common baggage key for request identity.
	BaggageKeyRequestID GRPCBaggageKey = "request.id"

	// BaggageKeySessionID is a common baggage key for session identity.
	BaggageKeySessionID GRPCBaggageKey = "session.id"

	// BaggageKeyFeatureFlags is a common baggage key for feature flags.
	BaggageKeyFeatureFlags GRPCBaggageKey = "feature.flags"

	// BaggageKeySynthetic is a common baggage key for synthetic requests.
	BaggageKeySynthetic GRPCBaggageKey = "synthetic"
)

// GetBaggageValue retrieves a baggage value from context.
func GetBaggageValue(ctx context.Context, key GRPCBaggageKey) (string, bool) {
	bag := BaggageFromContext(ctx)
	if bag == nil {
		return "", false
	}
	return bag.Get(string(key))
}

// SetBaggageValue sets a baggage value in context.
func SetBaggageValue(ctx context.Context, key GRPCBaggageKey, value string) context.Context {
	bag := BaggageFromContext(ctx)
	if bag == nil {
		bag = NewBaggage()
	}

	_ = bag.Set(string(key), value)
	return ContextWithBaggage(ctx, bag)
}

// HPACK encoding constants for gRPC/HTTP2 header injection.
const (
	// HPackIndexedTraceparent is the indexed header representation for traceparent.
	HPackIndexedTraceparent = 0x00

	// HPackLiteralTraceparent is the literal header representation prefix.
	HPackLiteralTraceparent = 0x40
)

// GRPCHeaderBuilder builds headers for gRPC injection.
type GRPCHeaderBuilder struct {
	headers map[string]string
}

// NewGRPCHeaderBuilder creates a new header builder.
func NewGRPCHeaderBuilder() *GRPCHeaderBuilder {
	return &GRPCHeaderBuilder{
		headers: make(map[string]string),
	}
}

// WithTraceparent adds traceparent header.
func (b *GRPCHeaderBuilder) WithTraceparent(tp *TraceParent) *GRPCHeaderBuilder {
	if tp != nil {
		b.headers[MetadataKeyTraceparent] = tp.String()
	}
	return b
}

// WithTracestate adds tracestate header.
func (b *GRPCHeaderBuilder) WithTracestate(ts *TraceState) *GRPCHeaderBuilder {
	if ts != nil {
		b.headers[MetadataKeyTracestate] = ts.String()
	}
	return b
}

// WithBaggage adds baggage header.
func (b *GRPCHeaderBuilder) WithBaggage(bag *Baggage) *GRPCHeaderBuilder {
	if bag != nil && bag.Len() > 0 {
		b.headers[MetadataKeyBaggage] = bag.String()
	}
	return b
}

// Build returns the built headers.
func (b *GRPCHeaderBuilder) Build() map[string]string {
	return b.headers
}

// ToMetadata converts to gRPC metadata.
func (b *GRPCHeaderBuilder) ToMetadata() metadata.MD {
	md := metadata.MD{}
	for k, v := range b.headers {
		md.Set(k, v)
	}
	return md
}
