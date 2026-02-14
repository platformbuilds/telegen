// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"bytes"
	"log/slog"
	"regexp"
	"sync"
)

// HTTPHeaderInjector injects trace context and baggage into HTTP headers.
type HTTPHeaderInjector struct {
	log              *slog.Logger
	baggageCache     *BaggageCache
	headerMatcher    *regexp.Regexp
	traceparentRegex *regexp.Regexp
}

// NewHTTPHeaderInjector creates a new HTTP header injector.
func NewHTTPHeaderInjector(log *slog.Logger) *HTTPHeaderInjector {
	if log == nil {
		log = slog.Default()
	}

	return &HTTPHeaderInjector{
		log:              log.With("component", "http_header_injector"),
		baggageCache:     NewBaggageCache(10000),
		headerMatcher:    regexp.MustCompile(`(?i)^(\r?\n|\s)*(\w+[\-\w]*:\s*[^\r\n]+\r?\n)+`),
		traceparentRegex: regexp.MustCompile(`(?i)traceparent:\s*([a-f0-9\-]+)\r?\n`),
	}
}

// InjectBaggage injects baggage header into HTTP request bytes.
// This should be called after BPF has injected the traceparent.
func (h *HTTPHeaderInjector) InjectBaggage(data []byte, tc *TraceContext) []byte {
	if tc == nil || !tc.TraceID.IsValid() {
		return data
	}

	// Look up cached baggage for this trace
	bag, ok := h.baggageCache.Get(tc.TraceID)
	if !ok || bag == nil || bag.Len() == 0 {
		return data
	}

	// Find traceparent header to insert baggage after it
	loc := h.traceparentRegex.FindIndex(data)
	if loc == nil {
		// No traceparent found, insert after first line
		newlineIdx := bytes.IndexByte(data, '\n')
		if newlineIdx == -1 {
			return data
		}
		loc = []int{newlineIdx + 1, newlineIdx + 1}
	}

	// Build baggage header
	baggageHeader := "baggage: " + bag.String() + "\r\n"

	// Insert baggage after traceparent
	result := make([]byte, len(data)+len(baggageHeader))
	copy(result[:loc[1]], data[:loc[1]])
	copy(result[loc[1]:loc[1]+len(baggageHeader)], baggageHeader)
	copy(result[loc[1]+len(baggageHeader):], data[loc[1]:])

	return result
}

// CacheBaggage caches baggage for a trace ID.
func (h *HTTPHeaderInjector) CacheBaggage(traceID TraceID, bag *Baggage) {
	h.baggageCache.Set(traceID, bag)
}

// ExtractAndCacheBaggage extracts baggage from headers and caches it.
func (h *HTTPHeaderInjector) ExtractAndCacheBaggage(data []byte, tc *TraceContext) {
	if tc == nil || !tc.TraceID.IsValid() {
		return
	}

	// Find baggage header
	baggageRegex := regexp.MustCompile(`(?i)baggage:\s*([^\r\n]+)\r?\n`)
	match := baggageRegex.FindSubmatch(data)
	if match == nil || len(match) < 2 {
		return
	}

	bag, err := ParseBaggage(string(match[1]))
	if err != nil {
		h.log.Debug("failed to parse baggage", "error", err)
		return
	}

	h.baggageCache.Set(tc.TraceID, bag)
}

// BPFBaggageIntegration provides baggage integration with BPF tracing.
type BPFBaggageIntegration struct {
	injector *HTTPHeaderInjector
	mu       sync.RWMutex
	pending  map[string]*pendingBaggage
}

type pendingBaggage struct {
	baggage   *Baggage
	timestamp int64
}

// NewBPFBaggageIntegration creates a new BPF baggage integration.
func NewBPFBaggageIntegration(log *slog.Logger) *BPFBaggageIntegration {
	return &BPFBaggageIntegration{
		injector: NewHTTPHeaderInjector(log),
		pending:  make(map[string]*pendingBaggage),
	}
}

// OnRequestStart is called when BPF detects a new request.
// Cache the baggage for later injection.
func (b *BPFBaggageIntegration) OnRequestStart(tc *TraceContext, bag *Baggage) {
	if tc == nil || !tc.TraceID.IsValid() {
		return
	}

	b.injector.CacheBaggage(tc.TraceID, bag)
}

// EnrichOutgoingRequest enriches an outgoing HTTP request with baggage.
func (b *BPFBaggageIntegration) EnrichOutgoingRequest(data []byte, tc *TraceContext) []byte {
	return b.injector.InjectBaggage(data, tc)
}

// ExtractIncomingBaggage extracts baggage from an incoming request.
func (b *BPFBaggageIntegration) ExtractIncomingBaggage(data []byte, tc *TraceContext) *Baggage {
	if tc == nil || !tc.TraceID.IsValid() {
		return nil
	}

	// Extract and cache
	b.injector.ExtractAndCacheBaggage(data, tc)

	// Return cached baggage
	bag, _ := b.injector.baggageCache.Get(tc.TraceID)
	return bag
}

// TraceparentExtractor extracts traceparent from HTTP data.
type TraceparentExtractor struct {
	regex *regexp.Regexp
}

// NewTraceparentExtractor creates a new traceparent extractor.
func NewTraceparentExtractor() *TraceparentExtractor {
	return &TraceparentExtractor{
		regex: regexp.MustCompile(`(?i)traceparent:\s*(\d{2})-([a-f0-9]{32})-([a-f0-9]{16})-([a-f0-9]{2})\r?\n`),
	}
}

// Extract extracts trace context from HTTP data.
func (e *TraceparentExtractor) Extract(data []byte) *TraceContext {
	match := e.regex.FindSubmatch(data)
	if match == nil || len(match) < 5 {
		return nil
	}

	traceID, err := ParseTraceID(string(match[2]))
	if err != nil {
		return nil
	}

	spanID, err := ParseSpanID(string(match[3]))
	if err != nil {
		return nil
	}

	// Parse flags
	var flags TraceFlags
	if len(match[4]) >= 2 {
		if match[4][1] == '1' {
			flags = FlagsSampled
		}
	}

	return &TraceContext{
		TraceID: traceID,
		SpanID:  spanID,
		Flags:   flags,
	}
}

// HeaderBuilder builds HTTP headers for trace propagation.
type HeaderBuilder struct {
	buf bytes.Buffer
}

// NewHeaderBuilder creates a new header builder.
func NewHeaderBuilder() *HeaderBuilder {
	return &HeaderBuilder{}
}

// AddTraceparent adds the traceparent header.
func (b *HeaderBuilder) AddTraceparent(tc *TraceContext) *HeaderBuilder {
	if tc == nil || !tc.TraceID.IsValid() {
		return b
	}

	tp := &TraceParent{
		Version:    0x00,
		TraceID:    tc.TraceID,
		SpanID:     tc.SpanID,
		TraceFlags: tc.Flags,
	}

	b.buf.WriteString("traceparent: ")
	b.buf.WriteString(tp.String())
	b.buf.WriteString("\r\n")

	return b
}

// AddTracestate adds the tracestate header.
func (b *HeaderBuilder) AddTracestate(ts *TraceState) *HeaderBuilder {
	if ts == nil {
		return b
	}

	str := ts.String()
	if str == "" {
		return b
	}

	b.buf.WriteString("tracestate: ")
	b.buf.WriteString(str)
	b.buf.WriteString("\r\n")

	return b
}

// AddBaggage adds the baggage header.
func (b *HeaderBuilder) AddBaggage(bag *Baggage) *HeaderBuilder {
	if bag == nil || bag.Len() == 0 {
		return b
	}

	b.buf.WriteString("baggage: ")
	b.buf.WriteString(bag.String())
	b.buf.WriteString("\r\n")

	return b
}

// Build returns the built headers.
func (b *HeaderBuilder) Build() []byte {
	return b.buf.Bytes()
}

// String returns the built headers as a string.
func (b *HeaderBuilder) String() string {
	return b.buf.String()
}

// Reset resets the builder.
func (b *HeaderBuilder) Reset() {
	b.buf.Reset()
}

// TCPOptionBaggageHandler handles baggage for TCP option propagation.
// Since TCP options have limited space (only trace_id and span_id fit),
// baggage is propagated separately using an application-layer approach.
type TCPOptionBaggageHandler struct {
	cache *BaggageCache
	mu    sync.RWMutex
}

// NewTCPOptionBaggageHandler creates a new TCP option baggage handler.
func NewTCPOptionBaggageHandler() *TCPOptionBaggageHandler {
	return &TCPOptionBaggageHandler{
		cache: NewBaggageCache(10000),
	}
}

// AssociateBaggage associates baggage with a trace ID for TCP option flows.
func (h *TCPOptionBaggageHandler) AssociateBaggage(traceID TraceID, bag *Baggage) {
	h.cache.Set(traceID, bag)
}

// LookupBaggage looks up baggage for a trace ID.
func (h *TCPOptionBaggageHandler) LookupBaggage(traceID TraceID) (*Baggage, bool) {
	return h.cache.Get(traceID)
}

// Global BPF baggage integration
var (
	globalBPFBaggageIntegration     *BPFBaggageIntegration
	globalBPFBaggageIntegrationOnce sync.Once
)

// GetGlobalBPFBaggageIntegration returns the global BPF baggage integration.
func GetGlobalBPFBaggageIntegration() *BPFBaggageIntegration {
	globalBPFBaggageIntegrationOnce.Do(func() {
		globalBPFBaggageIntegration = NewBPFBaggageIntegration(nil)
	})
	return globalBPFBaggageIntegration
}
