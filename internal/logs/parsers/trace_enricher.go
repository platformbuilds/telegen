package parsers

import (
	"path/filepath"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/correlation"
)

// TraceContextEnricher enriches logs with trace context from the eBPF layer.
//
// This bridges trace correlation for plain-text logs that don't embed trace context:
//
//  1. eBPF log_enricher intercepts write() syscalls
//  2. Records correlation_key + timestamp → trace_context in LogTraceCorrelator
//  3. This enricher queries the correlator using the same key
//  4. If found, adds TraceID and SpanID to the ParsedLog
//
// Correlation key selection (matches logenricher):
//   - Kubernetes: "cid:" + container ID (from K8s metadata)
//   - Non-Kubernetes: "path:" + resolved file path
//
// Requirements:
//   - log_enricher must be enabled and recording trace contexts
//   - Log timestamp must be within the correlation window (default: 30s)
//   - For K8s: K8s metadata enrichment must run first (to extract container ID)
type TraceContextEnricher struct {
	correlator *correlation.LogTraceCorrelator
	tolerance  time.Duration
}

// NewTraceContextEnricher creates a new trace context enricher.
// If correlator is nil, uses the global correlator instance.
func NewTraceContextEnricher(correlator *correlation.LogTraceCorrelator) *TraceContextEnricher {
	if correlator == nil {
		correlator = correlation.GetGlobalLogTraceCorrelator()
	}
	return &TraceContextEnricher{
		correlator: correlator,
		tolerance:  1 * time.Second, // Allow 1s timestamp skew
	}
}

// NewTraceContextEnricherWithTolerance creates an enricher with custom tolerance.
func NewTraceContextEnricherWithTolerance(correlator *correlation.LogTraceCorrelator, tolerance time.Duration) *TraceContextEnricher {
	e := NewTraceContextEnricher(correlator)
	e.tolerance = tolerance
	return e
}

// Name implements the Enricher interface.
func (e *TraceContextEnricher) Name() string {
	return "trace_context"
}

// Enrich implements the Enricher interface.
func (e *TraceContextEnricher) Enrich(log *ParsedLog, filePath string) {
	// Skip if log already has trace context (e.g., from Spring Boot MDC)
	if log.TraceID != "" && log.SpanID != "" {
		return
	}

	// Get correlation key (tries K8s container ID first, then file path)
	correlationKey := e.getCorrelationKey(log, filePath)
	if correlationKey == "" {
		return
	}

	// Need a timestamp to correlate
	ts := log.Timestamp
	if ts.IsZero() {
		ts = log.ObservedTimestamp
	}
	if ts.IsZero() {
		return
	}

	// Query the correlator
	traceID, spanID, found := e.correlator.LookupTraceContext(correlationKey, ts, e.tolerance)
	if found {
		log.TraceID = traceID
		log.SpanID = spanID
		log.Attributes["telegen.trace_source"] = "ebpf_correlation"
	}
}

// getCorrelationKey returns the key to use for trace context lookup.
//
// Key selection (must match logenricher's recording logic):
//  1. Kubernetes: "cid:" + container ID (from K8s metadata enrichment)
//  2. Non-Kubernetes: "path:" + resolved file path (fallback for bare-metal)
//
// This enables trace correlation in both K8s and non-K8s environments.
func (e *TraceContextEnricher) getCorrelationKey(log *ParsedLog, filePath string) string {
	// Try Kubernetes container ID first (most reliable in K8s)
	if containerID := log.ResourceAttributes["k8s.container.id"]; containerID != "" {
		return "cid:" + containerID
	}

	// Fallback: use file path for non-K8s environments
	// This must match the path that logenricher recorded
	if filePath != "" {
		// Resolve symlinks for consistent matching
		resolved, err := filepath.EvalSymlinks(filePath)
		if err != nil {
			resolved = filePath
		}
		return "path:" + resolved
	}

	return ""
}
