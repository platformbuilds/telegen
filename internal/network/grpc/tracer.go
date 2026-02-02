// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpc provides gRPC call tracing functionality.
// Task: NET-014
package grpc

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// StatusCode represents gRPC status codes
type StatusCode int32

const (
	StatusOK                 StatusCode = 0
	StatusCancelled          StatusCode = 1
	StatusUnknown            StatusCode = 2
	StatusInvalidArgument    StatusCode = 3
	StatusDeadlineExceeded   StatusCode = 4
	StatusNotFound           StatusCode = 5
	StatusAlreadyExists      StatusCode = 6
	StatusPermissionDenied   StatusCode = 7
	StatusResourceExhausted  StatusCode = 8
	StatusFailedPrecondition StatusCode = 9
	StatusAborted            StatusCode = 10
	StatusOutOfRange         StatusCode = 11
	StatusUnimplemented      StatusCode = 12
	StatusInternal           StatusCode = 13
	StatusUnavailable        StatusCode = 14
	StatusDataLoss           StatusCode = 15
	StatusUnauthenticated    StatusCode = 16
)

// String returns the string representation of the status code
func (s StatusCode) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusCancelled:
		return "CANCELLED"
	case StatusUnknown:
		return "UNKNOWN"
	case StatusInvalidArgument:
		return "INVALID_ARGUMENT"
	case StatusDeadlineExceeded:
		return "DEADLINE_EXCEEDED"
	case StatusNotFound:
		return "NOT_FOUND"
	case StatusAlreadyExists:
		return "ALREADY_EXISTS"
	case StatusPermissionDenied:
		return "PERMISSION_DENIED"
	case StatusResourceExhausted:
		return "RESOURCE_EXHAUSTED"
	case StatusFailedPrecondition:
		return "FAILED_PRECONDITION"
	case StatusAborted:
		return "ABORTED"
	case StatusOutOfRange:
		return "OUT_OF_RANGE"
	case StatusUnimplemented:
		return "UNIMPLEMENTED"
	case StatusInternal:
		return "INTERNAL"
	case StatusUnavailable:
		return "UNAVAILABLE"
	case StatusDataLoss:
		return "DATA_LOSS"
	case StatusUnauthenticated:
		return "UNAUTHENTICATED"
	default:
		return "UNKNOWN"
	}
}

// GRPCEvent represents a gRPC call
type GRPCEvent struct {
	Timestamp time.Time

	// Connection
	LocalAddr  string
	RemoteAddr string

	// Call info
	Service    string
	Method     string
	FullMethod string // /package.Service/Method

	// Request
	RequestSize     int64
	RequestMetadata map[string]string

	// Response
	ResponseSize  int64
	StatusCode    StatusCode
	StatusMessage string

	// Timing
	Duration        time.Duration
	TimeToFirstByte time.Duration

	// Streaming
	IsClientStream bool
	IsServerStream bool
	MessagesSent   int
	MessagesRecv   int

	// Trace context
	TraceID      [16]byte
	SpanID       [8]byte
	ParentSpanID [8]byte

	// Errors
	ErrorCode    string
	ErrorDetails string

	// Process info
	PID  uint32
	Comm string
}

// Config holds gRPC tracer configuration
type Config struct {
	Enabled          bool     `mapstructure:"enabled"`
	CaptureMetadata  bool     `mapstructure:"capture_metadata"`
	CapturePayload   bool     `mapstructure:"capture_payload"`
	MaxPayloadSize   int      `mapstructure:"max_payload_size"`
	SensitiveHeaders []string `mapstructure:"sensitive_headers"`
	TrackStreaming   bool     `mapstructure:"track_streaming"`
}

// DefaultConfig returns default gRPC tracer configuration
func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		CaptureMetadata: true,
		CapturePayload:  false,
		MaxPayloadSize:  4096,
		SensitiveHeaders: []string{
			"authorization",
			"cookie",
			"set-cookie",
		},
		TrackStreaming: true,
	}
}

// GRPCMetrics tracks gRPC call metrics
type GRPCMetrics struct {
	TotalCalls         uint64
	SuccessfulCalls    uint64
	FailedCalls        uint64
	TotalLatencyNs     uint64
	TotalRequestBytes  uint64
	TotalResponseBytes uint64

	// Per-status code counts
	statusCounts sync.Map // map[StatusCode]uint64
}

// RecordCall records a gRPC call
func (m *GRPCMetrics) RecordCall(event *GRPCEvent) {
	atomic.AddUint64(&m.TotalCalls, 1)

	if event.StatusCode == StatusOK {
		atomic.AddUint64(&m.SuccessfulCalls, 1)
	} else {
		atomic.AddUint64(&m.FailedCalls, 1)
	}

	atomic.AddUint64(&m.TotalLatencyNs, uint64(event.Duration.Nanoseconds()))
	atomic.AddUint64(&m.TotalRequestBytes, uint64(event.RequestSize))
	atomic.AddUint64(&m.TotalResponseBytes, uint64(event.ResponseSize))

	// Update per-status count
	if existing, ok := m.statusCounts.Load(event.StatusCode); ok {
		count := existing.(uint64)
		m.statusCounts.Store(event.StatusCode, count+1)
	} else {
		m.statusCounts.Store(event.StatusCode, uint64(1))
	}
}

// GetStats returns a snapshot of the metrics
func (m *GRPCMetrics) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_calls":          atomic.LoadUint64(&m.TotalCalls),
		"successful_calls":     atomic.LoadUint64(&m.SuccessfulCalls),
		"failed_calls":         atomic.LoadUint64(&m.FailedCalls),
		"total_request_bytes":  atomic.LoadUint64(&m.TotalRequestBytes),
		"total_response_bytes": atomic.LoadUint64(&m.TotalResponseBytes),
	}

	totalCalls := atomic.LoadUint64(&m.TotalCalls)
	if totalCalls > 0 {
		stats["avg_latency_ns"] = atomic.LoadUint64(&m.TotalLatencyNs) / totalCalls
	}

	statusCounts := make(map[string]uint64)
	m.statusCounts.Range(func(key, value interface{}) bool {
		statusCounts[key.(StatusCode).String()] = value.(uint64)
		return true
	})
	stats["status_counts"] = statusCounts

	return stats
}

// HTTP2Event from eBPF
type HTTP2Event struct {
	Timestamp     uint64
	PID           uint32
	TID           uint32
	Saddr         uint32
	Daddr         uint32
	Sport         uint16
	Dport         uint16
	FD            uint32
	FrameType     uint8
	FrameFlags    uint8
	StreamID      uint32
	FrameLength   uint32
	Method        [16]byte
	Path          [256]byte
	Authority     [128]byte
	ContentType   [64]byte
	StatusCode    uint32
	IsGRPC        uint8
	GRPCService   [128]byte
	GRPCMethod    [64]byte
	GRPCStatus    int32
	GRPCMessage   [256]byte
	StreamStartNs uint64
	FirstByteNs   uint64
	LastByteNs    uint64
	RequestBytes  uint64
	ResponseBytes uint64
	TraceID       [16]byte
	SpanID        [8]byte
	Comm          [16]byte
}

// StreamState tracks in-flight gRPC streams
type StreamState struct {
	StreamID      uint32
	Service       string
	Method        string
	StartTime     time.Time
	FirstByteTime time.Time
	RequestBytes  int64
	ResponseBytes int64
	MessageCount  int
	TraceID       [16]byte
	SpanID        [8]byte
	Metadata      map[string]string
}

// Tracer traces gRPC calls
type Tracer struct {
	config        Config
	activeStreams sync.Map // map[streamKey]*StreamState
	metrics       *GRPCMetrics
	eventChan     chan *GRPCEvent
	tracer        trace.Tracer

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// streamKey identifies a unique stream
//
//nolint:unused // reserved for stream tracking
type streamKey struct {
	pid      uint32
	fd       uint32
	streamID uint32
}

// NewTracer creates a new gRPC tracer
func NewTracer(config Config, tracer trace.Tracer) *Tracer {
	ctx, cancel := context.WithCancel(context.Background())

	return &Tracer{
		config:    config,
		metrics:   &GRPCMetrics{},
		eventChan: make(chan *GRPCEvent, 10000),
		tracer:    tracer,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins gRPC tracing
func (t *Tracer) Start(ctx context.Context) error {
	t.wg.Add(1)
	go t.processEvents()
	return nil
}

// Stop stops the tracer
func (t *Tracer) Stop() {
	t.cancel()
	close(t.eventChan)
	t.wg.Wait()
}

// processEvents handles incoming gRPC events
func (t *Tracer) processEvents() {
	defer t.wg.Done()

	for event := range t.eventChan {
		t.metrics.RecordCall(event)

		if t.tracer != nil {
			t.exportSpan(event)
		}
	}
}

// ProcessHTTP2Event handles HTTP/2 events from eBPF
func (t *Tracer) ProcessHTTP2Event(event *HTTP2Event) {
	if event.IsGRPC == 0 {
		return
	}

	grpcEvent := &GRPCEvent{
		Timestamp:    time.Now(),
		Service:      bytesToString(event.GRPCService[:]),
		Method:       bytesToString(event.GRPCMethod[:]),
		FullMethod:   bytesToString(event.Path[:]),
		RequestSize:  int64(event.RequestBytes),
		ResponseSize: int64(event.ResponseBytes),
		StatusCode:   StatusCode(event.GRPCStatus),
		TraceID:      event.TraceID,
		SpanID:       event.SpanID,
		PID:          event.PID,
		Comm:         bytesToString(event.Comm[:]),
	}

	// Calculate timings
	if event.StreamStartNs > 0 && event.LastByteNs > 0 {
		grpcEvent.Duration = time.Duration(event.LastByteNs - event.StreamStartNs)
		if event.FirstByteNs > 0 {
			grpcEvent.TimeToFirstByte = time.Duration(event.FirstByteNs - event.StreamStartNs)
		}
	}

	grpcEvent.StatusMessage = t.statusCodeToMessage(grpcEvent.StatusCode)

	// Send to processing channel
	select {
	case t.eventChan <- grpcEvent:
	default:
		// Channel full, drop event
	}
}

// exportSpan exports the gRPC event as an OTel span
func (t *Tracer) exportSpan(event *GRPCEvent) {
	if t.tracer == nil {
		return
	}

	// Create span options
	attrs := event.ToSpanAttributes()

	// This would typically be linked to existing trace context
	// For now, create a new span
	_, span := t.tracer.Start(t.ctx, event.FullMethod,
		trace.WithAttributes(attrs...),
		trace.WithTimestamp(event.Timestamp),
	)

	span.End(trace.WithTimestamp(event.Timestamp.Add(event.Duration)))
}

// statusCodeToMessage converts status code to message
func (t *Tracer) statusCodeToMessage(code StatusCode) string {
	return code.String()
}

// ToSpanAttributes converts GRPCEvent to OTel span attributes
func (e *GRPCEvent) ToSpanAttributes() []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("rpc.system", "grpc"),
		attribute.String("rpc.service", e.Service),
		attribute.String("rpc.method", e.Method),
		attribute.Int64("rpc.grpc.status_code", int64(e.StatusCode)),
	}

	if e.RequestSize > 0 {
		attrs = append(attrs, attribute.Int64("rpc.request.size", e.RequestSize))
	}
	if e.ResponseSize > 0 {
		attrs = append(attrs, attribute.Int64("rpc.response.size", e.ResponseSize))
	}
	if e.IsClientStream || e.IsServerStream {
		attrs = append(attrs,
			attribute.Bool("rpc.grpc.client_stream", e.IsClientStream),
			attribute.Bool("rpc.grpc.server_stream", e.IsServerStream),
			attribute.Int("rpc.grpc.messages_sent", e.MessagesSent),
			attribute.Int("rpc.grpc.messages_received", e.MessagesRecv),
		)
	}
	if e.LocalAddr != "" {
		attrs = append(attrs, attribute.String("net.peer.name", e.LocalAddr))
	}
	if e.RemoteAddr != "" {
		attrs = append(attrs, attribute.String("net.peer.address", e.RemoteAddr))
	}
	if e.Duration > 0 {
		attrs = append(attrs, attribute.Int64("rpc.duration_ns", e.Duration.Nanoseconds()))
	}
	if e.ErrorCode != "" {
		attrs = append(attrs, attribute.String("error.code", e.ErrorCode))
	}

	return attrs
}

// GetMetrics returns the gRPC metrics
func (t *Tracer) GetMetrics() map[string]interface{} {
	return t.metrics.GetStats()
}

// GetActiveStreams returns count of active streams
func (t *Tracer) GetActiveStreams() int {
	count := 0
	t.activeStreams.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// Helper function to convert null-terminated byte array to string
func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
