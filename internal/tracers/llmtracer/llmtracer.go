// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package llmtracer provides eBPF-based LLM API request tracing.
// Task: ML-011 - LLM Request Interceptor eBPF Userspace Loader
package llmtracer // import "github.com/mirastacklabs-ai/telegen/internal/tracers/llmtracer"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	"github.com/mirastacklabs-ai/telegen/internal/discover/exec"
	ebpfcommon "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"
	"github.com/mirastacklabs-ai/telegen/internal/goexec"
	"github.com/mirastacklabs-ai/telegen/internal/obi"
	config "github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type llm_event_t -target amd64,arm64 Bpf ../../../bpf/aiml/llm_tracer.c -- -I../../../bpf

// LLM event types - must match constants in llm_tracer.h
const (
	LLMEventRequestStart = 0
	LLMEventRequestEnd   = 1
	LLMEventFirstToken   = 2
	LLMEventStreamChunk  = 3
	LLMEventError        = 4
)

// LLM provider types
const (
	LLMProviderUnknown   = 0
	LLMProviderOpenAI    = 1
	LLMProviderAnthropic = 2
	LLMProviderAzure     = 3
	LLMProviderGoogle    = 4
	LLMProviderCohere    = 5
	LLMProviderMistral   = 6
	LLMProviderLocal     = 7
)

// ProviderName returns a human-readable name for the provider
func ProviderName(provider uint32) string {
	switch provider {
	case LLMProviderOpenAI:
		return "openai"
	case LLMProviderAnthropic:
		return "anthropic"
	case LLMProviderAzure:
		return "azure"
	case LLMProviderGoogle:
		return "google"
	case LLMProviderCohere:
		return "cohere"
	case LLMProviderMistral:
		return "mistral"
	case LLMProviderLocal:
		return "local"
	default:
		return "unknown"
	}
}

// LLMEvent wraps the BPF LLM event type
type LLMEvent BpfLlmEventT

// Tracer implements eBPF-based LLM API request tracing
type Tracer struct {
	pidsFilter       ebpfcommon.ServiceFilter
	cfg              *obi.Config
	metrics          imetrics.Reporter
	bpfObjects       BpfObjects
	closers          []io.Closer
	log              *slog.Logger
	instrumentedLibs ebpfcommon.InstrumentedLibsT
	libsMux          sync.Mutex

	// Request tracking for correlating start/end events
	activeRequests map[string]*LLMRequestInfo
	requestsMux    sync.RWMutex
}

// LLMRequestInfo tracks an in-flight LLM request
type LLMRequestInfo struct {
	RequestID        string
	StartTime        time.Time
	FirstTokenTime   time.Time
	Provider         string
	Model            string
	Endpoint         string
	IsStreaming      bool
	PromptTokens     uint32
	CompletionTokens uint32
	PID              uint32
	TID              uint32
}

// New creates a new LLM tracer
func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "llmtracer.Tracer")

	return &Tracer{
		log:              log,
		cfg:              cfg,
		metrics:          metrics,
		pidsFilter:       pidFilter,
		instrumentedLibs: make(ebpfcommon.InstrumentedLibsT),
		libsMux:          sync.Mutex{},
		activeRequests:   make(map[string]*LLMRequestInfo),
	}
}

// AllowPID adds a PID to the allowed list for tracing
func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
}

// BlockPID removes a PID from the allowed list
func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
}

// Load returns the embedded BPF collection spec
func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	return LoadBpf()
}

// Constants returns the constants to be injected into the BPF program
func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 1)

	if p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(0)
	} else {
		m["filter_pids"] = int32(1)
	}

	return m
}

// RegisterOffsets is called when offsets are available for a binary
func (p *Tracer) RegisterOffsets(fileInfo *exec.FileInfo, _ *goexec.Offsets) {
	p.ProcessBinary(fileInfo)
}

// ProcessBinary processes a binary for LLM instrumentation
func (p *Tracer) ProcessBinary(fileInfo *exec.FileInfo) {
	if fileInfo == nil || fileInfo.ELF == nil {
		p.log.Error("Empty fileinfo for LLM tracer")
	}
}

// BpfObjects returns the BPF objects
func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

// AddCloser adds a closer to be called on cleanup
func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

// GoProbes returns Go probes - not used for LLM tracer
func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

// KProbes returns kernel probes - not used for LLM tracer
func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

// Tracepoints returns tracepoints - not used for LLM tracer
func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

// UProbes returns the userspace probes for LLM library functions
// This targets the Python OpenAI/Anthropic/etc. client libraries
func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	// LLM tracing works via HTTP interception, which uses uprobes on
	// SSL/TLS libraries and HTTP parsing. The specific probes are attached
	// dynamically based on what's discovered in the process.
	//
	// For Python LLM libraries (openai, anthropic, etc.), we attach to:
	// - The HTTP client functions in the Python runtime
	// - SSL_read/SSL_write in libssl for encrypted traffic
	//
	// The BPF program's uprobe sections like python_openai_create and
	// python_anthropic_create are designed to be attached to the Python
	// interpreter when it calls into these library functions.
	return map[string]map[string][]*ebpfcommon.ProbeDesc{
		"libssl.so": {
			// HTTP/2 frame writes are used to detect LLM API calls
			"SSL_write": {{
				Start: p.bpfObjects.Http2WriteFrame,
			}},
			"SSL_read": {{
				Start: p.bpfObjects.HttpReadResponse,
			}},
		},
	}
}

// SetupTailCalls sets up tail calls - not used for LLM tracer
func (p *Tracer) SetupTailCalls() {}

// SocketFilters returns socket filters - not used for LLM tracer
func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

// SockMsgs returns sock msg programs - not used for LLM tracer
func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

// SockOps returns sock ops programs - not used for LLM tracer
func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

// Iters returns iterator programs - not used for LLM tracer
func (p *Tracer) Iters() []*ebpfcommon.Iter { return nil }

// RecordInstrumentedLib records an instrumented library
func (p *Tracer) RecordInstrumentedLib(id uint64, closers []io.Closer) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.AddRef(id)

	if len(closers) > 0 {
		module.Closers = append(module.Closers, closers...)
	}

	p.log.Debug("Recorded instrumented Lib", "ino", id, "module", module)
}

// AddInstrumentedLibRef adds a reference to an instrumented library
func (p *Tracer) AddInstrumentedLibRef(id uint64) {
	p.RecordInstrumentedLib(id, nil)
}

// UnlinkInstrumentedLib removes a reference to an instrumented library
func (p *Tracer) UnlinkInstrumentedLib(id uint64) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module, err := p.instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
	}
}

// AlreadyInstrumentedLib checks if a library is already instrumented
func (p *Tracer) AlreadyInstrumentedLib(id uint64) bool {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.Find(id)

	p.log.Debug("checking already instrumented Lib", "ino", id, "module", module)
	return module != nil
}

// Run starts the tracer and forwards events to the output channel
func (p *Tracer) Run(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, eventsChan *msg.Queue[[]request.Span]) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.LlmEvents,
		ebpfEventContext.CommonPIDsFilter,
		p.processLLMEvent,
		p.log,
		p.metrics,
		eventsChan,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

// processLLMEvent parses an LLM event from the ring buffer and converts it to a span
func (p *Tracer) processLLMEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	if len(record.RawSample) == 0 {
		return request.Span{}, true, errors.New("invalid ringbuffer record size")
	}

	event, err := ebpfcommon.ReinterpretCast[LLMEvent](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	requestID := string(event.RequestId[:nullTerminated(event.RequestId[:])])
	model := string(event.Model[:nullTerminated(event.Model[:])])
	provider := ProviderName(event.Provider)

	span := request.Span{
		Pid: request.PidInfo{
			HostPID: event.Pid,
			UserPID: event.Pid,
		},
	}

	switch event.EventType {
	case LLMEventRequestStart:
		// Track the start of a new request
		p.requestsMux.Lock()
		p.activeRequests[requestID] = &LLMRequestInfo{
			RequestID:   requestID,
			StartTime:   time.Unix(0, int64(event.TimestampNs)),
			Provider:    provider,
			Model:       model,
			IsStreaming: event.IsStreaming != 0,
			PID:         event.Pid,
			TID:         event.Tid,
		}
		p.requestsMux.Unlock()

		// Create a span for the request start (will be completed on end)
		span.Type = request.EventTypeSQLClient // Using SQL type as placeholder for LLM
		span.Method = "LLM_REQUEST_START"
		span.Path = provider + "/" + model
		span.RequestStart = int64(event.TimestampNs)
		p.log.Debug("LLM Request Start", "requestID", requestID, "provider", provider, "model", model)

	case LLMEventFirstToken:
		// Record time to first token
		p.requestsMux.Lock()
		if req, ok := p.activeRequests[requestID]; ok {
			req.FirstTokenTime = time.Unix(0, int64(event.TimestampNs))
		}
		p.requestsMux.Unlock()

		span.Type = request.EventTypeSQLClient
		span.Method = "LLM_FIRST_TOKEN"
		span.Path = provider + "/" + model
		p.log.Debug("LLM First Token", "requestID", requestID, "ttft_ns", event.TtftNs)

	case LLMEventRequestEnd:
		// Complete the request and emit final metrics
		p.requestsMux.Lock()
		req, ok := p.activeRequests[requestID]
		if ok {
			delete(p.activeRequests, requestID)
		}
		p.requestsMux.Unlock()

		span.Type = request.EventTypeSQLClient
		span.Method = "LLM_REQUEST"
		span.Path = provider + "/" + model
		span.ContentLength = int64(event.PromptTokens + event.CompletionTokens)

		// Include TTFT if we tracked the request
		if ok && !req.FirstTokenTime.IsZero() {
			// Store TTFT in the status code field as a workaround
			span.Status = int(req.FirstTokenTime.Sub(req.StartTime).Nanoseconds() / 1000000) // ms
		}

		p.log.Debug("LLM Request End",
			"requestID", requestID,
			"provider", provider,
			"model", model,
			"duration_ns", event.DurationNs,
			"prompt_tokens", event.PromptTokens,
			"completion_tokens", event.CompletionTokens)

	case LLMEventError:
		// Handle error events
		errorMsg := string(event.ErrorMsg[:nullTerminated(event.ErrorMsg[:])])

		p.requestsMux.Lock()
		delete(p.activeRequests, requestID)
		p.requestsMux.Unlock()

		span.Type = request.EventTypeSQLClient
		span.Method = "LLM_ERROR"
		span.Path = provider + "/" + model
		span.Status = int(event.StatusCode)
		p.log.Error("LLM Request Error", "requestID", requestID, "error", errorMsg, "status", event.StatusCode)

	case LLMEventStreamChunk:
		// Stream chunks are typically not emitted as individual spans
		// Just log for debugging
		p.log.Debug("LLM Stream Chunk", "requestID", requestID, "chunk_index", event.ChunkIndex)
		return request.Span{}, true, nil

	default:
		p.log.Error("Unknown LLM event type", "type", event.EventType)
		return request.Span{}, true, nil
	}

	return span, false, nil
}

// nullTerminated finds the index of the first null byte
func nullTerminated(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

// Required returns whether this tracer is required
func (p *Tracer) Required() bool {
	return false
}
