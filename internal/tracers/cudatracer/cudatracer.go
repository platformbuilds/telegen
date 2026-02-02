// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package cudatracer provides eBPF-based CUDA kernel and memory operation tracing.
// Task: ML-014 - CUDA Kernel eBPF Tracer Userspace Loader
package cudatracer // import "github.com/platformbuilds/telegen/internal/tracers/cudatracer"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/platformbuilds/telegen/internal/appolly/app/request"
	"github.com/platformbuilds/telegen/internal/appolly/app/svc"
	"github.com/platformbuilds/telegen/internal/discover/exec"
	ebpfcommon "github.com/platformbuilds/telegen/internal/ebpf/common"
	"github.com/platformbuilds/telegen/internal/goexec"
	"github.com/platformbuilds/telegen/internal/obi"
	config "github.com/platformbuilds/telegen/internal/obiconfig"
	"github.com/platformbuilds/telegen/internal/ringbuf"
	"github.com/platformbuilds/telegen/pkg/export/imetrics"
	"github.com/platformbuilds/telegen/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type cuda_event_t -type cuda_mem_stats_t -target amd64,arm64 Bpf ../../../bpf/aiml/cuda_tracer.c -- -I../../../bpf

// CUDA event types - must match constants in cuda_tracer.h
const (
	CUDAEventKernelLaunch   = 0
	CUDAEventKernelComplete = 1
	CUDAEventMemcpyStart    = 2
	CUDAEventMemcpyComplete = 3
	CUDAEventMalloc         = 4
	CUDAEventFree           = 5
	CUDAEventSync           = 6
	CUDAEventStreamCreate   = 7
	CUDAEventStreamDestroy  = 8
)

// Memory copy direction
const (
	CUDAMemcpyHostToHost     = 0
	CUDAMemcpyHostToDevice   = 1
	CUDAMemcpyDeviceToHost   = 2
	CUDAMemcpyDeviceToDevice = 3
	CUDAMemcpyDefault        = 4
)

// CUDAEvent wraps the BPF CUDA event type
type CUDAEvent BpfCudaEventT

// CUDAMemStats wraps the BPF memory statistics type
type CUDAMemStats BpfCudaMemStatsT

// Tracer implements eBPF-based CUDA kernel and memory operation tracing
type Tracer struct {
	pidsFilter       ebpfcommon.ServiceFilter
	cfg              *obi.Config
	metrics          imetrics.Reporter
	bpfObjects       BpfObjects
	closers          []io.Closer
	log              *slog.Logger
	instrumentedLibs ebpfcommon.InstrumentedLibsT
	libsMux          sync.Mutex
}

// New creates a new CUDA tracer
func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "cudatracer.Tracer")

	return &Tracer{
		log:              log,
		cfg:              cfg,
		metrics:          metrics,
		pidsFilter:       pidFilter,
		instrumentedLibs: make(ebpfcommon.InstrumentedLibsT),
		libsMux:          sync.Mutex{},
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

// ProcessBinary processes a binary for CUDA instrumentation
func (p *Tracer) ProcessBinary(fileInfo *exec.FileInfo) {
	if fileInfo == nil || fileInfo.ELF == nil {
		p.log.Error("Empty fileinfo for CUDA tracer")
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

// GoProbes returns Go probes - not used for CUDA tracer
func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

// KProbes returns kernel probes - not used for CUDA tracer
func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

// Tracepoints returns tracepoints - not used for CUDA tracer
func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

// UProbes returns the userspace probes for CUDA library functions
func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return map[string]map[string][]*ebpfcommon.ProbeDesc{
		"libcudart.so": {
			"cudaLaunchKernel": {{
				Start: p.bpfObjects.CudaLaunchKernel,
				End:   p.bpfObjects.CudaLaunchKernelRet,
			}},
			"cudaMemcpy": {{
				Start: p.bpfObjects.CudaMemcpy,
				End:   p.bpfObjects.CudaMemcpyRet,
			}},
			"cudaMemcpyAsync": {{
				Start: p.bpfObjects.CudaMemcpyAsync,
			}},
			"cudaMalloc": {{
				Start: p.bpfObjects.CudaMalloc,
			}},
			"cudaFree": {{
				Start: p.bpfObjects.CudaFree,
			}},
			"cudaDeviceSynchronize": {{
				Start: p.bpfObjects.CudaDeviceSynchronize,
			}},
			"cudaStreamCreate": {{
				Start: p.bpfObjects.CudaStreamCreate,
			}},
			"cudaStreamDestroy": {{
				Start: p.bpfObjects.CudaStreamDestroy,
			}},
		},
	}
}

// SetupTailCalls sets up tail calls - not used for CUDA tracer
func (p *Tracer) SetupTailCalls() {}

// SocketFilters returns socket filters - not used for CUDA tracer
func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

// SockMsgs returns sock msg programs - not used for CUDA tracer
func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

// SockOps returns sock ops programs - not used for CUDA tracer
func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

// Iters returns iterator programs - not used for CUDA tracer
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
		p.bpfObjects.CudaEvents,
		ebpfEventContext.CommonPIDsFilter,
		p.processCUDAEvent,
		p.log,
		p.metrics,
		eventsChan,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

// processCUDAEvent parses a CUDA event from the ring buffer and converts it to a span
func (p *Tracer) processCUDAEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	if len(record.RawSample) == 0 {
		return request.Span{}, true, errors.New("invalid ringbuffer record size")
	}

	event, err := ebpfcommon.ReinterpretCast[CUDAEvent](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	span := request.Span{
		Pid: request.PidInfo{
			HostPID: event.Pid,
			UserPID: event.Pid,
		},
	}

	switch event.EventType {
	case CUDAEventKernelLaunch:
		span.Type = request.EventTypeGPUKernelLaunch
		span.Method = string(event.KernelName[:nullTerminated(event.KernelName[:])])
		// Grid size as content length (total threads = gridX * gridY * gridZ * blockX * blockY * blockZ)
		gridSize := int64(event.GridDimX) * int64(event.GridDimY) * int64(event.GridDimZ)
		blockSize := int64(event.BlockDimX) * int64(event.BlockDimY) * int64(event.BlockDimZ)
		span.ContentLength = gridSize * blockSize
		p.log.Debug("CUDA Kernel Launch", "kernel", span.Method, "threads", span.ContentLength)

	case CUDAEventMemcpyStart, CUDAEventMemcpyComplete:
		span.Type = request.EventTypeGPUMemcpy
		span.ContentLength = int64(event.Bytes)
		span.SubType = int(event.MemcpyKind)
		if event.EventType == CUDAEventMemcpyComplete {
			// Duration is calculated from End - Start in the span processing
			span.End = span.Start + int64(event.DurationNs)
		}
		p.log.Debug("CUDA Memcpy", "bytes", event.Bytes, "kind", event.MemcpyKind)

	case CUDAEventMalloc:
		span.Type = request.EventTypeGPUMalloc
		span.ContentLength = int64(event.AllocSize)
		p.log.Debug("CUDA Malloc", "size", event.AllocSize)

	case CUDAEventFree:
		span.Type = request.EventTypeGPUMalloc // Reuse same type for free
		span.ContentLength = 0                 // Free doesn't have size info from kernel
		span.SubType = 1                       // Mark as free operation
		p.log.Debug("CUDA Free", "ptr", event.AllocPtr)

	case CUDAEventSync:
		span.Type = request.EventTypeGPUKernelLaunch // Reuse for sync
		span.Method = "cudaDeviceSynchronize"
		p.log.Debug("CUDA Device Synchronize")

	case CUDAEventStreamCreate:
		span.Type = request.EventTypeGPUKernelLaunch
		span.Method = "cudaStreamCreate"
		p.log.Debug("CUDA Stream Create")

	case CUDAEventStreamDestroy:
		span.Type = request.EventTypeGPUKernelLaunch
		span.Method = "cudaStreamDestroy"
		p.log.Debug("CUDA Stream Destroy")

	default:
		p.log.Error("Unknown CUDA event type", "type", event.EventType)
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
