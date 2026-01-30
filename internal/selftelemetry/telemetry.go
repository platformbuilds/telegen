// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package selftelemetry provides self-monitoring metrics for the Telegen agent.
package selftelemetry

import (
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all self-telemetry metrics for the agent
type Metrics struct {
	namespace string
	ready     atomic.Bool

	// Agent lifecycle metrics
	AgentReady prometheus.Gauge
	AgentLive  prometheus.Gauge

	// Pipeline metrics
	PipelineReceived    *prometheus.CounterVec
	PipelineProcessed   *prometheus.CounterVec
	PipelineDropped     *prometheus.CounterVec
	PipelineExported    *prometheus.CounterVec
	PipelineExportError *prometheus.CounterVec

	// Processor metrics
	ProcessorFiltered *prometheus.CounterVec

	// Sampler metrics
	SamplerAccepted *prometheus.CounterVec
	SamplerRejected *prometheus.CounterVec

	// Exporter metrics
	ExporterSuccess   *prometheus.CounterVec
	ExporterErrors    *prometheus.CounterVec
	ExporterLatency   *prometheus.HistogramVec
	ExporterBatchSize *prometheus.HistogramVec

	// Fanout exporter metrics
	FanoutExportSuccess *prometheus.CounterVec
	FanoutExportError   *prometheus.CounterVec

	// Memory metrics
	MemoryHeapBytes      prometheus.Gauge
	MemoryStackBytes     prometheus.Gauge
	MemoryAllocatedBytes prometheus.Gauge
	MemoryPeakBytes      prometheus.Gauge
	MemoryState          prometheus.Gauge
	MemoryRejected       prometheus.Counter

	// CPU metrics
	CPUPercent   prometheus.Gauge
	CPUThrottled prometheus.Counter

	// eBPF metrics
	EBPFSpecsLoaded       prometheus.Counter
	EBPFCollectionsLoaded prometheus.Counter
	EBPFMapsLoaded        prometheus.Gauge
	EBPFLinksActive       prometheus.Gauge
	EBPFLoadErrors        prometheus.Counter
	EBPFAttachErrors      prometheus.Counter
	EBPFMapErrors         prometheus.Counter

	// Ring buffer metrics
	RingbufReceived *prometheus.CounterVec
	RingbufDropped  *prometheus.CounterVec
	RingbufLost     *prometheus.CounterVec
	RingbufBytes    *prometheus.CounterVec

	// Perf buffer metrics
	PerfbufReceived *prometheus.CounterVec
	PerfbufDropped  *prometheus.CounterVec
	PerfbufLost     *prometheus.CounterVec
	PerfbufBytes    *prometheus.CounterVec
}

// NewMetrics creates a new Metrics instance with all metrics registered
func NewMetrics(namespace string) (*Metrics, error) {
	if namespace == "" {
		namespace = "telegen"
	}

	m := &Metrics{
		namespace: namespace,
	}

	// Agent lifecycle
	m.AgentReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "agent_ready",
		Help:      "Whether the agent is ready to receive traffic (1 = ready)",
	})
	m.AgentLive = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "agent_live",
		Help:      "Whether the agent is alive (1 = live)",
	})

	// Pipeline metrics
	m.PipelineReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "pipeline_received_total",
		Help:      "Total number of signals received by the pipeline",
	}, []string{"signal_type"})

	m.PipelineProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "pipeline_processed_total",
		Help:      "Total number of signals processed by the pipeline",
	}, []string{"signal_type"})

	m.PipelineDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "pipeline_dropped_total",
		Help:      "Total number of signals dropped by the pipeline",
	}, []string{"signal_type", "reason"})

	m.PipelineExported = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "pipeline_exported_total",
		Help:      "Total number of signals exported by the pipeline",
	}, []string{"signal_type"})

	m.PipelineExportError = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "pipeline_export_errors_total",
		Help:      "Total number of export errors in the pipeline",
	}, []string{"signal_type"})

	// Processor metrics
	m.ProcessorFiltered = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "processor_filtered_total",
		Help:      "Total number of signals filtered by processors",
	}, []string{"signal_type", "processor"})

	// Sampler metrics
	m.SamplerAccepted = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "sampler_accepted_total",
		Help:      "Total number of signals accepted by sampler",
	}, []string{"sampler"})

	m.SamplerRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "sampler_rejected_total",
		Help:      "Total number of signals rejected by sampler",
	}, []string{"sampler"})

	// Exporter metrics
	m.ExporterSuccess = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_success_total",
		Help:      "Total number of signals successfully exported",
	}, []string{"exporter", "signal_type"})

	m.ExporterErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_errors_total",
		Help:      "Total number of export errors",
	}, []string{"exporter", "signal_type"})

	m.ExporterLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "exporter_latency_seconds",
		Help:      "Export latency in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"exporter", "signal_type"})

	m.ExporterBatchSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "exporter_batch_size",
		Help:      "Size of export batches",
		Buckets:   []float64{1, 10, 50, 100, 500, 1000, 5000, 10000},
	}, []string{"exporter", "signal_type"})

	// Fanout metrics
	m.FanoutExportSuccess = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "fanout_export_success_total",
		Help:      "Total successful fanout exports",
	}, []string{"fanout", "destination"})

	m.FanoutExportError = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "fanout_export_errors_total",
		Help:      "Total fanout export errors",
	}, []string{"fanout", "destination"})

	// Memory metrics
	m.MemoryHeapBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_heap_bytes",
		Help:      "Current heap memory in bytes",
	})

	m.MemoryStackBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_stack_bytes",
		Help:      "Current stack memory in bytes",
	})

	m.MemoryAllocatedBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_allocated_bytes",
		Help:      "Memory allocated by memory budget in bytes",
	})

	m.MemoryPeakBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_peak_bytes",
		Help:      "Peak memory allocated in bytes",
	})

	m.MemoryState = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "memory_state",
		Help:      "Current memory state (0=normal, 1=soft_limit, 2=hard_limit)",
	})

	m.MemoryRejected = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "memory_rejected_bytes_total",
		Help:      "Total bytes rejected due to memory limits",
	})

	// CPU metrics
	m.CPUPercent = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "cpu_percent",
		Help:      "Current CPU usage percentage",
	})

	m.CPUThrottled = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "cpu_throttled_total",
		Help:      "Total number of CPU throttle events",
	})

	// eBPF metrics
	m.EBPFSpecsLoaded = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ebpf_specs_loaded_total",
		Help:      "Total number of eBPF specs loaded",
	})

	m.EBPFCollectionsLoaded = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ebpf_collections_loaded_total",
		Help:      "Total number of eBPF collections loaded",
	})

	m.EBPFMapsLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "ebpf_maps_loaded",
		Help:      "Current number of eBPF maps loaded",
	})

	m.EBPFLinksActive = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "ebpf_links_active",
		Help:      "Current number of active eBPF links",
	})

	m.EBPFLoadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ebpf_load_errors_total",
		Help:      "Total number of eBPF load errors",
	})

	m.EBPFAttachErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ebpf_attach_errors_total",
		Help:      "Total number of eBPF attach errors",
	})

	m.EBPFMapErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ebpf_map_errors_total",
		Help:      "Total number of eBPF map operation errors",
	})

	// Ring buffer metrics
	m.RingbufReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ringbuf_received_total",
		Help:      "Total events received from ring buffers",
	}, []string{"map"})

	m.RingbufDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ringbuf_dropped_total",
		Help:      "Total events dropped from ring buffers",
	}, []string{"map"})

	m.RingbufLost = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ringbuf_lost_total",
		Help:      "Total events lost in ring buffers",
	}, []string{"map"})

	m.RingbufBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ringbuf_bytes_total",
		Help:      "Total bytes received from ring buffers",
	}, []string{"map"})

	// Perf buffer metrics
	m.PerfbufReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "perfbuf_received_total",
		Help:      "Total events received from perf buffers",
	}, []string{"map"})

	m.PerfbufDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "perfbuf_dropped_total",
		Help:      "Total events dropped from perf buffers",
	}, []string{"map"})

	m.PerfbufLost = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "perfbuf_lost_total",
		Help:      "Total events lost in perf buffers",
	}, []string{"map"})

	m.PerfbufBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "perfbuf_bytes_total",
		Help:      "Total bytes received from perf buffers",
	}, []string{"map"})

	return m, nil
}

// SetReady sets the readiness state
func (m *Metrics) SetReady(ready bool) {
	m.ready.Store(ready)
	if ready {
		m.AgentReady.Set(1)
	} else {
		m.AgentReady.Set(0)
	}
}

// IsReady returns the current readiness state
func (m *Metrics) IsReady() bool {
	return m.ready.Load()
}

// InstallHandler installs the Prometheus metrics handler
func (m *Metrics) InstallHandler(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
}
