package selftelemetry

import (
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Registry struct {
	QueueSize         *prometheus.GaugeVec
	QueueDropped      *prometheus.CounterVec
	ExportFails       *prometheus.CounterVec
	ExportLatency     *prometheus.HistogramVec
	RingEvents        prometheus.Counter
	RingLost          prometheus.Counter
	RecoveredPanics   *prometheus.CounterVec
	ready             atomic.Bool
	lastExportSuccess atomic.Int64
	lastExportFailure atomic.Int64
	livenessWindowNs  atomic.Int64
}

var globalRegistry atomic.Pointer[Registry]

func NewRegistry(namespace string) *Registry {
	if namespace == "" {
		namespace = "telegen"
	}
	r := &Registry{}
	r.QueueSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: "agent_queue_size"}, []string{"pipeline"})
	r.QueueDropped = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "agent_queue_dropped_total"}, []string{"pipeline", "reason"})
	r.ExportFails = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: "agent_export_failures_total"}, []string{"pipeline", "endpoint"})
	r.ExportLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: namespace, Name: "agent_export_latency_seconds", Buckets: prometheus.DefBuckets}, []string{"pipeline", "endpoint"})
	r.RingEvents = prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: "agent_ringbuf_events_total"})
	r.RingLost = prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: "agent_ringbuf_lost_total"})
	r.RecoveredPanics = prometheus.NewCounterVec(
		prometheus.CounterOpts{Namespace: namespace, Name: "agent_recovered_panics_total"},
		[]string{"component"},
	)
	r.SetLivenessWindow(5 * time.Minute)
	prometheus.MustRegister(
		r.QueueSize,
		r.QueueDropped,
		r.ExportFails,
		r.ExportLatency,
		r.RingEvents,
		r.RingLost,
		r.RecoveredPanics,
	)
	return r
}
func InstallHandlers(mux *http.ServeMux, listen string) *Registry {
	r := NewRegistry("telegen")
	SetGlobalRegistry(r)
	mux.Handle("/metrics", promhttp.Handler())
	installProbeHandlers(mux, r)
	log.Printf("self-telemetry HTTP on %s", listen)
	return r
}

// InstallProbeHandlers installs only health/readiness handlers on the given mux.
// It reuses an existing registry so readiness and liveness state stay consistent
// across the self-telemetry and health listeners.
func InstallProbeHandlers(mux *http.ServeMux, listen string, r *Registry) {
	if r == nil {
		r = NewRegistry("telegen")
	}
	SetGlobalRegistry(r)
	installProbeHandlers(mux, r)
	log.Printf("self-telemetry probe HTTP on %s", listen)
}

func installProbeHandlers(mux *http.ServeMux, r *Registry) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		successTS := r.lastExportSuccess.Load()
		failureTS := r.lastExportFailure.Load()
		now := time.Now().UnixNano()
		livenessWindowNs := r.livenessWindowNs.Load()
		if livenessWindowNs <= 0 {
			livenessWindowNs = int64((5 * time.Minute))
		}

		if successTS == 0 && failureTS == 0 {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("ok: no export attempts yet")); err != nil {
				return
			}
			return
		}

		if successTS != 0 && now-successTS <= livenessWindowNs {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("ok: recent export success")); err != nil {
				return
			}
			return
		}

		// Report unhealthy only when last attempt failed and there is no recent success.
		if failureTS > successTS {
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := w.Write([]byte("unhealthy: export failures without recent success")); err != nil {
				return
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok: no recent success but last attempt did not fail")); err != nil {
			return
		}
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if r.ready.Load() {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("ready")); err != nil {
				return
			}
		} else {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
		}
	})
}
func (r *Registry) SetReady(v bool) { r.ready.Store(v) }
func (r *Registry) SetLivenessWindow(d time.Duration) {
	if d <= 0 {
		d = 5 * time.Minute
	}
	r.livenessWindowNs.Store(int64(d))
}
func (r *Registry) RecordExportOutcome(success bool) {
	now := time.Now().UnixNano()
	if success {
		r.lastExportSuccess.Store(now)
		return
	}
	r.lastExportFailure.Store(now)
}
func (r *Registry) ObserveLatency(pipeline, endpoint string, d time.Duration) {
	r.ExportLatency.WithLabelValues(pipeline, endpoint).Observe(d.Seconds())
}

func SetGlobalRegistry(r *Registry) {
	globalRegistry.Store(r)
}

func GlobalRegistry() *Registry {
	return globalRegistry.Load()
}
