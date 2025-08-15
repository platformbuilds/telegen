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
    QueueSize    *prometheus.GaugeVec
    QueueDropped *prometheus.CounterVec
    ExportFails  *prometheus.CounterVec
    ExportLatency *prometheus.HistogramVec
    RingEvents   prometheus.Counter
    RingLost     prometheus.Counter
    ready atomic.Bool
}

func NewRegistry(namespace string) *Registry {
    if namespace == "" { namespace = "telegen" }
    r := &Registry{ }
    r.QueueSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{ Namespace: namespace, Name: "agent_queue_size" }, []string{"pipeline"})
    r.QueueDropped = prometheus.NewCounterVec(prometheus.CounterOpts{ Namespace: namespace, Name: "agent_queue_dropped_total" }, []string{"pipeline","reason"})
    r.ExportFails  = prometheus.NewCounterVec(prometheus.CounterOpts{ Namespace: namespace, Name: "agent_export_failures_total" }, []string{"pipeline","endpoint"})
    r.ExportLatency= prometheus.NewHistogramVec(prometheus.HistogramOpts{ Namespace: namespace, Name: "agent_export_latency_seconds", Buckets: prometheus.DefBuckets }, []string{"pipeline","endpoint"})
    r.RingEvents   = prometheus.NewCounter(prometheus.CounterOpts{ Namespace: namespace, Name: "agent_ringbuf_events_total" })
    r.RingLost     = prometheus.NewCounter(prometheus.CounterOpts{ Namespace: namespace, Name: "agent_ringbuf_lost_total" })
    prometheus.MustRegister(r.QueueSize, r.QueueDropped, r.ExportFails, r.ExportLatency, r.RingEvents, r.RingLost)
    return r
}
func InstallHandlers(mux *http.ServeMux, listen string) *Registry {
    r := NewRegistry("telegen")
    mux.Handle("/metrics", promhttp.Handler())
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request){ w.WriteHeader(http.StatusOK); w.Write([]byte("ok")) })
    mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request){
        if r.ready.Load() { w.WriteHeader(http.StatusOK); w.Write([]byte("ready")) } else { http.Error(w, "not ready", http.StatusServiceUnavailable) }
    })
    log.Printf("self-telemetry HTTP on %s", listen)
    return r
}
func (r *Registry) SetReady(v bool){ r.ready.Store(v) }
func (r *Registry) ObserveLatency(pipeline, endpoint string, d time.Duration){
    r.ExportLatency.WithLabelValues(pipeline, endpoint).Observe(d.Seconds())
}
