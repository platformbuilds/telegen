// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "github.com/mirastacklabs-ai/telegen/pkg/export/prom"

import (
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/mirastacklabs-ai/telegen/pkg/export/expire"
)

func plog() *slog.Logger {
	return slog.With("component", "prom.Expirer")
}

// Expirer drops metrics from labels that haven't been updated during a given timeout
type Expirer[T prometheus.Metric] struct {
	entries *expire.ExpiryMap[*MetricEntry[T]]
	wrapped *prometheus.MetricVec
	name    string
}

type MetricEntry[T prometheus.Metric] struct {
	Metric    T
	LabelVals []string
}

var (
	expirerDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "telegen",
			Name:      "prom_expirer_dropped_total",
			Help:      "Number of metrics dropped by the Prom expirer fallback path.",
		},
		[]string{"metric", "reason"},
	)
	expirerRegisterOnce sync.Once
	expirerLastErrLog   atomic.Int64
)

// NewExpirer creates a metric that wraps a given CounterVec. Its labeled instances are dropped
// if they haven't been updated during the last timeout period
func NewExpirer[T prometheus.Metric](wrapped *prometheus.MetricVec, clock func() time.Time, expireTime time.Duration) *Expirer[T] {
	expirerRegisterOnce.Do(func() {
		prometheus.MustRegister(expirerDropped)
	})
	return &Expirer[T]{
		wrapped: wrapped,
		entries: expire.NewExpiryMap[*MetricEntry[T]](clock, expireTime),
		name:    metricVecName(wrapped),
	}
}

// WithLabelValues returns the Counter for the given slice of label
// values (same order as the variable labels in Desc). If that combination of
// label values is accessed for the first time, a new Counter is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
func (ex *Expirer[T]) WithLabelValues(lbls ...string) *MetricEntry[T] {
	return ex.entries.GetOrCreate(lbls, func() *MetricEntry[T] {
		plog().With("labelValues", lbls).Debug("storing new metric label set")
		c, err := ex.wrapped.GetMetricWithLabelValues(lbls...)
		if err != nil {
			ex.observeDrop("label_mismatch", lbls, err)
			return newNoopMetricEntry[T](lbls)
		}
		typedMetric, ok := castMetric[T](c)
		if !ok {
			ex.observeDrop("type_assert", lbls, fmt.Errorf("metric type assertion failed: got %T", c))
			return newNoopMetricEntry[T](lbls)
		}
		return &MetricEntry[T]{
			Metric:    typedMetric,
			LabelVals: lbls,
		}
	})
}

func (ex *Expirer[T]) observeDrop(reason string, lbls []string, err error) {
	expirerDropped.WithLabelValues(ex.name, reason).Inc()
	if shouldLogExpirerError(60 * time.Second) {
		plog().Error("prom expirer falling back to no-op metric",
			"metric", ex.name,
			"reason", reason,
			"label_count", len(lbls),
			"error", err,
		)
	}
}

func shouldLogExpirerError(interval time.Duration) bool {
	now := time.Now().UnixNano()
	last := expirerLastErrLog.Load()
	if last != 0 && now-last < interval.Nanoseconds() {
		return false
	}
	return expirerLastErrLog.CompareAndSwap(last, now)
}

func metricVecName(wrapped *prometheus.MetricVec) string {
	descs := make(chan *prometheus.Desc, 1)
	wrapped.Describe(descs)
	select {
	case d := <-descs:
		return d.String()
	default:
		return fmt.Sprintf("%T", wrapped)
	}
}

func newNoopMetricEntry[T prometheus.Metric](lbls []string) *MetricEntry[T] {
	return &MetricEntry[T]{
		Metric:    newNoopMetric[T](),
		LabelVals: append([]string(nil), lbls...),
	}
}

func castMetric[T prometheus.Metric](metric prometheus.Metric) (T, bool) {
	typedMetric, ok := any(metric).(T)
	return typedMetric, ok
}

func newNoopMetric[T prometheus.Metric]() T {
	var zero T
	metricType := reflect.TypeOf((*T)(nil)).Elem()
	switch {
	case metricType.Implements(reflect.TypeOf((*prometheus.Gauge)(nil)).Elem()):
		return any(noopGauge{}).(T)
	case metricType.Implements(reflect.TypeOf((*prometheus.Histogram)(nil)).Elem()):
		return any(noopHistogram{}).(T)
	case metricType.Implements(reflect.TypeOf((*prometheus.Counter)(nil)).Elem()):
		return any(noopCounter{}).(T)
	default:
		return zero
	}
}

type noopMetric struct{}

func (noopMetric) Desc() *prometheus.Desc {
	return prometheus.NewDesc("telegen_noop_metric", "noop metric", nil, nil)
}
func (noopMetric) Write(*dto.Metric) error          { return nil }
func (noopMetric) Describe(chan<- *prometheus.Desc) {}
func (noopMetric) Collect(chan<- prometheus.Metric) {}

type noopCounter struct{ noopMetric }

func (noopCounter) Inc()        {}
func (noopCounter) Add(float64) {}

type noopGauge struct{ noopMetric }

func (noopGauge) Set(float64)       {}
func (noopGauge) Inc()              {}
func (noopGauge) Dec()              {}
func (noopGauge) Add(float64)       {}
func (noopGauge) Sub(float64)       {}
func (noopGauge) SetToCurrentTime() {}

type noopHistogram struct{ noopMetric }

func (noopHistogram) Observe(float64) {}

// Describe wraps prometheus.Collector Describe method
func (ex *Expirer[T]) Describe(descs chan<- *prometheus.Desc) {
	ex.wrapped.Describe(descs)
}

// Collect wraps prometheus.Collector Wrap method
func (ex *Expirer[T]) Collect(metrics chan<- prometheus.Metric) {
	log := plog()
	for _, old := range ex.entries.DeleteExpired() {
		ex.wrapped.DeleteLabelValues(old.LabelVals...)
		log.With("labelValues", old).Debug("deleting old Prometheus metric")
	}
	for _, m := range ex.entries.All() {
		metrics <- m.Metric
	}
}
