package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestExpirerWithLabelValues_LabelMismatchFallsBackToNoop(t *testing.T) {
	cv := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "telegen_prom_expirer_label_mismatch_test_total",
			Help: "test metric",
		},
		[]string{"k1"},
	)
	ex := NewExpirer[prometheus.Counter](cv.MetricVec, time.Now, time.Minute)

	before := testutil.ToFloat64(expirerDropped.WithLabelValues(ex.name, "label_mismatch"))
	entry := ex.WithLabelValues("v1", "v2")
	entry.Metric.Inc()
	after := testutil.ToFloat64(expirerDropped.WithLabelValues(ex.name, "label_mismatch"))

	if after != before+1 {
		t.Fatalf("expected dropped counter increment by 1, before=%v after=%v", before, after)
	}
}

func TestExpirerWithLabelValues_TypeAssertionFallbackToNoop(t *testing.T) {
	cv := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "telegen_prom_expirer_type_assert_test_total",
			Help: "test metric",
		},
		[]string{"k1"},
	)
	ex := NewExpirer[prometheus.Gauge](cv.MetricVec, time.Now, time.Minute)

	before := testutil.ToFloat64(expirerDropped.WithLabelValues(ex.name, "type_assert"))
	entry := ex.WithLabelValues("v1")
	entry.Metric.Set(1)
	after := testutil.ToFloat64(expirerDropped.WithLabelValues(ex.name, "type_assert"))

	if after != before+1 {
		t.Fatalf("expected dropped counter increment by 1, before=%v after=%v", before, after)
	}
}
