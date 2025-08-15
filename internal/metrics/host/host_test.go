package host

import (
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
)

func TestAppendPoint_SetsMetricAndLabels(t *testing.T) {
	// Minimal collector with stable fields for base labels.
	c := &Collector{job: "telegen", instance: "hostA"}

	var wr prompb.WriteRequest
	extra := []labels.Label{{Name: "device", Value: "eth0"}}
	lbls := c.baseLabels(extra...)
	appendPoint(&wr, "system_network_transmit_bytes_total", lbls, 123.45)

	if len(wr.Timeseries) != 1 {
		t.Fatalf("expected 1 timeseries, got %d", len(wr.Timeseries))
	}
	ts := wr.Timeseries[0]

	// Expect one sample with a recent timestamp.
	if len(ts.Samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(ts.Samples))
	}
	if time.Since(time.UnixMilli(ts.Samples[0].Timestamp)) > time.Second*5 {
		t.Fatalf("sample timestamp too old")
	}

	// Validate labels.
	want := map[string]string{
		"__name__": "system_network_transmit_bytes_total",
		"job":      "telegen",
		"instance": "hostA",
		"device":   "eth0",
	}
	got := map[string]string{}
	for _, l := range ts.Labels {
		got[l.Name] = l.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("label %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestBaseLabels_IncludesJobAndInstance(t *testing.T) {
	c := &Collector{job: "telegen", instance: "hostB"}
	lbls := c.baseLabels(labels.Label{Name: "x", Value: "y"})

	// Convert to map for easy assertions.
	m := map[string]string{}
	for _, l := range lbls {
		m[l.Name] = l.Value
	}

	if m["job"] != "telegen" || m["instance"] != "hostB" {
		t.Fatalf("baseLabels missing job/instance: %#v", m)
	}
	if m["x"] != "y" {
		t.Fatalf("baseLabels missing passthrough label x=y: %#v", m)
	}
	// __name__ placeholder should be present in the label list (set by appendPoint).
	if _, ok := m["__name__"]; !ok {
		t.Fatalf("__name__ placeholder not present in baseLabels result")
	}
}
