// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

func TestMetricSink_AddScrapeResult(t *testing.T) {
	t.Parallel()

	sink := &metricSink{timestamp: time.Now().UTC()}
	sink.addScrapeResult("host", "vc-1", true, 1500*time.Millisecond)
	out := sink.metrics()
	if len(out) != 2 {
		t.Fatalf("expected 2 scrape metrics, got %d", len(out))
	}

	var foundSuccess, foundDuration bool
	for _, m := range out {
		switch m.Name {
		case "vmware_scrape_collector_success":
			foundSuccess = true
			if m.Value != 1 {
				t.Fatalf("success value = %v, want 1", m.Value)
			}
			if m.Labels["collector"] != "host" || m.Labels["vcenter"] != "vc-1" {
				t.Fatalf("unexpected success labels: %+v", m.Labels)
			}
			if m.TimestampSource != vmwaredef.TimestampFromCycleInstant {
				t.Fatalf("success timestamp source = %v, want cycle instant", m.TimestampSource)
			}
		case "vmware_scrape_collector_duration_seconds":
			foundDuration = true
			if m.Value != 1.5 {
				t.Fatalf("duration value = %v, want 1.5", m.Value)
			}
			if m.Labels["collector"] != "host" || m.Labels["vcenter"] != "vc-1" {
				t.Fatalf("unexpected duration labels: %+v", m.Labels)
			}
			if m.TimestampSource != vmwaredef.TimestampFromCycleInstant {
				t.Fatalf("duration timestamp source = %v, want cycle instant", m.TimestampSource)
			}
		}
	}
	if !foundSuccess || !foundDuration {
		t.Fatalf("missing expected scrape metrics (success=%v duration=%v)", foundSuccess, foundDuration)
	}
}

func TestMetricSink_AddScrapeResult_FailureAndLabelMapIndependence(t *testing.T) {
	t.Parallel()

	sink := &metricSink{timestamp: time.Now().UTC()}
	sink.addScrapeResult("vm", "vc-2", false, 2*time.Second)
	out := sink.metrics()
	if len(out) != 2 {
		t.Fatalf("expected 2 scrape metrics, got %d", len(out))
	}

	var successMetric, durationMetric *vmwaredef.Metric
	for i := range out {
		switch out[i].Name {
		case "vmware_scrape_collector_success":
			successMetric = &out[i]
		case "vmware_scrape_collector_duration_seconds":
			durationMetric = &out[i]
		}
	}
	if successMetric == nil || durationMetric == nil {
		t.Fatalf("missing scrape metrics: success=%v duration=%v", successMetric != nil, durationMetric != nil)
	}
	if successMetric.Value != 0 {
		t.Fatalf("success value = %v, want 0 when ok=false", successMetric.Value)
	}

	successMetric.Labels["collector"] = "mutated"
	if got := durationMetric.Labels["collector"]; got != "vm" {
		t.Fatalf("label maps are shared; duration collector label = %q, want vm", got)
	}
}

func TestTargetState_ExportCarryForward(t *testing.T) {
	t.Parallel()

	st := newTargetState()
	st.markExport(false, 2*time.Second)
	ok, d, seen := st.takeExport()
	if !seen {
		t.Fatal("expected export result to be visible once")
	}
	if ok {
		t.Fatal("expected ok=false")
	}
	if d != 2*time.Second {
		t.Fatalf("duration = %v, want 2s", d)
	}

	_, _, seen = st.takeExport()
	if seen {
		t.Fatal("expected export result to be consumed on first read")
	}
}
