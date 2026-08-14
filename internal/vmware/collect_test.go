// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/vmware/govmomi/performance"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testCounterInfo() map[string]*types.PerfCounterInfo {
	return map[string]*types.PerfCounterInfo{
		"cpu.usagemhz.average": {
			UnitInfo: &types.ElementDescription{Description: types.Description{Label: "mhz"}},
			NameInfo: &types.ElementDescription{Description: types.Description{Summary: "CPU usage"}},
		},
	}
}

func TestEmitPerformanceMetrics_PerSample(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	fallback := base.Add(5 * time.Minute)
	sink := &metricSink{}
	metrics := []performance.EntityMetric{
		{
			Entity: types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-1"},
			SampleInfo: []types.PerfSampleInfo{
				{Timestamp: base},
				{Timestamp: base.Add(20 * time.Second)},
				{Timestamp: base.Add(40 * time.Second)},
			},
			Value: []performance.MetricSeries{
				{
					Name:  "cpu.usagemhz.average",
					Value: []int64{100, 200, 300},
				},
			},
		},
	}

	emitPerformanceMetrics(
		sink,
		"vc",
		"VirtualMachine",
		"vm",
		"",
		testCounterInfo(),
		map[string]string{"vm-1": "vm-a"},
		metrics,
		fallback,
		testLogger(),
	)

	out := sink.metrics()
	if len(out) != 3 {
		t.Fatalf("expected 3 datapoints, got %d", len(out))
	}
	wantValues := []float64{100, 200, 300}
	wantTimes := []time.Time{base, base.Add(20 * time.Second), base.Add(40 * time.Second)}
	for i := range out {
		if out[i].Value != wantValues[i] {
			t.Fatalf("point %d value = %v, want %v", i, out[i].Value, wantValues[i])
		}
		if !out[i].Timestamp.Equal(wantTimes[i]) {
			t.Fatalf("point %d timestamp = %v, want %v", i, out[i].Timestamp, wantTimes[i])
		}
		if out[i].TimestampSource != vmwaredef.TimestampFromSource {
			t.Fatalf("point %d source = %v, want %v", i, out[i].TimestampSource, vmwaredef.TimestampFromSource)
		}
	}
}

func TestEmitPerformanceMetrics_LabelMapIndependence(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	sink := &metricSink{}
	metrics := []performance.EntityMetric{
		{
			Entity: types.ManagedObjectReference{Type: "HostSystem", Value: "host-1"},
			SampleInfo: []types.PerfSampleInfo{
				{Timestamp: base},
			},
			Value: []performance.MetricSeries{
				{
					Name:     "cpu.usagemhz.average",
					Instance: "vmnic0",
					Value:    []int64{10},
				},
				{
					Name:     "cpu.usagemhz.average",
					Instance: "vmnic1",
					Value:    []int64{20},
				},
			},
		},
	}

	emitPerformanceMetrics(
		sink,
		"vc",
		"HostSystem",
		"host",
		"",
		testCounterInfo(),
		map[string]string{"host-1": "esx-a"},
		metrics,
		base.Add(time.Minute),
		testLogger(),
	)

	out := sink.metrics()
	if len(out) != 2 {
		t.Fatalf("expected 2 datapoints, got %d", len(out))
	}
	if out[0].Labels["pfinstance"] != "vmnic0" || out[1].Labels["pfinstance"] != "vmnic1" {
		t.Fatalf("unexpected pfinstance labels: %q %q", out[0].Labels["pfinstance"], out[1].Labels["pfinstance"])
	}

	out[0].Labels["pfinstance"] = "mutated"
	if got := out[1].Labels["pfinstance"]; got != "vmnic1" {
		t.Fatalf("label maps are shared; second pfinstance = %q, want vmnic1", got)
	}
}

func TestEmitPerformanceMetrics_LengthMismatchSkipped(t *testing.T) {
	t.Parallel()

	sink := &metricSink{}
	metrics := []performance.EntityMetric{
		{
			Entity: types.ManagedObjectReference{Type: "HostSystem", Value: "host-1"},
			SampleInfo: []types.PerfSampleInfo{
				{Timestamp: time.Now().UTC()},
				{Timestamp: time.Now().UTC().Add(20 * time.Second)},
				{Timestamp: time.Now().UTC().Add(40 * time.Second)},
			},
			Value: []performance.MetricSeries{
				{
					Name:  "cpu.usagemhz.average",
					Value: []int64{100, 200},
				},
			},
		},
	}

	emitPerformanceMetrics(sink, "vc", "HostSystem", "host", "", testCounterInfo(), map[string]string{"host-1": "esx"}, metrics, time.Now().UTC(), testLogger())
	if got := len(sink.metrics()); got != 0 {
		t.Fatalf("expected mismatch series to be skipped, got %d metrics", got)
	}
}

func TestEmitPerformanceMetrics_ZeroTimestampFallback(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	fallback := base.Add(2 * time.Minute)
	sink := &metricSink{}
	metrics := []performance.EntityMetric{
		{
			Entity: types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-1"},
			SampleInfo: []types.PerfSampleInfo{
				{Timestamp: base},
				{Timestamp: time.Time{}},
			},
			Value: []performance.MetricSeries{
				{
					Name:  "cpu.usagemhz.average",
					Value: []int64{10, 20},
				},
			},
		},
	}

	emitPerformanceMetrics(sink, "vc", "VirtualMachine", "vm", "", testCounterInfo(), map[string]string{"vm-1": "vm-a"}, metrics, fallback, testLogger())
	out := sink.metrics()
	if len(out) != 2 {
		t.Fatalf("expected 2 datapoints, got %d", len(out))
	}
	if out[0].TimestampSource != vmwaredef.TimestampFromSource {
		t.Fatalf("first datapoint source = %v, want source", out[0].TimestampSource)
	}
	if out[1].TimestampSource != vmwaredef.TimestampFromFallback {
		t.Fatalf("second datapoint source = %v, want fallback", out[1].TimestampSource)
	}
	if !out[1].Timestamp.Equal(fallback) {
		t.Fatalf("fallback timestamp = %v, want %v", out[1].Timestamp, fallback)
	}
}

func TestEmitPerformanceMetrics_UnknownCounterSkipped(t *testing.T) {
	t.Parallel()

	sink := &metricSink{}
	metrics := []performance.EntityMetric{
		{
			Entity: types.ManagedObjectReference{Type: "HostSystem", Value: "host-1"},
			SampleInfo: []types.PerfSampleInfo{
				{Timestamp: time.Now().UTC()},
			},
			Value: []performance.MetricSeries{
				{
					Name:  "mem.unknown.average",
					Value: []int64{1},
				},
			},
		},
	}

	emitPerformanceMetrics(sink, "vc", "HostSystem", "host", "", testCounterInfo(), map[string]string{"host-1": "esx"}, metrics, time.Now().UTC(), testLogger())
	if got := len(sink.metrics()); got != 0 {
		t.Fatalf("expected unknown counter to be skipped, got %d metrics", got)
	}
}
