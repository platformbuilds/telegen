// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/types"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

type deadlineExporter struct {
	exportCalled bool
	hasDeadline  bool
	deadline     time.Time
	err          error
}

func (e *deadlineExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (e *deadlineExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.AggregationDefault{}
}

func (e *deadlineExporter) Export(ctx context.Context, _ *metricdata.ResourceMetrics) error {
	e.exportCalled = true
	e.deadline, e.hasDeadline = ctx.Deadline()
	return e.err
}

func (e *deadlineExporter) ForceFlush(context.Context) error { return nil }
func (e *deadlineExporter) Shutdown(context.Context) error   { return nil }

func boolPtr(v bool) *bool { return &v }

func scrapeSuccessByCollector(sink *metricSink) map[string]float64 {
	out := make(map[string]float64)
	for _, m := range sink.metrics() {
		if m.Name != "vmware_scrape_collector_success" {
			continue
		}
		out[m.Labels["collector"]] = m.Value
	}
	return out
}

func TestRunCollectors_RecoversPanic(t *testing.T) {
	t.Parallel()

	m := &Manager{
		cfg: vmwaredef.Config{
			Collectors: vmwaredef.Collectors{
				Datacenter: boolPtr(true),
				Cluster:    boolPtr(true),
				Datastore:  boolPtr(false),
				Host:       boolPtr(false),
				VM:         boolPtr(false),
			},
		},
		log: testLogger(),
	}
	s := &vcSession{
		target: "vc",
		client: &vim25.Client{
			ServiceContent: types.ServiceContent{
				About: types.AboutInfo{Version: "8.0.0", Build: "1"},
			},
		},
		ctx: context.Background(),
	}
	sink := &metricSink{timestamp: time.Now().UTC()}

	ok := m.runCollectors(s, sink, newTargetState(), testLogger())
	if ok {
		t.Fatal("expected panic in collector path to be recovered and reported as failure")
	}
	success := scrapeSuccessByCollector(sink)
	if success["datacenter"] != 0 {
		t.Fatalf("datacenter success = %v, want 0 after panic", success["datacenter"])
	}
	if success["cluster"] != 0 {
		t.Fatalf("cluster success = %v, want 0 after panic", success["cluster"])
	}
}

func TestRunCollectorsWithSharedInventory_ErrorIsMarkedFailed(t *testing.T) {
	t.Parallel()

	m := &Manager{
		cfg: vmwaredef.Config{
			Collectors: vmwaredef.Collectors{
				Datacenter: boolPtr(false),
				Cluster:    boolPtr(false),
				Datastore:  boolPtr(false),
				Host:       boolPtr(true),
				VM:         boolPtr(true),
			},
		},
		log: testLogger(),
	}
	s := &vcSession{
		target: "vc",
		ctx:    context.Background(),
		cfg:    vmwaredef.Config{CollectInterval: time.Minute, Interval: 20},
	}
	sink := &metricSink{timestamp: time.Now().UTC()}

	ok := m.runCollectorsWithSharedInventory(
		s,
		sink,
		newTargetState(),
		testLogger(),
		nil,
		errors.New("vm fetch failed"),
		nil,
		nil,
		nil,
		nil,
	)
	if ok {
		t.Fatal("expected overall collector result to be degraded when one collector returns error")
	}

	success := scrapeSuccessByCollector(sink)
	if success["vm"] != 0 {
		t.Fatalf("vm success = %v, want 0 for erroring collector", success["vm"])
	}
	if success["host"] != 1 {
		t.Fatalf("host success = %v, want 1 for sibling collector", success["host"])
	}
}

func TestRunCollectorsWithSharedInventory_AllSuccess(t *testing.T) {
	t.Parallel()

	m := &Manager{
		cfg: vmwaredef.Config{
			Collectors: vmwaredef.Collectors{
				Datacenter: boolPtr(false),
				Cluster:    boolPtr(false),
				Datastore:  boolPtr(true),
				Host:       boolPtr(true),
				VM:         boolPtr(true),
			},
		},
		log: testLogger(),
	}
	s := &vcSession{
		target: "vc",
		ctx:    context.Background(),
		cfg:    vmwaredef.Config{CollectInterval: time.Minute, Interval: 20},
	}
	sink := &metricSink{timestamp: time.Now().UTC()}

	ok := m.runCollectorsWithSharedInventory(
		s,
		sink,
		newTargetState(),
		testLogger(),
		nil, nil,
		nil, nil,
		nil, nil,
	)
	if !ok {
		t.Fatal("expected overall collector result to be healthy")
	}

	success := scrapeSuccessByCollector(sink)
	for _, collector := range []string{"datastore", "host", "vm"} {
		if success[collector] != 1 {
			t.Fatalf("%s success = %v, want 1", collector, success[collector])
		}
	}
}

func TestExportTargetMetrics_ContextAndState(t *testing.T) {
	t.Parallel()

	exp := &deadlineExporter{}
	m := &Manager{
		cfg:     vmwaredef.Config{CollectInterval: time.Minute},
		metrics: exp,
		log:     testLogger(),
	}
	st := newTargetState()
	sink := &metricSink{timestamp: time.Now().UTC()}
	sink.add(vmwaredef.Metric{
		Name:            "vmware_host_info",
		Type:            vmwaredef.MetricTypeGauge,
		Value:           1,
		Labels:          map[string]string{"host": "esx-1"},
		Timestamp:       time.Now().UTC(),
		TimestampSource: vmwaredef.TimestampFromSource,
	})

	before := time.Now()
	m.exportTargetMetrics(context.Background(), "vc", sink, st, testLogger())
	after := time.Now()

	if !exp.exportCalled {
		t.Fatal("expected metrics exporter to be called")
	}
	if !exp.hasDeadline {
		t.Fatal("expected export context to have deadline")
	}
	if exp.deadline.Before(before.Add(20*time.Second)) || exp.deadline.After(after.Add(35*time.Second)) {
		t.Fatalf("unexpected export deadline %v", exp.deadline)
	}

	ok, d, seen := st.takeExport()
	if !seen {
		t.Fatal("expected export outcome to be stored in target state")
	}
	if !ok {
		t.Fatal("expected successful export state")
	}
	if d <= 0 {
		t.Fatalf("expected positive export duration, got %v", d)
	}
}

func TestExportTargetMetrics_ErrorStored(t *testing.T) {
	t.Parallel()

	exp := &deadlineExporter{err: errors.New("export failed")}
	m := &Manager{
		cfg:     vmwaredef.Config{CollectInterval: time.Minute},
		metrics: exp,
		log:     testLogger(),
	}
	st := newTargetState()
	sink := &metricSink{timestamp: time.Now().UTC()}
	sink.add(vmwaredef.Metric{
		Name:            "vmware_host_info",
		Type:            vmwaredef.MetricTypeGauge,
		Value:           1,
		Labels:          map[string]string{"host": "esx-1"},
		Timestamp:       time.Now().UTC(),
		TimestampSource: vmwaredef.TimestampFromSource,
	})

	m.exportTargetMetrics(context.Background(), "vc", sink, st, testLogger())
	ok, _, seen := st.takeExport()
	if !seen {
		t.Fatal("expected failed export outcome to be stored")
	}
	if ok {
		t.Fatal("expected failed export state")
	}
}
