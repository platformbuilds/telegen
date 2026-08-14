// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vmware/govmomi/performance"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

// newSimSession builds a vcSession backed by the govmomi simulator client.
func newSimSession(ctx context.Context, t *testing.T, c *vim25.Client) *vcSession {
	t.Helper()
	perf := performance.NewManager(c)
	counters, err := perf.CounterInfoByName(ctx)
	if err != nil {
		t.Fatalf("counter info: %v", err)
	}
	return &vcSession{
		target:   "vcsim",
		client:   c,
		view:     view.NewManager(c),
		perf:     perf,
		counters: counters,
		interval: 20,
		cfg:      vmwaredef.Config{CollectInterval: time.Minute, Interval: 20},
		ctx:      ctx,
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestCollectorsAgainstSimulator runs every ported collector against the govmomi
// vCenter simulator and asserts the expected vmware_* metric families appear.
func TestCollectorsAgainstSimulator(t *testing.T) {
	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		s := newSimSession(ctx, t, c)
		log := discardLogger()
		sink := &metricSink{}

		st := newTargetState()
		for name, fn := range map[string]func(*vcSession, *metricSink, *targetState, *slog.Logger) error{
			"datacenter": collectDatacenter,
			"cluster":    collectCluster,
			"datastore":  collectDatastore,
			"host":       collectHost,
			"vm":         collectVM,
		} {
			if err := fn(s, sink, st, log); err != nil {
				t.Errorf("collect %s: %v", name, err)
			}
		}

		metrics := sink.metrics()
		if len(metrics) == 0 {
			t.Fatal("no metrics collected from simulator")
		}

		names := make(map[string]bool)
		for _, m := range metrics {
			names[m.Name] = true
			if !strings.HasPrefix(m.Name, "vmware_") {
				t.Errorf("metric %q does not use vmware_ prefix", m.Name)
			}
			if m.Type != vmwaredef.MetricTypeGauge {
				t.Errorf("metric %q has unexpected type %q", m.Name, m.Type)
			}
			if _, ok := m.Labels["vcenter"]; !ok {
				t.Errorf("metric %q missing vcenter label", m.Name)
			}
		}

		// The simulator's default VPX inventory guarantees these families exist.
		for _, want := range []string{
			"vmware_vcenter_info",
			"vmware_datacenter_info",
			"vmware_host_info",
			"vmware_vm_info",
			"vmware_datastore_info",
			"vmware_datastore_capacity",
		} {
			if !names[want] {
				t.Errorf("expected metric %q not found", want)
			}
		}
	})
}

// TestEventsAndStateChangesAgainstSimulator exercises the logs path: event
// polling plus the two-pass state-change baseline/diff logic.
func TestEventsAndStateChangesAgainstSimulator(t *testing.T) {
	simulator.Test(func(ctx context.Context, c *vim25.Client) {
		s := newSimSession(ctx, t, c)
		log := discardLogger()
		st := newTargetState()

		// First poll establishes the watermark baseline and emits nothing.
		if recs := collectEvents(s, 50, st, log); len(recs) != 0 {
			t.Errorf("expected no events on baseline poll, got %d", len(recs))
		}
		if !st.haveEventKey {
			t.Fatal("event watermark baseline not established")
		}
		// Second poll with no new events should also emit nothing.
		if recs := collectEvents(s, 50, st, log); len(recs) != 0 {
			t.Errorf("expected no events on unchanged poll, got %d", len(recs))
		}

		// First state-change pass establishes the baseline and emits nothing.
		if recs := collectStateChanges(s, st, log); len(recs) != 0 {
			t.Errorf("expected no state-change logs on baseline pass, got %d", len(recs))
		}
		if !st.initialized.Load() {
			t.Fatal("state baseline not initialized")
		}
		if len(st.vmPower) == 0 {
			t.Error("expected VM power state baseline to be populated")
		}

		// Second pass with no changes should also emit nothing.
		if recs := collectStateChanges(s, st, log); len(recs) != 0 {
			t.Errorf("expected no state-change logs on unchanged pass, got %d", len(recs))
		}
	})
}
