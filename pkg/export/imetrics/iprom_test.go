package imetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Regression guard for the agent crash "panic: duplicate metrics collector registration
// attempted". Constructing the reporter twice against one shared registry must degrade,
// never panic.
func TestNewPrometheusReporter_DuplicateRegistrationDoesNotPanic(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	cfg := &Config{Exporter: InternalMetricsExporterPrometheus}

	if first := NewPrometheusReporter(cfg, nil, reg); first == nil {
		t.Fatal("first reporter is nil")
	}
	if second := NewPrometheusReporter(cfg, nil, reg); second == nil {
		t.Fatal("second reporter is nil")
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed after duplicate registration: %v", err)
	}
	if len(families) == 0 {
		t.Fatal("no metric families registered in the shared registry")
	}
	seen := map[string]int{}
	for _, f := range families {
		seen[f.GetName()]++
	}
	for name, count := range seen {
		if count != 1 {
			t.Fatalf("metric family %q present %d times, want 1", name, count)
		}
	}
}
