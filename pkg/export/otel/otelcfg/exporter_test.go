// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const testTimeout = 5 * time.Second

// mockExporter is a simple mock for testing
type mockExporter struct{}

func (m *mockExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error { return nil }
func (m *mockExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}
func (m *mockExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}
func (m *mockExporter) ForceFlush(ctx context.Context) error { return nil }
func (m *mockExporter) Shutdown(ctx context.Context) error   { return nil }

// Tests that the Instantiate method of Exporter always returns the same instance
// even if invoked concurrently
func TestSingleton(t *testing.T) {
	concurrency := 50
	sharedExporter := &mockExporter{}
	instancer := MetricsExporterInstancer{
		SharedExporter: sharedExporter,
	}
	// run multiple exporters concurrently
	exporters := make(chan sdkmetric.Exporter, concurrency)
	errs := make(chan error, concurrency)
	for range concurrency {
		go func() {
			if exp, err := instancer.Instantiate(t.Context()); err != nil {
				errs <- err
			} else {
				exporters <- exp
			}
		}()
	}
	// all the Instantiate invocations should return the same instance
	get := func() sdkmetric.Exporter {
		select {
		case <-time.After(testTimeout):
			t.Fatal("timeout waiting for exporter")
		case exp := <-exporters:
			return exp
		case err := <-errs:
			t.Fatalf("unexpected error: %v", err)
		}
		return nil
	}
	ref := get()
	for i := 0; i < concurrency-1; i++ {
		if exp := get(); exp != ref {
			t.Fatalf("expected exporter to be the same as %p, got %p", ref, exp)
		}
	}
}
