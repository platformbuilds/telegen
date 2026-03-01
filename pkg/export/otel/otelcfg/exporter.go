// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "github.com/mirastacklabs-ai/telegen/pkg/export/otel/otelcfg"

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func meilog() *slog.Logger {
	return slog.With("component", "otelcommon.MetricsExporterInstancer")
}

// MetricsExporterInstancer provides a common instance for the OTEL metrics exporter,
// so all the OTEL metric families (RED, Network, Service Graph, Internal...) would go through
// the same connection/instance
type MetricsExporterInstancer struct {
	mutex    sync.Mutex
	instance sdkmetric.Exporter
	Cfg      *MetricsConfig
	// SharedExporter is the pre-created exporter from the unified OTLP pipeline.
	// This is REQUIRED - all signals (kube_metrics, node_exporter, ebpf, etc.) must share
	// the same OTLP connection. This is the telegen design principle: one agent, one exporter.
	SharedExporter sdkmetric.Exporter
}

// Instantiate returns the OTLP metrics exporter from the unified pipeline.
// The SharedExporter MUST be set - telegen requires all signals to use the unified exporter.
func (i *MetricsExporterInstancer) Instantiate(ctx context.Context) (sdkmetric.Exporter, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	if i.instance != nil {
		return i.instance, nil
	}

	// SharedExporter from the unified OTLP pipeline is required
	if i.SharedExporter != nil {
		meilog().Info("using shared metrics exporter from unified OTLP pipeline")
		i.instance = i.SharedExporter
		return i.instance, nil
	}

	// If a MetricsConsumer is configured (for testing/vendored mode), use the ConsumerExporter
	if i.Cfg != nil && i.Cfg.MetricsConsumer != nil {
		meilog().Debug("instantiating Consumer MetricsReporter")
		i.instance = NewConsumerExporter(i.Cfg.MetricsConsumer)
		return i.instance, nil
	}

	// No fallback - shared exporter is required
	return nil, fmt.Errorf("SharedExporter is required: telegen requires all signals to use the unified OTLP exporter. " +
		"Ensure the unified OTLP pipeline is initialized before starting eBPF instrumentation")
}
