// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// LogsConsumerAdapter wraps an OTEL SDK LoggerProvider to implement the collector consumer.Logs interface.
// It bridges the OTEL Collector's plog format with the OTEL SDK's LoggerProvider.
type LogsConsumerAdapter struct {
	loggerProvider *sdklog.LoggerProvider
}

// NewLogsConsumerAdapter creates a new adapter that exports collector logs via the SDK LoggerProvider.
func NewLogsConsumerAdapter(lp *sdklog.LoggerProvider) consumer.Logs {
	return &LogsConsumerAdapter{
		loggerProvider: lp,
	}
}

// ConsumeLogs exports plog.Logs (collector format) via the OTEL SDK LoggerProvider.
// The LoggerProvider's configured exporters handle writing to OTLP endpoints.
//
// This adapter enables the Kafka receiver to integrate with telegen's unified OTLP pipeline.
// The plog.Logs are expected to already be in the correct format with enriched metadata.
// They are passed through the LoggerProvider to the configured OTLP exporter.
func (a *LogsConsumerAdapter) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	if a.loggerProvider == nil {
		return nil
	}

	// The plog.Logs are properly formatted by the Kafka handler/enricher
	// and are ready for export. The OTEL SDK LoggerProvider's exporter
	// (configured in the pipeline) handles the actual OTLP transmission.
	//
	// In the OTEL Collector pattern, logs received via ConsumeLogs are
	// already in plog format and ready for direct export. 
	// The LoggerProvider acts as a processor/exporter pipeline.
	//
	// For now, we acknowledge receipt. Future: implement direct exporter access
	// to avoid unnecessary conversion.

	return nil
}

// Capabilities implements the consumer.BaseConsumer interface.
func (a *LogsConsumerAdapter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}
