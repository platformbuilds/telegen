// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/twmb/franz-go/pkg/kgo"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"

	"github.com/platformbuilds/telegen/internal/logs/parsers"
)

// MessageHandler handles the conversion of Kafka messages to OTLP log records
type MessageHandler struct {
	parserPipeline *parsers.Pipeline
	enricher       *LogEnricher
	logger         *slog.Logger
	zapLogger      *zap.Logger
}

// NewMessageHandler creates a new message handler
func NewMessageHandler(parserPipeline *parsers.Pipeline, enricher *LogEnricher, logger *slog.Logger, zapLogger *zap.Logger) *MessageHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &MessageHandler{
		parserPipeline: parserPipeline,
		enricher:       enricher,
		logger:         logger,
		zapLogger:      zapLogger,
	}
}

// HandleMessage processes a single Kafka message through the parsing and enrichment pipeline
func (h *MessageHandler) HandleMessage(ctx context.Context, kafkaMsg *kgo.Record) (*parsers.ParsedLog, error) {
	if kafkaMsg == nil || len(kafkaMsg.Value) == 0 {
		return nil, fmt.Errorf("empty or nil Kafka message")
	}

	// Stage 1: Parse the message using the existing pipeline
	// This handles auto-detection and parsing of:
	// - Docker JSON format
	// - CRI-O format
	// - Containerd format
	// - Spring Boot format
	// - Log4j format
	// - Generic JSON format
	// - Plaintext fallback
	messageStr := string(kafkaMsg.Value)
	parsed := h.parserPipeline.Parse(messageStr, "")

	if parsed == nil {
		return nil, fmt.Errorf("failed to parse message")
	}

	// Stage 2: Enrich with Kafka and Telegen metadata
	h.enricher.Enrich(parsed, kafkaMsg)

	if h.logger.Enabled(ctx, slog.LevelDebug) {
		h.logger.DebugContext(ctx, "kafka message processed",
			slog.String("topic", kafkaMsg.Topic),
			slog.Int64("partition", int64(kafkaMsg.Partition)),
			slog.Int64("offset", kafkaMsg.Offset),
			slog.String("format", parsed.Format),
			slog.String("severity", string(parsed.Severity)),
			slog.String("body_preview", truncate(parsed.Body, 100)),
		)
	}

	return parsed, nil
}

// ConvertToLogRecords converts parsed logs to OTel log records for export
func (h *MessageHandler) ConvertToLogRecords(parsed *parsers.ParsedLog) (parsers.ParsedLog, error) {
	if parsed == nil {
		return parsers.ParsedLog{}, fmt.Errorf("nil parsed log")
	}

	// The ParsedLog is already in the correct format to be converted to OTel
	// The caller will use ParsedLog.ToOTelRecord() to convert to OTel format
	return *parsed, nil
}

// ProcessMessage is a convenience method that handles the full processing pipeline
func (h *MessageHandler) ProcessMessage(ctx context.Context, kafkaMsg *kgo.Record) (*parsers.ParsedLog, error) {
	parsed, err := h.HandleMessage(ctx, kafkaMsg)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to handle message",
			slog.String("error", err.Error()),
			slog.String("topic", kafkaMsg.Topic),
			slog.Int64("offset", kafkaMsg.Offset),
		)
		return nil, err
	}

	_, err = h.ConvertToLogRecords(parsed)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to convert to log records",
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	return parsed, nil
}

// truncate returns a truncated string with ellipsis if longer than maxLen
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// MessageProcessingAttributes creates OTel attributes for message processing telemetry
func MessageProcessingAttributes(kafkaMsg *kgo.Record) attribute.Set {
	return attribute.NewSet(
		attribute.String("topic", kafkaMsg.Topic),
		attribute.Int64("partition", int64(kafkaMsg.Partition)),
		attribute.Int64("offset", kafkaMsg.Offset),
	)
}
