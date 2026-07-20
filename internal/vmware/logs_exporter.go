// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"

	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

// emitLogs emits the given records through the shared OTLP LoggerProvider using
// the OTel log bridge API (see internal/logs/filetailer/filetailer.go:306-343
// for the same pattern). It is a no-op when logs export is not configured.
func emitLogs(ctx context.Context, lp *sdklog.LoggerProvider, extra map[string]string, records []vmwaredef.LogRecord) {
	if lp == nil || len(records) == 0 {
		return
	}

	logger := lp.Logger(scopeName)
	for _, r := range records {
		var rec log.Record
		rec.SetTimestamp(r.Timestamp)
		rec.SetObservedTimestamp(r.Timestamp)
		rec.SetBody(log.StringValue(r.Body))
		rec.SetSeverity(mapSeverity(r.Severity))
		rec.SetSeverityText(severityText(r.Severity))
		for k, v := range r.Attributes {
			rec.AddAttributes(log.String(k, v))
		}
		for k, v := range extra {
			rec.AddAttributes(log.String(k, v))
		}
		logger.Emit(ctx, rec)
	}
}

// mapSeverity maps a normalized severity string to an OTel log severity.
func mapSeverity(sev string) log.Severity {
	switch sev {
	case "trace":
		return log.SeverityTrace
	case "debug":
		return log.SeverityDebug
	case "warn":
		return log.SeverityWarn
	case "error":
		return log.SeverityError
	default:
		return log.SeverityInfo
	}
}

func severityText(sev string) string {
	switch sev {
	case "trace":
		return "TRACE"
	case "debug":
		return "DEBUG"
	case "warn":
		return "WARN"
	case "error":
		return "ERROR"
	default:
		return "INFO"
	}
}
