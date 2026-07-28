// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubemetrics

import (
	"context"
	"testing"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type captureSDKLogExporter struct {
	records []sdklog.Record
}

func (c *captureSDKLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	for _, record := range records {
		c.records = append(c.records, record.Clone())
	}
	return nil
}

func (c *captureSDKLogExporter) Shutdown(ctx context.Context) error {
	return nil
}

func (c *captureSDKLogExporter) ForceFlush(ctx context.Context) error {
	return nil
}

func TestLoggerProviderExporter_ExportsKubernetesEvents(t *testing.T) {
	ctx := context.Background()
	capture := &captureSDKLogExporter{}
	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(capture)),
	)
	defer func() {
		_ = loggerProvider.Shutdown(ctx)
	}()

	exporter := NewLoggerProviderExporter(loggerProvider)
	if exporter == nil {
		t.Fatalf("expected non-nil exporter")
	}

	logsStreamer := &LogsStreamingExporter{
		config: &LogsStreamingConfig{
			IncludeSignalMetadata: false,
		},
		resource: resource.NewSchemaless(),
	}

	eventTime := time.Now().UTC()
	events := []*corev1.Event{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "evt-1",
				Namespace: "default",
			},
			InvolvedObject: corev1.ObjectReference{
				Kind: "Pod",
				Name: "demo-pod",
				UID:  types.UID("uid-1"),
			},
			Reason:        "BackOff",
			Message:       "Back-off pulling image",
			Source:        corev1.EventSource{Component: "kubelet", Host: "node-a"},
			Type:          "Warning",
			Action:        "Pulling",
			LastTimestamp: metav1.NewTime(eventTime),
		},
	}

	logRecords := logsStreamer.convertToLogs(events)
	if len(logRecords) != 1 {
		t.Fatalf("expected one converted log record, got %d", len(logRecords))
	}

	if err := exporter.Export(ctx, logRecords); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if err := loggerProvider.ForceFlush(ctx); err != nil {
		t.Fatalf("force flush failed: %v", err)
	}

	if len(capture.records) != 1 {
		t.Fatalf("expected exactly one emitted sdk log record, got %d", len(capture.records))
	}

	record := capture.records[0]
	if record.SeverityText() != "WARN" {
		t.Fatalf("expected severity text WARN, got %q", record.SeverityText())
	}
	if record.Severity() != otellog.SeverityWarn {
		t.Fatalf("expected severity WARN, got %v", record.Severity())
	}
	if got := record.Body().AsString(); got != "Back-off pulling image" {
		t.Fatalf("unexpected body: got %q", got)
	}

	attrMap := make(map[string]string)
	record.WalkAttributes(func(kv otellog.KeyValue) bool {
		attrMap[kv.Key] = kv.Value.AsString()
		return true
	})

	if got := attrMap["k8s.event.reason"]; got != "BackOff" {
		t.Fatalf("expected k8s.event.reason=BackOff, got %q", got)
	}
	if got := attrMap["k8s.object.kind"]; got != "Pod" {
		t.Fatalf("expected k8s.object.kind=Pod, got %q", got)
	}
}
