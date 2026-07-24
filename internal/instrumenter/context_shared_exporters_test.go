package instrumenter

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/mirastacklabs-ai/telegen/internal/obi"
)

type fakeTracesExporter struct{}

func (f *fakeTracesExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (f *fakeTracesExporter) ConsumeTraces(context.Context, ptrace.Traces) error {
	return nil
}

func (f *fakeTracesExporter) Start(context.Context, component.Host) error {
	return nil
}

func (f *fakeTracesExporter) Shutdown(context.Context) error {
	return nil
}

func TestBuildCommonContextInfoWithExporter_SetsSharedTracesExporter(t *testing.T) {
	t.Parallel()

	cfg := obi.DefaultConfig
	cfg.Attributes.HostID.Override = "test-host"

	shared := &fakeTracesExporter{}

	ctxInfo, err := BuildCommonContextInfoWithExporter(context.Background(), &cfg, nil, shared)
	if err != nil {
		t.Fatalf("BuildCommonContextInfoWithExporter failed: %v", err)
	}
	if ctxInfo == nil {
		t.Fatal("context info is nil")
	}
	if ctxInfo.OTELTracesExporter != shared {
		t.Fatal("shared traces exporter was not preserved in context info")
	}
}
