package filetailer

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/mirastacklabs-ai/telegen/internal/logs/parsers"
)

type panickingParser struct{}

func (panickingParser) Parse(string) (*parsers.ParsedLog, error) {
	panic("panic from parser")
}

func (panickingParser) Name() string {
	return "panicking_parser"
}

func TestProcessLine_PanicIsContained(t *testing.T) {
	t.Parallel()

	lp := sdklog.NewLoggerProvider()
	tailer := NewWithOptions(Options{
		Globs:                []string{},
		LoggerProvider:       lp,
		ShipHistoricalEvents: false,
		StartTime:            time.Now(),
		PollInterval:         10 * time.Millisecond,
		ParserConfig:         DefaultParserConfig(),
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if tailer == nil {
		t.Fatal("tailer should not be nil")
	}

	tailer.pipeline.AddParser(panickingParser{})
	logger := lp.Logger("filelog")

	tailer.processLine(context.Background(), logger, "/var/log/containers/mypod_myns_mycontainer-abc123def456.log", "line 1", nil)
	tailer.processLine(context.Background(), logger, "/var/log/containers/mypod_myns_mycontainer-abc123def456.log", "line 2", nil)

	if got := tailer.parsePanics.Load(); got != 2 {
		t.Fatalf("parsePanics = %d, want %d", got, 2)
	}
}
