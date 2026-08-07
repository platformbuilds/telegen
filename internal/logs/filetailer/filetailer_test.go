package filetailer

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func TestTailerTrackedPathCleanup(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	tailer := NewWithOptions(Options{
		Globs:                []string{filepath.Join(tempDir, "*.log")},
		LoggerProvider:       sdklog.NewLoggerProvider(),
		ShipHistoricalEvents: false,
		StartTime:            time.Now(),
		PollInterval:         10 * time.Millisecond,
		ParserConfig:         DefaultParserConfig(),
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if tailer == nil {
		t.Fatal("tailer should not be nil")
	}

	paths := make([]string, 0, 1000)
	for i := 0; i < 1000; i++ {
		path := filepath.Join(tempDir, "pod-"+strconv.Itoa(i)+".log")
		if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
			t.Fatalf("write test file %s: %v", path, err)
		}
		paths = append(paths, path)
		tailer.tailOnce(path)
	}

	if got := countSyncMapEntries(&tailer.filePositions); got != 1000 {
		t.Fatalf("expected 1000 tracked file positions, got %d", got)
	}
	if got := countSyncMapEntries(&tailer.initializedFiles); got != 1000 {
		t.Fatalf("expected 1000 tracked initialized files, got %d", got)
	}

	// Simulate discovery removing half of the files.
	discovered := make(map[string]struct{}, 500)
	for i := 0; i < 500; i++ {
		discovered[paths[i]] = struct{}{}
	}
	tailer.pruneTrackedPaths(discovered)

	if got := countSyncMapEntries(&tailer.filePositions); got != 500 {
		t.Fatalf("expected 500 tracked file positions after prune, got %d", got)
	}
	if got := countSyncMapEntries(&tailer.initializedFiles); got != 500 {
		t.Fatalf("expected 500 tracked initialized files after prune, got %d", got)
	}

	// Simulate missed delete events: remove the remaining files on disk and
	// rely on periodic sweeps to clean up stale entries.
	for i := 0; i < 500; i++ {
		if err := os.Remove(paths[i]); err != nil {
			t.Fatalf("remove test file %s: %v", paths[i], err)
		}
	}
	tailer.sweepMissingTrackedPaths()

	if got := countSyncMapEntries(&tailer.filePositions); got != 0 {
		t.Fatalf("expected 0 tracked file positions after sweep, got %d", got)
	}
	if got := countSyncMapEntries(&tailer.initializedFiles); got != 0 {
		t.Fatalf("expected 0 tracked initialized files after sweep, got %d", got)
	}
}

func countSyncMapEntries(m *sync.Map) int {
	count := 0
	m.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
