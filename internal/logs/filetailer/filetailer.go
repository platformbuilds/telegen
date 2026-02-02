package filetailer

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/platformbuilds/telegen/internal/sigdef"
)

// Options configures the file tailer
type Options struct {
	// Globs are the file patterns to watch
	Globs []string
	// PositionFile stores file read positions for resuming after restart
	PositionFile string
	// LoggerProvider for emitting logs
	LoggerProvider *sdklog.LoggerProvider
	// ShipHistoricalEvents controls whether to ship log entries that existed before Telegen started.
	// When false (default), only new log entries written after StartTime are shipped.
	// When true, all existing log content is shipped (useful for backfilling).
	ShipHistoricalEvents bool
	// StartTime is when Telegen started. Used to filter historical entries.
	StartTime time.Time
}

type Tailer struct {
	paths                []string
	positionFile         string
	lp                   *sdklog.LoggerProvider
	shipHistoricalEvents bool
	startTime            time.Time
	// Track file positions to avoid re-reading content
	filePositions sync.Map // map[string]int64
	// Track if we've initialized each file (for historical event filtering)
	initializedFiles sync.Map // map[string]bool
}

// New creates a new Tailer (backward compatible constructor)
func New(globs []string, positionFile string, lp *sdklog.LoggerProvider) *Tailer {
	return NewWithOptions(Options{
		Globs:                globs,
		PositionFile:         positionFile,
		LoggerProvider:       lp,
		ShipHistoricalEvents: false,
		StartTime:            time.Now(),
	})
}

// NewWithOptions creates a new Tailer with full configuration
func NewWithOptions(opts Options) *Tailer {
	if opts.StartTime.IsZero() {
		opts.StartTime = time.Now()
	}
	return &Tailer{
		paths:                opts.Globs,
		positionFile:         opts.PositionFile,
		lp:                   opts.LoggerProvider,
		shipHistoricalEvents: opts.ShipHistoricalEvents,
		startTime:            opts.StartTime,
	}
}

func (t *Tailer) Run(stop <-chan struct{}) error {
	if t.lp == nil {
		return nil
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			for _, g := range t.paths {
				matches, _ := filepath.Glob(g)
				for _, p := range matches {
					t.tailOnce(p)
				}
			}
		case <-stop:
			return nil
		}
	}
}

// getSignalMetadata returns the appropriate signal metadata based on the file path
func (t *Tailer) getSignalMetadata(path string) *sigdef.SignalMetadata {
	// Check if it's a container log path
	if strings.Contains(path, "/containers/") || strings.Contains(path, "/pods/") {
		return sigdef.ContainerLogs
	}
	// Default to file log tailing
	return sigdef.FileLogTailing
}

func (t *Tailer) tailOnce(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return
	}

	currentSize := stat.Size()

	// Determine the starting position for reading
	var startPos int64

	// Check if we've seen this file before
	if _, initialized := t.initializedFiles.Load(path); !initialized {
		// First time seeing this file
		if t.shipHistoricalEvents {
			// Ship all content - start from beginning
			startPos = 0
		} else {
			// Skip historical content - start from current end of file
			// Only new content written after this point will be shipped
			startPos = currentSize
		}
		t.filePositions.Store(path, startPos)
		t.initializedFiles.Store(path, true)

		// If we're skipping to the end, there's nothing to read yet
		if startPos >= currentSize {
			return
		}
	} else {
		// We've seen this file before - read from last known position
		if pos, ok := t.filePositions.Load(path); ok {
			startPos = pos.(int64)
		}
	}

	// Check if file was truncated (rotated)
	if startPos > currentSize {
		// File was truncated, start from beginning
		startPos = 0
	}

	// Nothing new to read
	if startPos >= currentSize {
		return
	}

	// Seek to our start position
	if _, err := f.Seek(startPos, 0); err != nil {
		return
	}

	sc := bufio.NewScanner(f)
	logger := t.lp.Logger("filelog")
	ctx := context.Background()

	// Get signal metadata for this log source
	metadata := t.getSignalMetadata(path)
	metadataAttrs := metadata.ToAttributes()

	// Convert OTel attribute.KeyValue to log.KeyValue
	logMetadataAttrs := make([]log.KeyValue, 0, len(metadataAttrs))
	for _, attr := range metadataAttrs {
		logMetadataAttrs = append(logMetadataAttrs, log.String(string(attr.Key), attr.Value.AsString()))
	}

	for sc.Scan() {
		line := sc.Text()
		var rec log.Record
		rec.SetTimestamp(time.Now())
		rec.SetBody(log.StringValue(line))
		var js map[string]any
		if json.Unmarshal([]byte(line), &js) == nil {
			rec.AddAttributes(log.String("body.format", "json"))
		} else {
			rec.AddAttributes(log.String("body.format", "text"))
		}
		rec.AddAttributes(log.String("file.path", path))

		// Add telegen signal metadata attributes
		rec.AddAttributes(logMetadataAttrs...)

		logger.Emit(ctx, rec)
	}

	// Update file position to current end for next read
	// Get current position after reading
	newPos, err := f.Seek(0, 1) // Seek relative to current position
	if err == nil {
		t.filePositions.Store(path, newPos)
	} else {
		// Fallback: use file size
		t.filePositions.Store(path, currentSize)
	}
}
