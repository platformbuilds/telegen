// Package filetailer provides file-based log collection with container runtime
// format parsing and Kubernetes metadata extraction.
//
// IMPORTANT: This package uses the unified OTLP exporter. The LoggerProvider
// passed to New/NewWithOptions MUST come from the shared OTLP pipeline
// (internal/exporters/otlp.Clients.Log). This ensures all telegen signals
// (traces, metrics, logs, profiles) share the same OTLP connection.
//
// The filetailer:
//   - Watches files matching glob patterns (e.g., /var/log/pods/*/*.log)
//   - Parses container runtime formats (Docker JSON, CRI-O, containerd)
//   - Extracts Kubernetes metadata from file paths
//   - Parses application log formats (Spring Boot, Log4j, JSON)
//   - Ships logs via the unified OTLP LoggerProvider
package filetailer

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/mirastacklabs-ai/telegen/internal/logs/parsers"
	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
)

// Options configures the file tailer
type Options struct {
	// Globs are the file patterns to watch
	Globs []string
	// Excludes are file patterns to skip, even if matched by Globs or K8s discovery
	Excludes []string
	// PositionFile stores file read positions for resuming after restart
	PositionFile string
	// LoggerProvider is the OTEL SDK LoggerProvider from the unified OTLP pipeline.
	// This MUST come from the shared OTLP exporter (internal/exporters/otlp.Clients.Log).
	// Telegen follows a single-exporter design: all signals share the same OTLP connection.
	LoggerProvider *sdklog.LoggerProvider
	// ShipHistoricalEvents controls whether to ship log entries that existed before Telegen started.
	// When false (default), only new log entries written after StartTime are shipped.
	// When true, all existing log content is shipped (useful for backfilling).
	ShipHistoricalEvents bool
	// StartTime is when Telegen started. Used to filter historical entries.
	StartTime time.Time
	// PollInterval is how often to check for new log content (default: 500ms)
	PollInterval time.Duration
	// Logger for debug output
	Logger *slog.Logger

	// Parser configuration
	ParserConfig ParserConfig

	// K8sDiscovery provides dynamically discovered log paths from Kubernetes.
	// When non-nil, its paths are merged with Globs on each poll tick.
	K8sDiscovery *K8sLogDiscoverer
}

// ParserConfig configures log parsing behavior
type ParserConfig struct {
	// EnableContainerRuntime enables Docker/CRI-O/containerd format parsing
	EnableContainerRuntime bool
	// EnableK8sMetadata extracts K8s metadata from file paths
	EnableK8sMetadata bool
	// EnableApplicationParsers enables Spring Boot, Log4j, etc. parsing
	EnableApplicationParsers bool
	// EnableSpringBoot enables Spring Boot log parsing with trace correlation
	EnableSpringBoot bool
	// EnableLog4j enables Log4j format parsing
	EnableLog4j bool
	// EnableGenericParsing enables generic timestamp/level parsing
	EnableGenericParsing bool
}

// DefaultParserConfig returns parser config with all features enabled
func DefaultParserConfig() ParserConfig {
	return ParserConfig{
		EnableContainerRuntime:   true,
		EnableK8sMetadata:        true,
		EnableApplicationParsers: true,
		EnableSpringBoot:         true,
		EnableLog4j:              true,
		EnableGenericParsing:     true,
	}
}

// Tailer watches files matching glob patterns and ships log entries via OTLP.
// It uses the unified OTLP LoggerProvider from the shared pipeline - ensuring
// all signals (traces, metrics, logs) use the same OTLP connection.
type Tailer struct {
	paths                []string
	excludes             []string
	positionFile         string
	lp                   *sdklog.LoggerProvider // From unified OTLP pipeline (otlp.Clients.Log)
	shipHistoricalEvents bool
	startTime            time.Time
	pollInterval         time.Duration
	logger               *slog.Logger
	// Track file positions to avoid re-reading content
	filePositions sync.Map // map[string]int64
	// Track if we've initialized each file (for historical event filtering)
	initializedFiles sync.Map // map[string]bool
	// Parser pipeline for log parsing
	pipeline *parsers.Pipeline
	// K8s log discovery (optional, provides dynamically discovered paths)
	k8sDiscovery *K8sLogDiscoverer
}

// New creates a new Tailer using the unified OTLP LoggerProvider.
// The lp parameter MUST come from the shared OTLP exporter (otlp.Clients.Log).
// This ensures all telegen signals share the same OTLP connection.
func New(globs []string, positionFile string, lp *sdklog.LoggerProvider) *Tailer {
	return NewWithOptions(Options{
		Globs:                globs,
		PositionFile:         positionFile,
		LoggerProvider:       lp,
		ShipHistoricalEvents: false,
		StartTime:            time.Now(),
		PollInterval:         500 * time.Millisecond,
		ParserConfig:         DefaultParserConfig(),
	})
}

// NewWithOptions creates a new Tailer with full configuration.
// The LoggerProvider MUST come from the unified OTLP pipeline (otlp.Clients.Log).
// Telegen requires all signals to use the shared OTLP exporter for consistency.
func NewWithOptions(opts Options) *Tailer {
	if opts.LoggerProvider == nil {
		// LoggerProvider is required - it must come from the unified OTLP pipeline
		// The pipeline should pass otlp.Clients.Log here
		return nil
	}

	if opts.StartTime.IsZero() {
		opts.StartTime = time.Now()
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 500 * time.Millisecond
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	// Create parser pipeline configuration
	pipelineConfig := parsers.PipelineConfig{
		EnableRuntimeParsing:     opts.ParserConfig.EnableContainerRuntime,
		EnableK8sEnrichment:      opts.ParserConfig.EnableK8sMetadata,
		EnableApplicationParsing: opts.ParserConfig.EnableApplicationParsers,
		DefaultSeverity:          "INFO",
	}

	// Configure application parsers based on ParserConfig
	if opts.ParserConfig.EnableApplicationParsers {
		appParsers := []string{}
		if opts.ParserConfig.EnableSpringBoot {
			appParsers = append(appParsers, "spring_boot")
		}
		if opts.ParserConfig.EnableLog4j {
			appParsers = append(appParsers, "log4j")
		}
		if opts.ParserConfig.EnableGenericParsing {
			appParsers = append(appParsers, "json", "generic")
		}
		// If no specific parsers requested, enable all
		if len(appParsers) == 0 {
			appParsers = nil // nil means all parsers
		}
		pipelineConfig.ApplicationParsers = appParsers
	}

	return &Tailer{
		paths:                opts.Globs,
		excludes:             opts.Excludes,
		positionFile:         opts.PositionFile,
		lp:                   opts.LoggerProvider,
		shipHistoricalEvents: opts.ShipHistoricalEvents,
		startTime:            opts.StartTime,
		pollInterval:         opts.PollInterval,
		logger:               opts.Logger,
		pipeline:             parsers.NewPipeline(pipelineConfig, opts.Logger),
		k8sDiscovery:         opts.K8sDiscovery,
	}
}

func (t *Tailer) Run(stop <-chan struct{}) error {
	if t.lp == nil {
		return nil
	}
	tick := time.NewTicker(t.pollInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			// Collect all glob patterns: static Include + K8s-discovered
			allGlobs := make([]string, 0, len(t.paths))
			allGlobs = append(allGlobs, t.paths...)
			if t.k8sDiscovery != nil {
				allGlobs = append(allGlobs, t.k8sDiscovery.DiscoveredPaths()...)
			}
			for _, g := range allGlobs {
				matches, _ := filepath.Glob(g)
				for _, p := range matches {
					if t.isExcluded(p) {
						continue
					}
					t.tailOnce(p)
				}
			}
		case <-stop:
			return nil
		}
	}
}

// isExcluded returns true if the path matches any of the configured exclude patterns.
func (t *Tailer) isExcluded(path string) bool {
	for _, ex := range t.excludes {
		if matched, _ := filepath.Match(ex, path); matched {
			return true
		}
		// Also try matching against just the base name for patterns
		// without directory separators (e.g. "*telegen*")
		if !strings.ContainsRune(ex, '/') {
			if matched, _ := filepath.Match(ex, filepath.Base(path)); matched {
				return true
			}
		}
	}
	return false
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

		// Parse the log line using the pipeline
		parsed := t.pipeline.Parse(line, path)
		if parsed == nil {
			// Fallback to raw line if parsing fails
			parsed = &parsers.ParsedLog{
				Body:               line,
				Timestamp:          time.Now(),
				Format:             "text",
				FilePath:           path,
				OriginalLine:       line,
				ResourceAttributes: make(map[string]string),
				Attributes:         make(map[string]string),
			}
		}

		// Convert to OTEL record
		rec := parsed.ToOTelRecord()

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
