package parsers

import (
	"log/slog"
	"time"

	"github.com/platformbuilds/telegen/internal/correlation"
)

// PipelineConfig configures the parser pipeline
type PipelineConfig struct {
	// EnableRuntimeParsing enables container runtime format parsing (Docker JSON, CRI-O, containerd)
	EnableRuntimeParsing bool `yaml:"enable_runtime_parsing"`

	// EnableApplicationParsing enables application log format parsing (Spring Boot, Log4j, etc.)
	EnableApplicationParsing bool `yaml:"enable_application_parsing"`

	// EnableK8sEnrichment enables Kubernetes metadata extraction from file paths
	EnableK8sEnrichment bool `yaml:"enable_k8s_enrichment"`

	// EnableTraceContextEnrichment enables eBPF-based trace context correlation.
	// When enabled, plain-text logs can be correlated with traces using the
	// LogTraceCorrelator populated by log_enricher.
	// Requires: log_enricher enabled in eBPF config
	EnableTraceContextEnrichment bool `yaml:"enable_trace_context_enrichment"`

	// TraceContextTolerance is the time window for trace context matching.
	// Default: 1s (allows for timestamp skew between log write and file read)
	TraceContextTolerance time.Duration `yaml:"trace_context_tolerance"`

	// ApplicationParsers specifies which application parsers to enable
	// Valid values: "spring_boot", "log4j", "json", "generic"
	// If empty, all parsers are enabled
	ApplicationParsers []string `yaml:"application_parsers"`

	// DefaultSeverity is the default severity for logs that don't have one
	DefaultSeverity string `yaml:"default_severity"`
}

// DefaultPipelineConfig returns a default pipeline configuration
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		EnableRuntimeParsing:         true,
		EnableApplicationParsing:     true,
		EnableK8sEnrichment:          true,
		EnableTraceContextEnrichment: false, // Opt-in, requires log_enricher
		TraceContextTolerance:        1 * time.Second,
		ApplicationParsers:           []string{}, // Empty means all
		DefaultSeverity:              "INFO",
	}
}

// Pipeline orchestrates parsing of log lines through multiple stages:
// 1. Runtime format parsing (Docker JSON, CRI-O, containerd)
// 2. Application log parsing (Spring Boot, Log4j, JSON, generic)
// 3. Enrichment (K8s metadata from file paths)
// 4. Trace context correlation (eBPF-based, for plain-text logs)
type Pipeline struct {
	config PipelineConfig
	logger *slog.Logger

	// Stage 1: Runtime format parsing
	runtimeRouter *RuntimeFormatRouter

	// Stage 2: Application parsers
	appParsers []Parser

	// Stage 3+4: Enrichers (K8s metadata, then trace context)
	enrichers []Enricher

	// Trace context correlator (optional, for eBPF correlation)
	traceCorrelator *correlation.LogTraceCorrelator
}

// NewPipeline creates a new parser pipeline
func NewPipeline(config PipelineConfig, logger *slog.Logger) *Pipeline {
	return NewPipelineWithCorrelator(config, logger, nil)
}

// NewPipelineWithCorrelator creates a pipeline with a custom trace correlator.
// If correlator is nil and EnableTraceContextEnrichment is true, uses global correlator.
func NewPipelineWithCorrelator(config PipelineConfig, logger *slog.Logger, correlator *correlation.LogTraceCorrelator) *Pipeline {
	if logger == nil {
		logger = slog.Default()
	}

	p := &Pipeline{
		config:          config,
		logger:          logger,
		traceCorrelator: correlator,
	}

	// Initialize runtime router if enabled
	if config.EnableRuntimeParsing {
		p.runtimeRouter = NewRuntimeFormatRouter()
	}

	// Initialize application parsers
	if config.EnableApplicationParsing {
		p.initApplicationParsers()
	}

	// Initialize enrichers - ORDER MATTERS
	// K8s enrichment must come first (provides container ID for trace correlation)
	if config.EnableK8sEnrichment {
		p.enrichers = append(p.enrichers, NewK8sPathEnricher())
	}

	// Trace context enrichment comes after K8s enrichment
	// This enables correlation for plain-text logs that don't embed trace context
	if config.EnableTraceContextEnrichment {
		tolerance := config.TraceContextTolerance
		if tolerance == 0 {
			tolerance = 1 * time.Second
		}
		p.enrichers = append(p.enrichers, NewTraceContextEnricherWithTolerance(correlator, tolerance))
		logger.Info("trace context enrichment enabled",
			"tolerance", tolerance,
			"correlator", correlator != nil)
	}

	return p
}

// initApplicationParsers initializes the configured application parsers
func (p *Pipeline) initApplicationParsers() {
	enabledParsers := make(map[string]bool)
	enableAll := len(p.config.ApplicationParsers) == 0

	if !enableAll {
		for _, name := range p.config.ApplicationParsers {
			enabledParsers[name] = true
		}
	}

	// Add parsers in order of specificity (most specific first)
	if enableAll || enabledParsers["spring_boot"] {
		p.appParsers = append(p.appParsers, NewSpringBootParser())
	}
	if enableAll || enabledParsers["log4j"] {
		p.appParsers = append(p.appParsers, NewLog4jParser())
	}
	if enableAll || enabledParsers["json"] {
		p.appParsers = append(p.appParsers, NewJSONLogParser())
	}
	if enableAll || enabledParsers["generic"] {
		p.appParsers = append(p.appParsers, NewGenericTimestampParser())
	}
}

// Parse processes a raw log line through the pipeline
func (p *Pipeline) Parse(line string, filePath string) *ParsedLog {
	if line == "" {
		return nil
	}

	var log *ParsedLog
	var err error

	// Stage 1: Try runtime format parsing first
	if p.runtimeRouter != nil {
		log, err = p.runtimeRouter.Parse(line)
		if err == nil && log != nil {
			// Successfully parsed runtime format, now try to parse the extracted body
			if p.appParsers != nil && log.Body != "" {
				parsedBody := p.parseApplicationLog(log.Body)
				if parsedBody != nil {
					// Merge: keep runtime metadata, use parsed body data
					mergeApplicationLog(log, parsedBody)
				}
			}
		}
	}

	// Stage 2: If no runtime format detected, try application parsers directly
	if log == nil && p.appParsers != nil {
		log = p.parseApplicationLog(line)
	}

	// Stage 3: If nothing matched, create a raw log entry
	if log == nil {
		log = NewParsedLog()
		log.Body = line
		log.Format = "raw"
		log.Severity = normalizeSeverity(p.config.DefaultSeverity)
		log.SeverityNumber = severityToNumber(log.Severity)
	}

	// Stage 4: Apply enrichers
	for _, enricher := range p.enrichers {
		enricher.Enrich(log, filePath)
	}

	// Ensure timestamp is set
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}

	return log
}

// parseApplicationLog tries all application parsers
func (p *Pipeline) parseApplicationLog(line string) *ParsedLog {
	for _, parser := range p.appParsers {
		log, err := parser.Parse(line)
		if err == nil && log != nil {
			return log
		}
	}
	return nil
}

// mergeApplicationLog merges parsed application log data into a runtime-parsed log
func mergeApplicationLog(runtime, app *ParsedLog) {
	// Use application timestamp if runtime didn't have one or app timestamp is more precise
	if !app.Timestamp.IsZero() {
		runtime.Timestamp = app.Timestamp
	}

	// Use application severity if available
	if app.Severity != "" && app.Severity != SeverityInfo {
		runtime.Severity = app.Severity
		runtime.SeverityNumber = app.SeverityNumber
	}

	// Use application body (the actual log message without timestamps/levels)
	if app.Body != "" {
		runtime.Body = app.Body
	}

	// Merge application attributes (don't overwrite runtime attributes)
	for k, v := range app.Attributes {
		if _, exists := runtime.Attributes[k]; !exists {
			runtime.Attributes[k] = v
		}
	}

	// Note the application format
	runtime.Attributes["app.log.format"] = app.Format
}

// ParseBatch processes multiple log lines
func (p *Pipeline) ParseBatch(lines []string, filePath string) []*ParsedLog {
	results := make([]*ParsedLog, 0, len(lines))
	for _, line := range lines {
		if parsed := p.Parse(line, filePath); parsed != nil {
			results = append(results, parsed)
		}
	}
	return results
}

// AddEnricher adds a custom enricher to the pipeline
func (p *Pipeline) AddEnricher(enricher Enricher) {
	p.enrichers = append(p.enrichers, enricher)
}

// AddParser adds a custom application parser to the beginning of the parser chain
func (p *Pipeline) AddParser(parser Parser) {
	// Prepend to give custom parsers priority
	p.appParsers = append([]Parser{parser}, p.appParsers...)
}

// Stats returns pipeline statistics
type PipelineStats struct {
	TotalProcessed    int64
	RuntimeParsed     int64
	ApplicationParsed int64
	RawPassthrough    int64
	ParseErrors       int64
}

// StatsPipeline is a Pipeline wrapper that tracks statistics
type StatsPipeline struct {
	*Pipeline
	stats PipelineStats
}

// NewStatsPipeline creates a pipeline that tracks parsing statistics
func NewStatsPipeline(config PipelineConfig, logger *slog.Logger) *StatsPipeline {
	return &StatsPipeline{
		Pipeline: NewPipeline(config, logger),
	}
}

// Parse processes a log line and tracks statistics
func (p *StatsPipeline) Parse(line string, filePath string) *ParsedLog {
	p.stats.TotalProcessed++

	log := p.Pipeline.Parse(line, filePath)
	if log == nil {
		p.stats.ParseErrors++
		return nil
	}

	switch log.Format {
	case "docker_json", "crio", "containerd":
		p.stats.RuntimeParsed++
	case "spring_boot", "log4j", "json", "generic":
		p.stats.ApplicationParsed++
	case "raw":
		p.stats.RawPassthrough++
	}

	return log
}

// Stats returns current pipeline statistics
func (p *StatsPipeline) Stats() PipelineStats {
	return p.stats
}

// ResetStats resets pipeline statistics
func (p *StatsPipeline) ResetStats() {
	p.stats = PipelineStats{}
}
