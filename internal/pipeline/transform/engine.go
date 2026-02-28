// Package transform provides signal transformation capabilities including
// attribute manipulation, filtering, and PII redaction for Telegen V3.
package transform

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// TransformEngine applies transformations to telemetry signals.
type TransformEngine struct {
	config TransformConfig
	log    *slog.Logger

	// Compiled rules
	rules      []compiledRule
	rulesMu    sync.RWMutex
	piiMatcher *PIIMatcher

	// Stats
	transformCount atomic.Int64
	filterCount    atomic.Int64
	redactCount    atomic.Int64
}

// TransformConfig configures the transformation engine.
type TransformConfig struct {
	// Enabled toggles transformations.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Rules define transformation rules.
	Rules []TransformRule `yaml:"rules" json:"rules"`

	// PIIRedaction configures PII detection and redaction.
	PIIRedaction PIIRedactionConfig `yaml:"pii_redaction" json:"pii_redaction"`
}

// TransformRule defines a single transformation rule.
type TransformRule struct {
	// Name is the rule identifier.
	Name string `yaml:"name" json:"name"`

	// Match defines when this rule applies.
	Match RuleMatch `yaml:"match" json:"match"`

	// Actions to apply when match succeeds.
	Actions []RuleAction `yaml:"actions" json:"actions"`

	// Enabled toggles this rule.
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// RuleMatch defines matching criteria.
type RuleMatch struct {
	// SignalTypes to match: "metrics", "traces", "logs", or empty for all.
	SignalTypes []string `yaml:"signal_types,omitempty" json:"signal_types,omitempty"`

	// ResourceAttributes to match (all must match).
	ResourceAttributes map[string]string `yaml:"resource_attributes,omitempty" json:"resource_attributes,omitempty"`

	// MetricNames to match (regex patterns).
	MetricNames []string `yaml:"metric_names,omitempty" json:"metric_names,omitempty"`

	// SpanNames to match (regex patterns).
	SpanNames []string `yaml:"span_names,omitempty" json:"span_names,omitempty"`

	// LogBodyPatterns to match (regex patterns).
	LogBodyPatterns []string `yaml:"log_body_patterns,omitempty" json:"log_body_patterns,omitempty"`

	// Condition is a CEL expression for complex matching.
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"`
}

// RuleAction defines an action to apply.
type RuleAction struct {
	// Type is the action type.
	Type ActionType `yaml:"type" json:"type"`

	// SetAttribute sets an attribute value.
	SetAttribute *SetAttributeAction `yaml:"set_attribute,omitempty" json:"set_attribute,omitempty"`

	// DeleteAttribute removes an attribute.
	DeleteAttribute *DeleteAttributeAction `yaml:"delete_attribute,omitempty" json:"delete_attribute,omitempty"`

	// RenameAttribute renames an attribute.
	RenameAttribute *RenameAttributeAction `yaml:"rename_attribute,omitempty" json:"rename_attribute,omitempty"`

	// HashAttribute hashes an attribute value.
	HashAttribute *HashAttributeAction `yaml:"hash_attribute,omitempty" json:"hash_attribute,omitempty"`

	// Filter drops the signal element.
	Filter *FilterAction `yaml:"filter,omitempty" json:"filter,omitempty"`

	// Transform applies a value transformation.
	Transform *TransformAction `yaml:"transform,omitempty" json:"transform,omitempty"`
}

// ActionType defines the type of action.
type ActionType string

const (
	ActionSetAttribute    ActionType = "set_attribute"
	ActionDeleteAttribute ActionType = "delete_attribute"
	ActionRenameAttribute ActionType = "rename_attribute"
	ActionHashAttribute   ActionType = "hash_attribute"
	ActionFilter          ActionType = "filter"
	ActionTransform       ActionType = "transform"
)

// SetAttributeAction sets an attribute.
type SetAttributeAction struct {
	Key   string `yaml:"key" json:"key"`
	Value string `yaml:"value" json:"value"`
}

// DeleteAttributeAction deletes an attribute.
type DeleteAttributeAction struct {
	Key     string `yaml:"key" json:"key"`
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty"` // Regex pattern
}

// RenameAttributeAction renames an attribute.
type RenameAttributeAction struct {
	FromKey string `yaml:"from_key" json:"from_key"`
	ToKey   string `yaml:"to_key" json:"to_key"`
}

// HashAttributeAction hashes an attribute value.
type HashAttributeAction struct {
	Key       string `yaml:"key" json:"key"`
	Algorithm string `yaml:"algorithm" json:"algorithm"` // sha256, md5, etc.
}

// FilterAction drops signals matching criteria.
type FilterAction struct {
	Drop bool `yaml:"drop" json:"drop"`
}

// TransformAction applies a value transformation.
type TransformAction struct {
	Key        string `yaml:"key" json:"key"`
	Expression string `yaml:"expression" json:"expression"` // Transformation expression
}

// compiledRule is a pre-compiled transformation rule.
type compiledRule struct {
	name             string
	metricPatterns   []*regexp.Regexp
	spanPatterns     []*regexp.Regexp
	logPatterns      []*regexp.Regexp
	resourceMatch    map[string]string
	signalTypes      map[string]bool
	actions          []RuleAction
	deletePatterns   []*regexp.Regexp
}

// DefaultTransformConfig returns sensible defaults.
func DefaultTransformConfig() TransformConfig {
	return TransformConfig{
		Enabled: true,
		PIIRedaction: PIIRedactionConfig{
			Enabled: true,
			Rules:   defaultPIIRules(),
		},
	}
}

// NewTransformEngine creates a new transformation engine.
func NewTransformEngine(config TransformConfig, log *slog.Logger) (*TransformEngine, error) {
	if log == nil {
		log = slog.Default()
	}

	engine := &TransformEngine{
		config: config,
		log:    log.With("component", "transform-engine"),
	}

	// Compile rules
	if err := engine.compileRules(); err != nil {
		return nil, fmt.Errorf("failed to compile rules: %w", err)
	}

	// Create PII matcher
	if config.PIIRedaction.Enabled {
		var err error
		engine.piiMatcher, err = NewPIIMatcher(config.PIIRedaction)
		if err != nil {
			return nil, fmt.Errorf("failed to create PII matcher: %w", err)
		}
	}

	return engine, nil
}

// compileRules compiles all transformation rules.
func (e *TransformEngine) compileRules() error {
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()

	e.rules = make([]compiledRule, 0, len(e.config.Rules))

	for _, rule := range e.config.Rules {
		if !rule.Enabled {
			continue
		}

		compiled := compiledRule{
			name:          rule.Name,
			resourceMatch: rule.Match.ResourceAttributes,
			actions:       rule.Actions,
		}

		// Compile signal type set
		if len(rule.Match.SignalTypes) > 0 {
			compiled.signalTypes = make(map[string]bool)
			for _, st := range rule.Match.SignalTypes {
				compiled.signalTypes[st] = true
			}
		}

		// Compile metric name patterns
		for _, pattern := range rule.Match.MetricNames {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid metric pattern %q: %w", pattern, err)
			}
			compiled.metricPatterns = append(compiled.metricPatterns, re)
		}

		// Compile span name patterns
		for _, pattern := range rule.Match.SpanNames {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid span pattern %q: %w", pattern, err)
			}
			compiled.spanPatterns = append(compiled.spanPatterns, re)
		}

		// Compile log patterns
		for _, pattern := range rule.Match.LogBodyPatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid log pattern %q: %w", pattern, err)
			}
			compiled.logPatterns = append(compiled.logPatterns, re)
		}

		// Compile delete patterns
		for _, action := range rule.Actions {
			if action.DeleteAttribute != nil && action.DeleteAttribute.Pattern != "" {
				re, err := regexp.Compile(action.DeleteAttribute.Pattern)
				if err != nil {
					return fmt.Errorf("invalid delete pattern %q: %w", action.DeleteAttribute.Pattern, err)
				}
				compiled.deletePatterns = append(compiled.deletePatterns, re)
			}
		}

		e.rules = append(e.rules, compiled)
	}

	return nil
}

// ProcessMetrics applies transformations to metrics.
func (e *TransformEngine) ProcessMetrics(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	if !e.config.Enabled {
		return md, nil
	}

	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	// Apply rules
	for i := md.ResourceMetrics().Len() - 1; i >= 0; i-- {
		rm := md.ResourceMetrics().At(i)
		e.transformResource(rm.Resource(), "metrics")

		for j := rm.ScopeMetrics().Len() - 1; j >= 0; j-- {
			sm := rm.ScopeMetrics().At(j)

			for k := sm.Metrics().Len() - 1; k >= 0; k-- {
				metric := sm.Metrics().At(k)
				if e.shouldFilterMetric(metric, rm.Resource()) {
					sm.Metrics().RemoveIf(func(m pmetric.Metric) bool {
						return m.Name() == metric.Name()
					})
					e.filterCount.Add(1)
					continue
				}

				e.transformMetric(metric, rm.Resource())
				e.transformCount.Add(1)
			}
		}
	}

	// Apply PII redaction
	if e.piiMatcher != nil {
		e.piiMatcher.RedactMetrics(md)
	}

	return md, nil
}

// ProcessTraces applies transformations to traces.
func (e *TransformEngine) ProcessTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	if !e.config.Enabled {
		return td, nil
	}

	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	for i := td.ResourceSpans().Len() - 1; i >= 0; i-- {
		rs := td.ResourceSpans().At(i)
		e.transformResource(rs.Resource(), "traces")

		for j := rs.ScopeSpans().Len() - 1; j >= 0; j-- {
			ss := rs.ScopeSpans().At(j)

			for k := ss.Spans().Len() - 1; k >= 0; k-- {
				span := ss.Spans().At(k)
				if e.shouldFilterSpan(span, rs.Resource()) {
					ss.Spans().RemoveIf(func(s ptrace.Span) bool {
						return s.SpanID() == span.SpanID()
					})
					e.filterCount.Add(1)
					continue
				}

				e.transformSpan(span, rs.Resource())
				e.transformCount.Add(1)
			}
		}
	}

	// Apply PII redaction
	if e.piiMatcher != nil {
		e.piiMatcher.RedactTraces(td)
	}

	return td, nil
}

// ProcessLogs applies transformations to logs.
func (e *TransformEngine) ProcessLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	if !e.config.Enabled {
		return ld, nil
	}

	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	for i := ld.ResourceLogs().Len() - 1; i >= 0; i-- {
		rl := ld.ResourceLogs().At(i)
		e.transformResource(rl.Resource(), "logs")

		for j := rl.ScopeLogs().Len() - 1; j >= 0; j-- {
			sl := rl.ScopeLogs().At(j)

			for k := sl.LogRecords().Len() - 1; k >= 0; k-- {
				lr := sl.LogRecords().At(k)
				if e.shouldFilterLog(lr, rl.Resource()) {
					sl.LogRecords().RemoveIf(func(l plog.LogRecord) bool {
						return l.Timestamp() == lr.Timestamp() && l.Body().AsString() == lr.Body().AsString()
					})
					e.filterCount.Add(1)
					continue
				}

				e.transformLog(lr, rl.Resource())
				e.transformCount.Add(1)
			}
		}
	}

	// Apply PII redaction
	if e.piiMatcher != nil {
		e.piiMatcher.RedactLogs(ld)
	}

	return ld, nil
}

// transformResource applies transformations to resource attributes.
func (e *TransformEngine) transformResource(res pcommon.Resource, signalType string) {
	for _, rule := range e.rules {
		if !e.matchesSignalType(rule, signalType) {
			continue
		}

		e.applyActions(res.Attributes(), rule.actions)
	}
}

// matchesSignalType checks if a rule matches a signal type.
func (e *TransformEngine) matchesSignalType(rule compiledRule, signalType string) bool {
	if rule.signalTypes == nil {
		return true // Match all
	}
	return rule.signalTypes[signalType]
}

// matchesResource checks if resource attributes match a rule.
func (e *TransformEngine) matchesResource(rule compiledRule, res pcommon.Resource) bool {
	if rule.resourceMatch == nil {
		return true
	}

	for key, value := range rule.resourceMatch {
		v, ok := res.Attributes().Get(key)
		if !ok || v.Str() != value {
			return false
		}
	}
	return true
}

// shouldFilterMetric checks if a metric should be filtered.
func (e *TransformEngine) shouldFilterMetric(metric pmetric.Metric, res pcommon.Resource) bool {
	for _, rule := range e.rules {
		if !e.matchesSignalType(rule, "metrics") {
			continue
		}
		if !e.matchesResource(rule, res) {
			continue
		}

		// Check metric name patterns
		matched := false
		if len(rule.metricPatterns) == 0 {
			matched = true
		} else {
			for _, pattern := range rule.metricPatterns {
				if pattern.MatchString(metric.Name()) {
					matched = true
					break
				}
			}
		}

		if matched {
			for _, action := range rule.actions {
				if action.Filter != nil && action.Filter.Drop {
					return true
				}
			}
		}
	}
	return false
}

// shouldFilterSpan checks if a span should be filtered.
func (e *TransformEngine) shouldFilterSpan(span ptrace.Span, res pcommon.Resource) bool {
	for _, rule := range e.rules {
		if !e.matchesSignalType(rule, "traces") {
			continue
		}
		if !e.matchesResource(rule, res) {
			continue
		}

		matched := false
		if len(rule.spanPatterns) == 0 {
			matched = true
		} else {
			for _, pattern := range rule.spanPatterns {
				if pattern.MatchString(span.Name()) {
					matched = true
					break
				}
			}
		}

		if matched {
			for _, action := range rule.actions {
				if action.Filter != nil && action.Filter.Drop {
					return true
				}
			}
		}
	}
	return false
}

// shouldFilterLog checks if a log should be filtered.
func (e *TransformEngine) shouldFilterLog(lr plog.LogRecord, res pcommon.Resource) bool {
	for _, rule := range e.rules {
		if !e.matchesSignalType(rule, "logs") {
			continue
		}
		if !e.matchesResource(rule, res) {
			continue
		}

		matched := false
		if len(rule.logPatterns) == 0 {
			matched = true
		} else {
			body := lr.Body().AsString()
			for _, pattern := range rule.logPatterns {
				if pattern.MatchString(body) {
					matched = true
					break
				}
			}
		}

		if matched {
			for _, action := range rule.actions {
				if action.Filter != nil && action.Filter.Drop {
					return true
				}
			}
		}
	}
	return false
}

// transformMetric applies transformations to a metric.
func (e *TransformEngine) transformMetric(metric pmetric.Metric, res pcommon.Resource) {
	for _, rule := range e.rules {
		if !e.matchesSignalType(rule, "metrics") {
			continue
		}
		if !e.matchesResource(rule, res) {
			continue
		}

		// Check metric name patterns
		matched := false
		if len(rule.metricPatterns) == 0 {
			matched = true
		} else {
			for _, pattern := range rule.metricPatterns {
				if pattern.MatchString(metric.Name()) {
					matched = true
					break
				}
			}
		}

		if matched {
			e.transformMetricDataPoints(metric, rule.actions)
		}
	}
}

// transformMetricDataPoints applies actions to metric data points.
func (e *TransformEngine) transformMetricDataPoints(metric pmetric.Metric, actions []RuleAction) {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dps := metric.Gauge().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			e.applyActions(dps.At(i).Attributes(), actions)
		}
	case pmetric.MetricTypeSum:
		dps := metric.Sum().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			e.applyActions(dps.At(i).Attributes(), actions)
		}
	case pmetric.MetricTypeHistogram:
		dps := metric.Histogram().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			e.applyActions(dps.At(i).Attributes(), actions)
		}
	case pmetric.MetricTypeSummary:
		dps := metric.Summary().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			e.applyActions(dps.At(i).Attributes(), actions)
		}
	case pmetric.MetricTypeExponentialHistogram:
		dps := metric.ExponentialHistogram().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			e.applyActions(dps.At(i).Attributes(), actions)
		}
	}
}

// transformSpan applies transformations to a span.
func (e *TransformEngine) transformSpan(span ptrace.Span, res pcommon.Resource) {
	for _, rule := range e.rules {
		if !e.matchesSignalType(rule, "traces") {
			continue
		}
		if !e.matchesResource(rule, res) {
			continue
		}

		matched := false
		if len(rule.spanPatterns) == 0 {
			matched = true
		} else {
			for _, pattern := range rule.spanPatterns {
				if pattern.MatchString(span.Name()) {
					matched = true
					break
				}
			}
		}

		if matched {
			e.applyActions(span.Attributes(), rule.actions)
		}
	}
}

// transformLog applies transformations to a log record.
func (e *TransformEngine) transformLog(lr plog.LogRecord, res pcommon.Resource) {
	for _, rule := range e.rules {
		if !e.matchesSignalType(rule, "logs") {
			continue
		}
		if !e.matchesResource(rule, res) {
			continue
		}

		matched := false
		if len(rule.logPatterns) == 0 {
			matched = true
		} else {
			body := lr.Body().AsString()
			for _, pattern := range rule.logPatterns {
				if pattern.MatchString(body) {
					matched = true
					break
				}
			}
		}

		if matched {
			e.applyActions(lr.Attributes(), rule.actions)
		}
	}
}

// applyActions applies a list of actions to attributes.
func (e *TransformEngine) applyActions(attrs pcommon.Map, actions []RuleAction) {
	for _, action := range actions {
		switch action.Type {
		case ActionSetAttribute:
			if action.SetAttribute != nil {
				attrs.PutStr(action.SetAttribute.Key, action.SetAttribute.Value)
			}

		case ActionDeleteAttribute:
			if action.DeleteAttribute != nil {
				if action.DeleteAttribute.Key != "" {
					attrs.Remove(action.DeleteAttribute.Key)
				}
				if action.DeleteAttribute.Pattern != "" {
					re, err := regexp.Compile(action.DeleteAttribute.Pattern)
					if err == nil {
						keysToDelete := make([]string, 0)
						attrs.Range(func(k string, _ pcommon.Value) bool {
							if re.MatchString(k) {
								keysToDelete = append(keysToDelete, k)
							}
							return true
						})
						for _, k := range keysToDelete {
							attrs.Remove(k)
						}
					}
				}
			}

		case ActionRenameAttribute:
			if action.RenameAttribute != nil {
				if val, ok := attrs.Get(action.RenameAttribute.FromKey); ok {
					newVal := pcommon.NewValueEmpty()
					val.CopyTo(newVal)
					attrs.Remove(action.RenameAttribute.FromKey)
					newVal.CopyTo(attrs.PutEmpty(action.RenameAttribute.ToKey))
				}
			}

		case ActionHashAttribute:
			if action.HashAttribute != nil {
				if val, ok := attrs.Get(action.HashAttribute.Key); ok {
					hashed := hashValue(val.AsString(), action.HashAttribute.Algorithm)
					attrs.PutStr(action.HashAttribute.Key, hashed)
				}
			}
		}
	}
}

// hashValue hashes a string value.
func hashValue(value, algorithm string) string {
	switch strings.ToLower(algorithm) {
	case "sha256":
		// Simple hash for demonstration - in production use crypto/sha256
		h := uint64(0)
		for _, c := range value {
			h = h*31 + uint64(c)
		}
		return fmt.Sprintf("sha256:%016x", h)
	case "md5":
		h := uint64(0)
		for _, c := range value {
			h = h*17 + uint64(c)
		}
		return fmt.Sprintf("md5:%016x", h)
	default:
		return "[REDACTED]"
	}
}

// Stats returns transformation statistics.
func (e *TransformEngine) Stats() TransformStats {
	return TransformStats{
		TransformCount: e.transformCount.Load(),
		FilterCount:    e.filterCount.Load(),
		RedactCount:    e.redactCount.Load(),
	}
}

// TransformStats holds transformation statistics.
type TransformStats struct {
	TransformCount int64 `json:"transform_count"`
	FilterCount    int64 `json:"filter_count"`
	RedactCount    int64 `json:"redact_count"`
}
