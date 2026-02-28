// PII redaction provides detection and masking of sensitive data.
package transform

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// PIIRedactionConfig configures PII detection and redaction.
type PIIRedactionConfig struct {
	// Enabled toggles PII redaction.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Rules define PII detection rules.
	Rules []PIIRule `yaml:"rules" json:"rules"`

	// RedactionString is the replacement text for redacted values.
	RedactionString string `yaml:"redaction_string" json:"redaction_string"`

	// HashRedacted hashes redacted values instead of replacing with fixed string.
	HashRedacted bool `yaml:"hash_redacted" json:"hash_redacted"`

	// AllowedAttributes are never redacted even if they match PII patterns.
	AllowedAttributes []string `yaml:"allowed_attributes,omitempty" json:"allowed_attributes,omitempty"`

	// ScanLogBodies enables scanning log message bodies.
	ScanLogBodies bool `yaml:"scan_log_bodies" json:"scan_log_bodies"`

	// ScanSpanNames enables scanning span names.
	ScanSpanNames bool `yaml:"scan_span_names" json:"scan_span_names"`
}

// PIIRule defines a PII detection rule.
type PIIRule struct {
	// Name identifies the rule.
	Name string `yaml:"name" json:"name"`

	// Type is the PII type: "email", "phone", "ssn", "credit_card", "ip", "custom".
	Type string `yaml:"type" json:"type"`

	// Pattern is a regex pattern for custom rules.
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty"`

	// AttributeKeys to specifically check (optional, checks all if empty).
	AttributeKeys []string `yaml:"attribute_keys,omitempty" json:"attribute_keys,omitempty"`

	// Enabled toggles this rule.
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// compiledPIIRule is a pre-compiled PII rule.
type compiledPIIRule struct {
	name          string
	piiType       string
	pattern       *regexp.Regexp
	attributeKeys map[string]bool
}

// PIIMatcher performs PII detection and redaction.
type PIIMatcher struct {
	config           PIIRedactionConfig
	rules            []compiledPIIRule
	allowedAttrs     map[string]bool
	redactionCount   atomic.Int64
}

// NewPIIMatcher creates a new PII matcher.
func NewPIIMatcher(config PIIRedactionConfig) (*PIIMatcher, error) {
	if config.RedactionString == "" {
		config.RedactionString = "[REDACTED]"
	}

	m := &PIIMatcher{
		config:       config,
		allowedAttrs: make(map[string]bool),
	}

	// Build allowed attributes set
	for _, attr := range config.AllowedAttributes {
		m.allowedAttrs[attr] = true
	}

	// Compile rules
	for _, rule := range config.Rules {
		if !rule.Enabled {
			continue
		}

		compiled := compiledPIIRule{
			name:    rule.Name,
			piiType: rule.Type,
		}

		// Get or compile pattern
		pattern := rule.Pattern
		if pattern == "" {
			pattern = getPIIPattern(rule.Type)
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid PII pattern %q: %w", pattern, err)
		}
		compiled.pattern = re

		// Build attribute key set
		if len(rule.AttributeKeys) > 0 {
			compiled.attributeKeys = make(map[string]bool)
			for _, key := range rule.AttributeKeys {
				compiled.attributeKeys[key] = true
			}
		}

		m.rules = append(m.rules, compiled)
	}

	return m, nil
}

// defaultPIIRules returns default PII detection rules.
func defaultPIIRules() []PIIRule {
	return []PIIRule{
		{
			Name:    "email",
			Type:    "email",
			Enabled: true,
		},
		{
			Name:    "phone",
			Type:    "phone",
			Enabled: true,
		},
		{
			Name:    "ssn",
			Type:    "ssn",
			Enabled: true,
		},
		{
			Name:    "credit_card",
			Type:    "credit_card",
			Enabled: true,
		},
		{
			Name:    "ipv4",
			Type:    "ipv4",
			Enabled: false, // Disabled by default as IPs may be needed
		},
		{
			Name:    "jwt",
			Type:    "jwt",
			Enabled: true,
		},
		{
			Name:    "api_key",
			Type:    "api_key",
			Enabled: true,
		},
	}
}

// getPIIPattern returns the regex pattern for a PII type.
func getPIIPattern(piiType string) string {
	patterns := map[string]string{
		"email":       `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
		"phone":       `(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`,
		"ssn":         `\b\d{3}-\d{2}-\d{4}\b`,
		"credit_card": `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
		"ipv4":        `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
		"ipv6":        `(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}`,
		"jwt":         `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`,
		"api_key":     `(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{16,}`,
		"password":    `(?i)(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"']+[\"']`,
	}

	if pattern, ok := patterns[piiType]; ok {
		return pattern
	}
	return "" // No default pattern
}

// RedactMetrics applies PII redaction to metrics.
func (m *PIIMatcher) RedactMetrics(md pmetric.Metrics) {
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		m.redactAttributes(rm.Resource().Attributes())

		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			m.redactAttributes(sm.Scope().Attributes())

			for k := 0; k < sm.Metrics().Len(); k++ {
				m.redactMetricDataPoints(sm.Metrics().At(k))
			}
		}
	}
}

// redactMetricDataPoints redacts PII from metric data points.
func (m *PIIMatcher) redactMetricDataPoints(metric pmetric.Metric) {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dps := metric.Gauge().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			m.redactAttributes(dps.At(i).Attributes())
		}
	case pmetric.MetricTypeSum:
		dps := metric.Sum().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			m.redactAttributes(dps.At(i).Attributes())
		}
	case pmetric.MetricTypeHistogram:
		dps := metric.Histogram().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			m.redactAttributes(dps.At(i).Attributes())
		}
	case pmetric.MetricTypeSummary:
		dps := metric.Summary().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			m.redactAttributes(dps.At(i).Attributes())
		}
	case pmetric.MetricTypeExponentialHistogram:
		dps := metric.ExponentialHistogram().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			m.redactAttributes(dps.At(i).Attributes())
		}
	}
}

// RedactTraces applies PII redaction to traces.
func (m *PIIMatcher) RedactTraces(td ptrace.Traces) {
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rs := td.ResourceSpans().At(i)
		m.redactAttributes(rs.Resource().Attributes())

		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)
			m.redactAttributes(ss.Scope().Attributes())

			for k := 0; k < ss.Spans().Len(); k++ {
				span := ss.Spans().At(k)
				m.redactAttributes(span.Attributes())

				// Optionally redact span name
				if m.config.ScanSpanNames {
					redacted := m.redactString(span.Name())
					if redacted != span.Name() {
						span.SetName(redacted)
					}
				}

				// Redact events
				for e := 0; e < span.Events().Len(); e++ {
					m.redactAttributes(span.Events().At(e).Attributes())
				}

				// Redact links
				for l := 0; l < span.Links().Len(); l++ {
					m.redactAttributes(span.Links().At(l).Attributes())
				}
			}
		}
	}
}

// RedactLogs applies PII redaction to logs.
func (m *PIIMatcher) RedactLogs(ld plog.Logs) {
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		m.redactAttributes(rl.Resource().Attributes())

		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			m.redactAttributes(sl.Scope().Attributes())

			for k := 0; k < sl.LogRecords().Len(); k++ {
				lr := sl.LogRecords().At(k)
				m.redactAttributes(lr.Attributes())

				// Optionally redact log body
				if m.config.ScanLogBodies && lr.Body().Type() == pcommon.ValueTypeStr {
					body := lr.Body().Str()
					redacted := m.redactString(body)
					if redacted != body {
						lr.Body().SetStr(redacted)
					}
				}
			}
		}
	}
}

// redactAttributes scans and redacts PII from attributes.
func (m *PIIMatcher) redactAttributes(attrs pcommon.Map) {
	attrs.Range(func(key string, val pcommon.Value) bool {
		// Skip allowed attributes
		if m.allowedAttrs[key] {
			return true
		}

		// Only redact string values
		if val.Type() != pcommon.ValueTypeStr {
			return true
		}

		str := val.Str()
		redacted := m.redactStringWithKey(str, key)

		if redacted != str {
			val.SetStr(redacted)
			m.redactionCount.Add(1)
		}

		return true
	})
}

// redactStringWithKey redacts PII from a string, considering attribute key.
func (m *PIIMatcher) redactStringWithKey(value, key string) string {
	result := value

	for _, rule := range m.rules {
		// Check if rule applies to this attribute key
		if rule.attributeKeys != nil && !rule.attributeKeys[key] {
			continue
		}

		// Apply redaction
		replacement := m.config.RedactionString
		if m.config.HashRedacted {
			replacement = fmt.Sprintf("[%s:HASH]", strings.ToUpper(rule.piiType))
		}

		result = rule.pattern.ReplaceAllString(result, replacement)
	}

	return result
}

// redactString redacts PII from a string.
func (m *PIIMatcher) redactString(value string) string {
	result := value

	for _, rule := range m.rules {
		replacement := m.config.RedactionString
		if m.config.HashRedacted {
			replacement = fmt.Sprintf("[%s:HASH]", strings.ToUpper(rule.piiType))
		}

		result = rule.pattern.ReplaceAllString(result, replacement)
	}

	return result
}

// Stats returns PII redaction statistics.
func (m *PIIMatcher) Stats() PIIStats {
	return PIIStats{
		RedactionCount: m.redactionCount.Load(),
		RulesActive:    len(m.rules),
	}
}

// PIIStats holds PII redaction statistics.
type PIIStats struct {
	RedactionCount int64 `json:"redaction_count"`
	RulesActive    int   `json:"rules_active"`
}
