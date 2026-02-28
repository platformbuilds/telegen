// Attribute limiter controls attribute size and count to prevent bloat.
package limits

import (
	"context"
	"log/slog"
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// AttributeLimiter enforces limits on attribute counts and sizes.
type AttributeLimiter struct {
	config AttributeLimiterConfig
	log    *slog.Logger

	// Stats
	attributesTruncated atomic.Int64
	attributesDropped   atomic.Int64
	valuesTruncated     atomic.Int64
}

// AttributeLimiterConfig configures attribute limiting.
type AttributeLimiterConfig struct {
	// Enabled toggles the limiter.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxResourceAttributes limits resource-level attributes.
	MaxResourceAttributes int `yaml:"max_resource_attributes" json:"max_resource_attributes"`

	// MaxScopeAttributes limits scope-level attributes.
	MaxScopeAttributes int `yaml:"max_scope_attributes" json:"max_scope_attributes"`

	// MaxDataPointAttributes limits data point/span/log attributes.
	MaxDataPointAttributes int `yaml:"max_data_point_attributes" json:"max_data_point_attributes"`

	// MaxAttributeKeyLength limits attribute key length.
	MaxAttributeKeyLength int `yaml:"max_attribute_key_length" json:"max_attribute_key_length"`

	// MaxAttributeValueLength limits attribute value length (strings only).
	MaxAttributeValueLength int `yaml:"max_attribute_value_length" json:"max_attribute_value_length"`

	// MaxArrayLength limits array attribute length.
	MaxArrayLength int `yaml:"max_array_length" json:"max_array_length"`

	// MaxMapDepth limits nested map depth.
	MaxMapDepth int `yaml:"max_map_depth" json:"max_map_depth"`

	// ProtectedAttributes are never dropped (but may be truncated).
	ProtectedAttributes []string `yaml:"protected_attributes,omitempty" json:"protected_attributes,omitempty"`

	// TruncationSuffix is appended to truncated values.
	TruncationSuffix string `yaml:"truncation_suffix" json:"truncation_suffix"`
}

// DefaultAttributeLimiterConfig returns sensible defaults.
func DefaultAttributeLimiterConfig() AttributeLimiterConfig {
	return AttributeLimiterConfig{
		Enabled:                 true,
		MaxResourceAttributes:   128,
		MaxScopeAttributes:      64,
		MaxDataPointAttributes:  64,
		MaxAttributeKeyLength:   256,
		MaxAttributeValueLength: 4096,
		MaxArrayLength:          100,
		MaxMapDepth:             5,
		TruncationSuffix:        "...",
		ProtectedAttributes: []string{
			"service.name",
			"service.namespace",
			"k8s.pod.name",
			"k8s.namespace.name",
			"k8s.container.name",
			"host.name",
			"trace.id",
			"span.id",
		},
	}
}

// NewAttributeLimiter creates a new attribute limiter.
func NewAttributeLimiter(config AttributeLimiterConfig, log *slog.Logger) *AttributeLimiter {
	if log == nil {
		log = slog.Default()
	}

	return &AttributeLimiter{
		config: config,
		log:    log.With("component", "attribute-limiter"),
	}
}

// ProcessMetrics applies attribute limits to metrics.
func (al *AttributeLimiter) ProcessMetrics(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	if !al.config.Enabled {
		return md, nil
	}

	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)

		// Limit resource attributes
		al.limitAttributes(rm.Resource().Attributes(), al.config.MaxResourceAttributes)

		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)

			// Limit scope attributes
			al.limitAttributes(sm.Scope().Attributes(), al.config.MaxScopeAttributes)

			// Limit data point attributes
			for k := 0; k < sm.Metrics().Len(); k++ {
				al.limitMetricAttributes(sm.Metrics().At(k))
			}
		}
	}

	return md, nil
}

// ProcessTraces applies attribute limits to traces.
func (al *AttributeLimiter) ProcessTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	if !al.config.Enabled {
		return td, nil
	}

	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rs := td.ResourceSpans().At(i)

		// Limit resource attributes
		al.limitAttributes(rs.Resource().Attributes(), al.config.MaxResourceAttributes)

		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)

			// Limit scope attributes
			al.limitAttributes(ss.Scope().Attributes(), al.config.MaxScopeAttributes)

			// Limit span attributes
			for k := 0; k < ss.Spans().Len(); k++ {
				span := ss.Spans().At(k)
				al.limitAttributes(span.Attributes(), al.config.MaxDataPointAttributes)

				// Also limit span events
				for e := 0; e < span.Events().Len(); e++ {
					event := span.Events().At(e)
					al.limitAttributes(event.Attributes(), al.config.MaxDataPointAttributes)
				}

				// And span links
				for l := 0; l < span.Links().Len(); l++ {
					link := span.Links().At(l)
					al.limitAttributes(link.Attributes(), al.config.MaxDataPointAttributes)
				}
			}
		}
	}

	return td, nil
}

// ProcessLogs applies attribute limits to logs.
func (al *AttributeLimiter) ProcessLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	if !al.config.Enabled {
		return ld, nil
	}

	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)

		// Limit resource attributes
		al.limitAttributes(rl.Resource().Attributes(), al.config.MaxResourceAttributes)

		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)

			// Limit scope attributes
			al.limitAttributes(sl.Scope().Attributes(), al.config.MaxScopeAttributes)

			// Limit log record attributes
			for k := 0; k < sl.LogRecords().Len(); k++ {
				lr := sl.LogRecords().At(k)
				al.limitAttributes(lr.Attributes(), al.config.MaxDataPointAttributes)

				// Also limit body if it's a map
				if lr.Body().Type() == pcommon.ValueTypeMap {
					al.limitAttributeValues(lr.Body().Map(), 0)
				}
			}
		}
	}

	return ld, nil
}

// limitMetricAttributes limits attributes on metric data points.
func (al *AttributeLimiter) limitMetricAttributes(metric pmetric.Metric) {
	switch metric.Type() {
	case pmetric.MetricTypeGauge:
		dps := metric.Gauge().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			al.limitAttributes(dps.At(i).Attributes(), al.config.MaxDataPointAttributes)
		}
	case pmetric.MetricTypeSum:
		dps := metric.Sum().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			al.limitAttributes(dps.At(i).Attributes(), al.config.MaxDataPointAttributes)
		}
	case pmetric.MetricTypeHistogram:
		dps := metric.Histogram().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			al.limitAttributes(dps.At(i).Attributes(), al.config.MaxDataPointAttributes)
		}
	case pmetric.MetricTypeSummary:
		dps := metric.Summary().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			al.limitAttributes(dps.At(i).Attributes(), al.config.MaxDataPointAttributes)
		}
	case pmetric.MetricTypeExponentialHistogram:
		dps := metric.ExponentialHistogram().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			al.limitAttributes(dps.At(i).Attributes(), al.config.MaxDataPointAttributes)
		}
	}
}

// limitAttributes enforces attribute count and size limits.
func (al *AttributeLimiter) limitAttributes(attrs pcommon.Map, maxCount int) {
	// First pass: truncate keys and values
	al.limitAttributeValues(attrs, 0)

	// Second pass: drop excess attributes if over limit
	if attrs.Len() <= maxCount {
		return
	}

	// Build list of keys to potentially drop (non-protected)
	keysToCheck := make([]string, 0, attrs.Len())
	attrs.Range(func(k string, _ pcommon.Value) bool {
		if !al.isProtected(k) {
			keysToCheck = append(keysToCheck, k)
		}
		return true
	})

	// Drop non-protected keys until under limit
	dropCount := attrs.Len() - maxCount
	for i := 0; i < dropCount && i < len(keysToCheck); i++ {
		attrs.Remove(keysToCheck[i])
		al.attributesDropped.Add(1)
	}
}

// limitAttributeValues recursively limits attribute values.
func (al *AttributeLimiter) limitAttributeValues(attrs pcommon.Map, depth int) {
	if depth > al.config.MaxMapDepth {
		// Max depth exceeded - clear nested maps
		attrs.Range(func(k string, v pcommon.Value) bool {
			if v.Type() == pcommon.ValueTypeMap {
				v.Map().Clear()
				al.attributesTruncated.Add(1)
			}
			return true
		})
		return
	}

	keysToTruncate := make(map[string]string)

	attrs.Range(func(k string, v pcommon.Value) bool {
		// Check key length
		if len(k) > al.config.MaxAttributeKeyLength {
			truncatedKey := k[:al.config.MaxAttributeKeyLength-len(al.config.TruncationSuffix)] + al.config.TruncationSuffix
			keysToTruncate[k] = truncatedKey
			al.attributesTruncated.Add(1)
		}

		// Check/truncate value
		al.limitValue(v, depth)
		return true
	})

	// Apply key truncations (need to copy values)
	for oldKey, newKey := range keysToTruncate {
		if val, ok := attrs.Get(oldKey); ok {
			newVal := pcommon.NewValueEmpty()
			val.CopyTo(newVal)
			attrs.Remove(oldKey)
			attrs.PutEmpty(newKey).SetEmptyMap() // placeholder
			if newVal.Type() == pcommon.ValueTypeStr {
				attrs.PutStr(newKey, newVal.Str())
			} else {
				newVal.CopyTo(attrs.PutEmpty(newKey))
			}
		}
	}
}

// limitValue truncates a single value.
func (al *AttributeLimiter) limitValue(v pcommon.Value, depth int) {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		str := v.Str()
		if len(str) > al.config.MaxAttributeValueLength {
			truncated := str[:al.config.MaxAttributeValueLength-len(al.config.TruncationSuffix)] + al.config.TruncationSuffix
			v.SetStr(truncated)
			al.valuesTruncated.Add(1)
		}

	case pcommon.ValueTypeSlice:
		slice := v.Slice()
		if slice.Len() > al.config.MaxArrayLength {
			// Truncate array
			for i := slice.Len() - 1; i >= al.config.MaxArrayLength; i-- {
				slice.RemoveIf(func(_ pcommon.Value) bool {
					return slice.Len() > al.config.MaxArrayLength
				})
			}
			al.valuesTruncated.Add(1)
		}

		// Recursively limit array elements
		for i := 0; i < slice.Len(); i++ {
			al.limitValue(slice.At(i), depth)
		}

	case pcommon.ValueTypeMap:
		al.limitAttributeValues(v.Map(), depth+1)
	}
}

// isProtected checks if an attribute key is protected.
func (al *AttributeLimiter) isProtected(key string) bool {
	for _, protected := range al.config.ProtectedAttributes {
		if key == protected {
			return true
		}
	}
	return false
}

// Stats returns attribute limiter statistics.
func (al *AttributeLimiter) Stats() AttributeLimiterStats {
	return AttributeLimiterStats{
		AttributesTruncated: al.attributesTruncated.Load(),
		AttributesDropped:   al.attributesDropped.Load(),
		ValuesTruncated:     al.valuesTruncated.Load(),
	}
}

// AttributeLimiterStats holds attribute limiter statistics.
type AttributeLimiterStats struct {
	AttributesTruncated int64 `json:"attributes_truncated"`
	AttributesDropped   int64 `json:"attributes_dropped"`
	ValuesTruncated     int64 `json:"values_truncated"`
}
