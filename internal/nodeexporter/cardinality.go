// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package nodeexporter

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// CardinalityFilter wraps an http.Handler and applies cardinality controls
// to the Prometheus metrics output.
type CardinalityFilter struct {
	handler http.Handler
	config  CardinalityConfig
	logger  *slog.Logger

	// Compiled regex patterns
	includePatterns []*regexp.Regexp
	excludePatterns []*regexp.Regexp
	dropLabelSet    map[string]struct{}
}

// NewCardinalityFilter creates a new cardinality filter wrapping the given handler.
func NewCardinalityFilter(handler http.Handler, config CardinalityConfig, logger *slog.Logger) (*CardinalityFilter, error) {
	f := &CardinalityFilter{
		handler:      handler,
		config:       config,
		logger:       logger,
		dropLabelSet: make(map[string]struct{}),
	}

	// Compile include patterns
	for _, pattern := range config.IncludeMetrics {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		f.includePatterns = append(f.includePatterns, re)
	}

	// Compile exclude patterns
	for _, pattern := range config.ExcludeMetrics {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		f.excludePatterns = append(f.excludePatterns, re)
	}

	// Build drop label set
	for _, label := range config.DropLabels {
		f.dropLabelSet[label] = struct{}{}
	}

	return f, nil
}

// responseCapture is a custom ResponseWriter that captures the response body.
type responseCapture struct {
	statusCode int
	headers    http.Header
	body       *bytes.Buffer
}

func newResponseCapture() *responseCapture {
	return &responseCapture{
		statusCode: http.StatusOK,
		headers:    make(http.Header),
		body:       &bytes.Buffer{},
	}
}

func (r *responseCapture) Header() http.Header {
	return r.headers
}

func (r *responseCapture) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseCapture) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

// ServeHTTP implements the http.Handler interface.
func (f *CardinalityFilter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If cardinality controls are not enabled, pass through directly
	if !f.config.Enabled {
		f.handler.ServeHTTP(w, r)
		return
	}

	// Capture the response from the underlying handler
	capture := newResponseCapture()
	f.handler.ServeHTTP(capture, r)

	// Copy headers
	for k, v := range capture.headers {
		w.Header()[k] = v
	}

	// If not a successful response or not metrics content, pass through as-is
	contentType := capture.headers.Get("Content-Type")
	if capture.statusCode != http.StatusOK || !strings.Contains(contentType, "text/plain") {
		w.WriteHeader(capture.statusCode)
		_, _ = io.Copy(w, capture.body)
		return
	}

	// Parse and filter the metrics
	filtered, err := f.filterMetrics(capture.body, contentType)
	if err != nil {
		f.logger.Error("failed to filter metrics", "err", err)
		// On error, pass through the original response
		w.WriteHeader(capture.statusCode)
		_, _ = io.Copy(w, capture.body)
		return
	}

	w.WriteHeader(capture.statusCode)
	_, _ = w.Write(filtered)
}

// filterMetrics parses Prometheus metrics and applies cardinality controls.
func (f *CardinalityFilter) filterMetrics(body *bytes.Buffer, contentType string) ([]byte, error) {
	// Determine format from content type - default to text format
	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	if strings.Contains(contentType, "application/openmetrics-text") {
		format = expfmt.NewFormat(expfmt.TypeOpenMetrics)
	}

	// Parse metrics
	parser := expfmt.NewDecoder(body, format)
	var families []*dto.MetricFamily

	for {
		mf := &dto.MetricFamily{}
		if err := parser.Decode(mf); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		families = append(families, mf)
	}

	// Apply filters
	filtered := f.applyFilters(families)

	// Encode back to text format
	var buf bytes.Buffer
	encoder := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range filtered {
		if err := encoder.Encode(mf); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// applyFilters applies all cardinality controls to the metric families.
func (f *CardinalityFilter) applyFilters(families []*dto.MetricFamily) []*dto.MetricFamily {
	var result []*dto.MetricFamily
	totalMetrics := 0

	for _, mf := range families {
		name := mf.GetName()

		// Check include patterns (if any are specified, metric must match at least one)
		if len(f.includePatterns) > 0 {
			matched := false
			for _, re := range f.includePatterns {
				if re.MatchString(name) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Check exclude patterns (metric must not match any)
		excluded := false
		for _, re := range f.excludePatterns {
			if re.MatchString(name) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Apply label filters to each metric in the family
		filteredMetrics := f.filterLabels(mf.Metric)
		if len(filteredMetrics) == 0 {
			continue
		}

		// Check max metrics limit
		if f.config.MaxMetrics > 0 {
			remaining := f.config.MaxMetrics - totalMetrics
			if remaining <= 0 {
				f.logger.Warn("max metrics limit reached",
					"limit", f.config.MaxMetrics,
					"dropped_family", name)
				break
			}
			if len(filteredMetrics) > remaining {
				filteredMetrics = filteredMetrics[:remaining]
			}
		}

		totalMetrics += len(filteredMetrics)

		// Create filtered metric family
		filtered := &dto.MetricFamily{
			Name:   mf.Name,
			Help:   mf.Help,
			Type:   mf.Type,
			Metric: filteredMetrics,
		}
		result = append(result, filtered)
	}

	return result
}

// filterLabels applies label-level cardinality controls.
func (f *CardinalityFilter) filterLabels(metrics []*dto.Metric) []*dto.Metric {
	var result []*dto.Metric

	for _, m := range metrics {
		// Filter out dropped labels
		var filteredLabels []*dto.LabelPair
		for _, lp := range m.GetLabel() {
			name := lp.GetName()

			// Skip dropped labels
			if _, drop := f.dropLabelSet[name]; drop {
				continue
			}

			// Apply max label value length
			value := lp.GetValue()
			if f.config.MaxLabelValueLength > 0 && len(value) > f.config.MaxLabelValueLength {
				truncated := value[:f.config.MaxLabelValueLength]
				lp.Value = &truncated
			}

			filteredLabels = append(filteredLabels, lp)
		}

		// Check max labels limit
		if f.config.MaxLabels > 0 && len(filteredLabels) > f.config.MaxLabels {
			filteredLabels = filteredLabels[:f.config.MaxLabels]
		}

		// Create new metric with filtered labels
		newMetric := &dto.Metric{
			Label:       filteredLabels,
			Gauge:       m.Gauge,
			Counter:     m.Counter,
			Summary:     m.Summary,
			Untyped:     m.Untyped,
			Histogram:   m.Histogram,
			TimestampMs: m.TimestampMs,
		}
		result = append(result, newMetric)
	}

	return result
}
