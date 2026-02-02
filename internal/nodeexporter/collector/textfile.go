// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

const textfileCollectorName = "textfile"

func init() {
	Register(textfileCollectorName, true, NewTextFileCollector)
}

// textFileCollector reads metrics from text files in the Prometheus exposition format.
type textFileCollector struct {
	directory string
	mtimeDesc *prometheus.Desc
	errorDesc *prometheus.Desc
	logger    *slog.Logger
}

// NewTextFileCollector returns a new Collector exposing metrics read from files.
func NewTextFileCollector(config CollectorConfig) (Collector, error) {
	directory := ""
	if config.Extra != nil {
		if dir, ok := config.Extra["textfile.directory"].(string); ok {
			directory = dir
		}
	}

	return &textFileCollector{
		directory: directory,
		mtimeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "textfile", "mtime_seconds"),
			"Unixtime mtime of textfiles successfully read.",
			[]string{"file"},
			nil,
		),
		errorDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "textfile", "scrape_error"),
			"1 if there was an error opening or reading a file, 0 otherwise",
			nil, nil,
		),
		logger: config.Logger,
	}, nil
}

// Update implements the Collector interface.
func (c *textFileCollector) Update(ch chan<- prometheus.Metric) error {
	if c.directory == "" {
		// No textfile directory configured, return without error
		ch <- prometheus.MustNewConstMetric(c.errorDesc, prometheus.GaugeValue, 0)
		return nil
	}

	var errored bool
	var parsedFamilies []*dto.MetricFamily
	metricsNamesToFiles := map[string][]string{}
	metricsNamesToHelpTexts := map[string][2]string{}
	mtimes := make(map[string]time.Time)

	// Read all .prom files from the directory
	files, err := os.ReadDir(c.directory)
	if err != nil {
		c.logger.Error("failed to read textfile collector directory", "path", c.directory, "err", err)
		ch <- prometheus.MustNewConstMetric(c.errorDesc, prometheus.GaugeValue, 1)
		return nil // Non-fatal, report error metric but don't fail collection
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".prom") {
			continue
		}

		metricsFilePath := filepath.Join(c.directory, f.Name())
		mtime, families, err := c.processFile(metricsFilePath)

		if err != nil {
			errored = true
			c.logger.Error("failed to collect textfile data", "file", f.Name(), "err", err)
			continue
		}

		for _, mf := range families {
			// Check for metrics with inconsistent help texts
			if helpTexts, seen := metricsNamesToHelpTexts[*mf.Name]; seen {
				if mf.Help != nil && helpTexts[0] != *mf.Help {
					metricsNamesToHelpTexts[*mf.Name] = [2]string{helpTexts[0], *mf.Help}
					errored = true
					c.logger.Error("inconsistent metric help text",
						"metric", *mf.Name,
						"original_help_text", helpTexts[0],
						"new_help_text", *mf.Help,
						"file", metricsNamesToFiles[*mf.Name][0])
					continue
				}
			}
			if mf.Help != nil {
				metricsNamesToHelpTexts[*mf.Name] = [2]string{*mf.Help}
			}
			metricsNamesToFiles[*mf.Name] = append(metricsNamesToFiles[*mf.Name], metricsFilePath)
			parsedFamilies = append(parsedFamilies, mf)
		}

		mtimes[metricsFilePath] = *mtime
	}

	// Add default help text for metrics without one
	mfHelp := make(map[string]*string)
	for _, mf := range parsedFamilies {
		if mf.Help == nil {
			if help, ok := mfHelp[*mf.Name]; ok {
				mf.Help = help
				continue
			}
			help := fmt.Sprintf("Metric read from %s", strings.Join(metricsNamesToFiles[*mf.Name], ", "))
			mf.Help = &help
			mfHelp[*mf.Name] = &help
		}
	}

	// Convert and export all parsed metric families
	for _, mf := range parsedFamilies {
		c.convertMetricFamily(mf, ch)
	}

	// Export mtimes
	c.exportMTimes(mtimes, ch)

	// Export error status
	var errVal float64
	if errored {
		errVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.errorDesc, prometheus.GaugeValue, errVal)

	return nil
}

// processFile processes a single .prom file.
func (c *textFileCollector) processFile(path string) (*time.Time, map[string]*dto.MetricFamily, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open textfile %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(f)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse textfile %q: %w", path, err)
	}

	// Check for unsupported client-side timestamps
	if c.hasTimestamps(families) {
		return nil, nil, fmt.Errorf("textfile %q contains unsupported client-side timestamps", path)
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, families, fmt.Errorf("failed to stat %q: %w", path, err)
	}

	t := stat.ModTime()
	return &t, families, nil
}

// hasTimestamps checks if any metrics have client-side timestamps.
func (c *textFileCollector) hasTimestamps(families map[string]*dto.MetricFamily) bool {
	for _, mf := range families {
		for _, m := range mf.Metric {
			if m.TimestampMs != nil {
				return true
			}
		}
	}
	return false
}

// exportMTimes exports the modification times of successfully read files.
func (c *textFileCollector) exportMTimes(mtimes map[string]time.Time, ch chan<- prometheus.Metric) {
	if len(mtimes) == 0 {
		return
	}

	// Sort for predictable output
	filepaths := make([]string, 0, len(mtimes))
	for path := range mtimes {
		filepaths = append(filepaths, path)
	}
	sort.Strings(filepaths)

	for _, path := range filepaths {
		mtime := float64(mtimes[path].UnixNano() / 1e9)
		ch <- prometheus.MustNewConstMetric(c.mtimeDesc, prometheus.GaugeValue, mtime, path)
	}
}

// convertMetricFamily converts a dto.MetricFamily to prometheus.Metric.
func (c *textFileCollector) convertMetricFamily(metricFamily *dto.MetricFamily, ch chan<- prometheus.Metric) {
	var valType prometheus.ValueType
	var val float64

	// Collect all label names for consistent labeling
	allLabelNames := map[string]struct{}{}
	for _, metric := range metricFamily.Metric {
		for _, label := range metric.GetLabel() {
			allLabelNames[label.GetName()] = struct{}{}
		}
	}

	for _, metric := range metricFamily.Metric {
		labels := metric.GetLabel()
		var names []string
		var values []string
		for _, label := range labels {
			names = append(names, label.GetName())
			values = append(values, label.GetValue())
		}

		// Fill in missing labels with empty values
		for k := range allLabelNames {
			if !slices.Contains(names, k) {
				names = append(names, k)
				values = append(values, "")
			}
		}

		metricType := metricFamily.GetType()
		switch metricType {
		case dto.MetricType_COUNTER:
			valType = prometheus.CounterValue
			val = metric.Counter.GetValue()
		case dto.MetricType_GAUGE:
			valType = prometheus.GaugeValue
			val = metric.Gauge.GetValue()
		case dto.MetricType_UNTYPED:
			valType = prometheus.UntypedValue
			val = metric.Untyped.GetValue()
		case dto.MetricType_SUMMARY:
			quantiles := map[float64]float64{}
			for _, q := range metric.Summary.Quantile {
				quantiles[q.GetQuantile()] = q.GetValue()
			}
			ch <- prometheus.MustNewConstSummary(
				prometheus.NewDesc(*metricFamily.Name, metricFamily.GetHelp(), names, nil),
				metric.Summary.GetSampleCount(),
				metric.Summary.GetSampleSum(),
				quantiles, values...,
			)
			continue
		case dto.MetricType_HISTOGRAM:
			buckets := map[float64]uint64{}
			for _, b := range metric.Histogram.Bucket {
				buckets[b.GetUpperBound()] = b.GetCumulativeCount()
			}
			ch <- prometheus.MustNewConstHistogram(
				prometheus.NewDesc(*metricFamily.Name, metricFamily.GetHelp(), names, nil),
				metric.Histogram.GetSampleCount(),
				metric.Histogram.GetSampleSum(),
				buckets, values...,
			)
			continue
		default:
			c.logger.Warn("Unknown metric type", "type", metricType, "metric", metricFamily.GetName())
			continue
		}

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(*metricFamily.Name, metricFamily.GetHelp(), names, nil),
			valType, val, values...,
		)
	}
}
