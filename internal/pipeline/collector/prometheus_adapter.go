// Prometheus adapter provides native Prometheus scraping with OTLP conversion for Telegen V3.
package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// PrometheusConfig holds Prometheus adapter configuration.
type PrometheusConfig struct {
	AdapterConfig `yaml:",inline" json:",inline"`

	// Targets to scrape.
	Targets []PrometheusTarget `yaml:"targets" json:"targets"`

	// GlobalLabels are added to all scraped metrics.
	GlobalLabels map[string]string `yaml:"global_labels,omitempty" json:"global_labels,omitempty"`

	// HonorLabels preserves labels from scraped targets.
	HonorLabels bool `yaml:"honor_labels" json:"honor_labels"`

	// HonorTimestamps uses timestamps from scraped metrics if present.
	HonorTimestamps bool `yaml:"honor_timestamps" json:"honor_timestamps"`

	// ScrapeTimeout for individual scrapes.
	ScrapeTimeout time.Duration `yaml:"scrape_timeout" json:"scrape_timeout"`

	// MaxConcurrent is the maximum concurrent scrapes.
	MaxConcurrent int `yaml:"max_concurrent" json:"max_concurrent"`

	// MetricRelabelConfigs for metric relabeling.
	MetricRelabelConfigs []RelabelConfig `yaml:"metric_relabel_configs,omitempty" json:"metric_relabel_configs,omitempty"`
}

// PrometheusTarget represents a Prometheus scrape target.
type PrometheusTarget struct {
	// Name is the target identifier.
	Name string `yaml:"name" json:"name"`

	// URL is the metrics endpoint URL.
	URL string `yaml:"url" json:"url"`

	// ScrapeInterval overrides the default scrape interval.
	ScrapeInterval time.Duration `yaml:"scrape_interval,omitempty" json:"scrape_interval,omitempty"`

	// ScrapeTimeout overrides the default scrape timeout.
	ScrapeTimeout time.Duration `yaml:"scrape_timeout,omitempty" json:"scrape_timeout,omitempty"`

	// Labels are additional labels for this target.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Auth holds authentication configuration.
	Auth *PrometheusAuth `yaml:"auth,omitempty" json:"auth,omitempty"`

	// TLS configuration.
	TLS *PrometheusTLS `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Scheme is http or https.
	Scheme string `yaml:"scheme,omitempty" json:"scheme,omitempty"`

	// MetricsPath overrides the default /metrics path.
	MetricsPath string `yaml:"metrics_path,omitempty" json:"metrics_path,omitempty"`

	// Params are URL parameters.
	Params map[string][]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// PrometheusAuth holds authentication configuration.
type PrometheusAuth struct {
	// Type is the auth type: "none", "basic", "bearer".
	Type string `yaml:"type" json:"type"`

	// Basic auth credentials.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// Bearer token.
	BearerToken string `yaml:"bearer_token,omitempty" json:"bearer_token,omitempty"`
}

// PrometheusTLS holds TLS configuration.
type PrometheusTLS struct {
	// InsecureSkipVerify skips certificate verification.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`

	// CACert is the CA certificate path.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`

	// ClientCert is the client certificate path.
	ClientCert string `yaml:"client_cert,omitempty" json:"client_cert,omitempty"`

	// ClientKey is the client key path.
	ClientKey string `yaml:"client_key,omitempty" json:"client_key,omitempty"`
}

// RelabelConfig for metric relabeling.
type RelabelConfig struct {
	// SourceLabels are the labels to use as input.
	SourceLabels []string `yaml:"source_labels,omitempty" json:"source_labels,omitempty"`

	// Separator for joining source labels.
	Separator string `yaml:"separator,omitempty" json:"separator,omitempty"`

	// Regex to match against.
	Regex string `yaml:"regex,omitempty" json:"regex,omitempty"`

	// TargetLabel is the label to write to.
	TargetLabel string `yaml:"target_label,omitempty" json:"target_label,omitempty"`

	// Replacement is the replacement value.
	Replacement string `yaml:"replacement,omitempty" json:"replacement,omitempty"`

	// Action is the relabel action.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
}

// DefaultPrometheusConfig returns sensible defaults.
func DefaultPrometheusConfig() PrometheusConfig {
	return PrometheusConfig{
		AdapterConfig:   DefaultAdapterConfig(),
		HonorLabels:     true,
		HonorTimestamps: true,
		ScrapeTimeout:   10 * time.Second,
		MaxConcurrent:   10,
	}
}

// PrometheusAdapter scrapes Prometheus metrics endpoints.
type PrometheusAdapter struct {
	config PrometheusConfig
	sink   MetricSink
	client *http.Client
	log    *slog.Logger

	// State
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Stats
	scrapeCount    atomic.Int64
	errorCount     atomic.Int64
	lastScrape     atomic.Value // time.Time
	lastError      atomic.Value // string
	targetStatus   sync.Map     // string -> string
	samplesScraped atomic.Int64
}

// NewPrometheusAdapter creates a new Prometheus adapter.
func NewPrometheusAdapter(config PrometheusConfig, sink MetricSink, log *slog.Logger) (*PrometheusAdapter, error) {
	if sink == nil {
		return nil, fmt.Errorf("metric sink is required")
	}
	if log == nil {
		log = slog.Default()
	}

	if config.CollectInterval == 0 {
		config.CollectInterval = 15 * time.Second
	}
	if config.ScrapeTimeout == 0 {
		config.ScrapeTimeout = 10 * time.Second
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 10
	}

	adapter := &PrometheusAdapter{
		config: config,
		sink:   sink,
		client: &http.Client{
			Timeout: config.ScrapeTimeout,
		},
		log: log.With("adapter", "prometheus"),
	}
	adapter.lastScrape.Store(time.Time{})
	adapter.lastError.Store("")

	return adapter, nil
}

// Name implements Adapter.
func (a *PrometheusAdapter) Name() string {
	return "prometheus"
}

// Start implements Adapter.
func (a *PrometheusAdapter) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	if !a.config.Enabled {
		a.log.Info("Prometheus adapter is disabled")
		return nil
	}

	a.ctx, a.cancel = context.WithCancel(ctx)
	a.running = true

	// Start scrape loop
	a.wg.Add(1)
	go a.scrapeLoop()

	a.log.Info("started Prometheus adapter",
		"targets", len(a.config.Targets),
		"scrape_interval", a.config.CollectInterval,
	)

	return nil
}

// Stop implements Adapter.
func (a *PrometheusAdapter) Stop(ctx context.Context) error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.cancel()
	a.running = false
	a.mu.Unlock()

	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		a.log.Info("stopped Prometheus adapter",
			"total_scrapes", a.scrapeCount.Load(),
			"total_samples", a.samplesScraped.Load(),
		)
	case <-ctx.Done():
		a.log.Warn("Prometheus adapter stop timeout")
	}

	return nil
}

// Health implements Adapter.
func (a *PrometheusAdapter) Health() AdapterHealth {
	health := AdapterHealth{
		Name:            "prometheus",
		Status:          "healthy",
		CollectionCount: a.scrapeCount.Load(),
		ErrorCount:      a.errorCount.Load(),
		Targets:         make(map[string]string),
	}

	if lastScrape, ok := a.lastScrape.Load().(time.Time); ok && !lastScrape.IsZero() {
		health.LastCollection = lastScrape
	}

	if lastErr, ok := a.lastError.Load().(string); ok && lastErr != "" {
		health.LastError = lastErr
		health.Status = "degraded"
	}

	a.targetStatus.Range(func(key, value interface{}) bool {
		health.Targets[key.(string)] = value.(string)
		return true
	})

	unhealthyCount := 0
	for _, status := range health.Targets {
		if status == "unhealthy" {
			unhealthyCount++
		}
	}
	if unhealthyCount > len(health.Targets)/2 {
		health.Status = "unhealthy"
	}

	return health
}

// scrapeLoop runs periodic scraping.
func (a *PrometheusAdapter) scrapeLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.CollectInterval)
	defer ticker.Stop()

	// Initial scrape
	a.scrapeAll()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.scrapeAll()
		}
	}
}

// scrapeAll scrapes all targets concurrently.
func (a *PrometheusAdapter) scrapeAll() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, a.config.MaxConcurrent)

	for _, target := range a.config.Targets {
		wg.Add(1)
		sem <- struct{}{}

		go func(t PrometheusTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := a.scrapeTarget(t); err != nil {
				a.log.Warn("failed to scrape target",
					"name", t.Name,
					"url", t.URL,
					"error", err,
				)
				a.targetStatus.Store(t.Name, "unhealthy")
				a.errorCount.Add(1)
				a.lastError.Store(err.Error())
			} else {
				a.targetStatus.Store(t.Name, "healthy")
			}
		}(target)
	}

	wg.Wait()
	a.lastScrape.Store(time.Now())
	a.scrapeCount.Add(1)
}

// scrapeTarget scrapes a single target.
func (a *PrometheusAdapter) scrapeTarget(target PrometheusTarget) error {
	timeout := target.ScrapeTimeout
	if timeout == 0 {
		timeout = a.config.ScrapeTimeout
	}

	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()

	// Build URL
	url := target.URL
	if url == "" {
		scheme := target.Scheme
		if scheme == "" {
			scheme = "http"
		}
		metricsPath := target.MetricsPath
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		url = fmt.Sprintf("%s://%s%s", scheme, target.Name, metricsPath)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Apply authentication
	if target.Auth != nil {
		switch target.Auth.Type {
		case "basic":
			req.SetBasicAuth(target.Auth.Username, target.Auth.Password)
		case "bearer":
			req.Header.Set("Authorization", "Bearer "+target.Auth.BearerToken)
		}
	}

	// Accept header for Prometheus format
	req.Header.Set("Accept", "text/plain; version=0.0.4; charset=utf-8")

	// Send request
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse Prometheus text format
	families, err := a.parsePrometheusText(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse metrics: %w", err)
	}

	// Convert to OTLP
	otlpMetrics := a.convertToOTLP(target, families)

	// Send to sink
	if err := a.sink.SendMetrics(ctx, otlpMetrics); err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}

	// Count samples
	sampleCount := 0
	for _, f := range families {
		sampleCount += len(f.Metrics)
	}
	a.samplesScraped.Add(int64(sampleCount))

	a.log.Debug("scraped Prometheus target",
		"target", target.Name,
		"families", len(families),
		"samples", sampleCount,
	)

	return nil
}

// MetricFamily represents a Prometheus metric family.
type MetricFamily struct {
	Name    string
	Help    string
	Type    string
	Metrics []PrometheusMetric
}

// PrometheusMetric represents a single Prometheus metric.
type PrometheusMetric struct {
	Labels    map[string]string
	Value     float64
	Timestamp int64 // milliseconds
	Exemplar  *PrometheusExemplar
}

// PrometheusExemplar represents a Prometheus exemplar.
type PrometheusExemplar struct {
	Labels    map[string]string
	Value     float64
	Timestamp int64
}

// parsePrometheusText parses Prometheus text exposition format.
func (a *PrometheusAdapter) parsePrometheusText(reader io.Reader) ([]*MetricFamily, error) {
	families := make(map[string]*MetricFamily)
	scanner := bufio.NewScanner(reader)

	var currentFamily *MetricFamily

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// HELP line
		if strings.HasPrefix(line, "# HELP ") {
			parts := strings.SplitN(line[7:], " ", 2)
			name := parts[0]
			help := ""
			if len(parts) > 1 {
				help = parts[1]
			}

			if f, exists := families[name]; exists {
				f.Help = help
				currentFamily = f
			} else {
				currentFamily = &MetricFamily{
					Name:    name,
					Help:    help,
					Metrics: make([]PrometheusMetric, 0),
				}
				families[name] = currentFamily
			}
			continue
		}

		// TYPE line
		if strings.HasPrefix(line, "# TYPE ") {
			parts := strings.SplitN(line[7:], " ", 2)
			name := parts[0]
			metricType := "untyped"
			if len(parts) > 1 {
				metricType = strings.ToLower(parts[1])
			}

			if f, exists := families[name]; exists {
				f.Type = metricType
				currentFamily = f
			} else {
				currentFamily = &MetricFamily{
					Name:    name,
					Type:    metricType,
					Metrics: make([]PrometheusMetric, 0),
				}
				families[name] = currentFamily
			}
			continue
		}

		// Skip other comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse metric line
		metric, name, err := a.parseMetricLine(line)
		if err != nil {
			continue
		}

		// First, try to find the family by exact name match
		if f, exists := families[name]; exists {
			f.Metrics = append(f.Metrics, metric)
			continue
		}

		// Then try to find by base family name (strip suffix for histograms/summaries)
		familyName := a.getBaseFamilyName(name)

		if f, exists := families[familyName]; exists {
			f.Metrics = append(f.Metrics, metric)
		} else {
			// Create new family with exact name
			families[name] = &MetricFamily{
				Name:    name,
				Type:    "untyped",
				Metrics: []PrometheusMetric{metric},
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Convert map to slice
	result := make([]*MetricFamily, 0, len(families))
	for _, f := range families {
		result = append(result, f)
	}

	return result, nil
}

// parseMetricLine parses a single metric line.
// Format: metric_name{label1="value1",label2="value2"} value [timestamp]
func (a *PrometheusAdapter) parseMetricLine(line string) (PrometheusMetric, string, error) {
	metric := PrometheusMetric{
		Labels: make(map[string]string),
	}

	// Find labels section
	labelStart := strings.Index(line, "{")
	labelEnd := strings.Index(line, "}")

	var name string
	var valueStr string

	if labelStart != -1 && labelEnd != -1 {
		name = line[:labelStart]
		labelsStr := line[labelStart+1 : labelEnd]
		valueStr = strings.TrimSpace(line[labelEnd+1:])

		// Parse labels
		metric.Labels = a.parseLabels(labelsStr)
	} else {
		// No labels
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return metric, "", fmt.Errorf("invalid metric line")
		}
		name = parts[0]
		valueStr = parts[1]
	}

	// Parse value and optional timestamp
	parts := strings.Fields(valueStr)
	if len(parts) == 0 {
		return metric, "", fmt.Errorf("missing value")
	}

	value, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return metric, "", fmt.Errorf("invalid value: %w", err)
	}
	metric.Value = value

	// Parse optional timestamp
	if len(parts) > 1 {
		ts, err := strconv.ParseInt(parts[1], 10, 64)
		if err == nil {
			metric.Timestamp = ts
		}
	}

	return metric, name, nil
}

// parseLabels parses a label string like: label1="value1",label2="value2"
func (a *PrometheusAdapter) parseLabels(labelsStr string) map[string]string {
	labels := make(map[string]string)

	// Use regex to handle quoted values with commas
	re := regexp.MustCompile(`(\w+)="([^"]*)"`)
	matches := re.FindAllStringSubmatch(labelsStr, -1)

	for _, match := range matches {
		if len(match) == 3 {
			labels[match[1]] = match[2]
		}
	}

	return labels
}

// getBaseFamilyName strips histogram/summary suffixes.
func (a *PrometheusAdapter) getBaseFamilyName(name string) string {
	suffixes := []string{"_total", "_count", "_sum", "_bucket", "_created", "_info"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}

// convertToOTLP converts Prometheus metrics to OTLP format.
func (a *PrometheusAdapter) convertToOTLP(target PrometheusTarget, families []*MetricFamily) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()

	// Set resource attributes
	res := rm.Resource()
	res.Attributes().PutStr("service.name", "prometheus")
	res.Attributes().PutStr("prometheus.target.name", target.Name)
	res.Attributes().PutStr("prometheus.target.url", target.URL)

	// Add global labels
	for k, v := range a.config.GlobalLabels {
		res.Attributes().PutStr(k, v)
	}

	// Add target labels
	for k, v := range target.Labels {
		res.Attributes().PutStr(k, v)
	}

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen-prometheus-adapter")
	sm.Scope().SetVersion("1.0.0")

	now := time.Now()

	for _, family := range families {
		a.convertFamilyToOTLP(sm, family, now)
	}

	return md
}

// convertFamilyToOTLP converts a single metric family to OTLP.
func (a *PrometheusAdapter) convertFamilyToOTLP(sm pmetric.ScopeMetrics, family *MetricFamily, now time.Time) {
	switch family.Type {
	case "counter":
		a.convertCounter(sm, family, now)
	case "gauge":
		a.convertGauge(sm, family, now)
	case "histogram":
		a.convertHistogram(sm, family, now)
	case "summary":
		a.convertSummary(sm, family, now)
	default:
		// Treat as gauge by default
		a.convertGauge(sm, family, now)
	}
}

// convertCounter converts a Prometheus counter to OTLP Sum.
func (a *PrometheusAdapter) convertCounter(sm pmetric.ScopeMetrics, family *MetricFamily, now time.Time) {
	metric := sm.Metrics().AppendEmpty()
	metric.SetName(family.Name)
	metric.SetDescription(family.Help)

	sum := metric.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

	for _, m := range family.Metrics {
		dp := sum.DataPoints().AppendEmpty()
		dp.SetDoubleValue(m.Value)

		if m.Timestamp > 0 && a.config.HonorTimestamps {
			dp.SetTimestamp(pcommon.Timestamp(m.Timestamp * 1e6))
		} else {
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
		}

		for k, v := range m.Labels {
			dp.Attributes().PutStr(k, v)
		}
	}
}

// convertGauge converts a Prometheus gauge to OTLP Gauge.
func (a *PrometheusAdapter) convertGauge(sm pmetric.ScopeMetrics, family *MetricFamily, now time.Time) {
	metric := sm.Metrics().AppendEmpty()
	metric.SetName(family.Name)
	metric.SetDescription(family.Help)

	gauge := metric.SetEmptyGauge()

	for _, m := range family.Metrics {
		dp := gauge.DataPoints().AppendEmpty()
		dp.SetDoubleValue(m.Value)

		if m.Timestamp > 0 && a.config.HonorTimestamps {
			dp.SetTimestamp(pcommon.Timestamp(m.Timestamp * 1e6))
		} else {
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
		}

		for k, v := range m.Labels {
			dp.Attributes().PutStr(k, v)
		}
	}
}

// convertHistogram converts a Prometheus histogram to OTLP Histogram.
func (a *PrometheusAdapter) convertHistogram(sm pmetric.ScopeMetrics, family *MetricFamily, now time.Time) {
	metric := sm.Metrics().AppendEmpty()
	metric.SetName(family.Name)
	metric.SetDescription(family.Help)

	hist := metric.SetEmptyHistogram()
	hist.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

	// Group by labels (excluding le)
	buckets := make(map[string][]struct {
		le    float64
		count float64
	})
	sums := make(map[string]float64)
	counts := make(map[string]float64)

	for _, m := range family.Metrics {
		key := a.labelKey(m.Labels, "le")

		if le, ok := m.Labels["le"]; ok {
			// Bucket
			leVal, _ := strconv.ParseFloat(le, 64)
			buckets[key] = append(buckets[key], struct {
				le    float64
				count float64
			}{le: leVal, count: m.Value})
		} else if strings.HasSuffix(family.Name, "_sum") {
			sums[key] = m.Value
		} else if strings.HasSuffix(family.Name, "_count") {
			counts[key] = m.Value
		}
	}

	// Create histogram data points
	for key, bucketList := range buckets {
		dp := hist.DataPoints().AppendEmpty()
		dp.SetTimestamp(pcommon.NewTimestampFromTime(now))

		// Sort buckets by le
		sort.Slice(bucketList, func(i, j int) bool {
			return bucketList[i].le < bucketList[j].le
		})

		// Set explicit bounds and counts
		prevCount := float64(0)
		for _, b := range bucketList {
			if !math.IsInf(b.le, 1) {
				dp.ExplicitBounds().Append(b.le)
			}
			dp.BucketCounts().Append(uint64(b.count - prevCount))
			prevCount = b.count
		}

		// Set sum and count
		if sum, ok := sums[key]; ok {
			dp.SetSum(sum)
		}
		if count, ok := counts[key]; ok {
			dp.SetCount(uint64(count))
		}

		// Set labels from first metric
		if len(family.Metrics) > 0 {
			for k, v := range family.Metrics[0].Labels {
				if k != "le" {
					dp.Attributes().PutStr(k, v)
				}
			}
		}
	}
}

// convertSummary converts a Prometheus summary to OTLP Summary.
func (a *PrometheusAdapter) convertSummary(sm pmetric.ScopeMetrics, family *MetricFamily, now time.Time) {
	metric := sm.Metrics().AppendEmpty()
	metric.SetName(family.Name)
	metric.SetDescription(family.Help)

	summary := metric.SetEmptySummary()

	// Group by labels (excluding quantile)
	quantiles := make(map[string][]struct {
		quantile float64
		value    float64
	})
	sums := make(map[string]float64)
	counts := make(map[string]float64)

	for _, m := range family.Metrics {
		key := a.labelKey(m.Labels, "quantile")

		if q, ok := m.Labels["quantile"]; ok {
			qVal, _ := strconv.ParseFloat(q, 64)
			quantiles[key] = append(quantiles[key], struct {
				quantile float64
				value    float64
			}{quantile: qVal, value: m.Value})
		} else if strings.HasSuffix(family.Name, "_sum") {
			sums[key] = m.Value
		} else if strings.HasSuffix(family.Name, "_count") {
			counts[key] = m.Value
		}
	}

	// Create summary data points
	for key, qList := range quantiles {
		dp := summary.DataPoints().AppendEmpty()
		dp.SetTimestamp(pcommon.NewTimestampFromTime(now))

		for _, q := range qList {
			qv := dp.QuantileValues().AppendEmpty()
			qv.SetQuantile(q.quantile)
			qv.SetValue(q.value)
		}

		if sum, ok := sums[key]; ok {
			dp.SetSum(sum)
		}
		if count, ok := counts[key]; ok {
			dp.SetCount(uint64(count))
		}

		// Set labels
		if len(family.Metrics) > 0 {
			for k, v := range family.Metrics[0].Labels {
				if k != "quantile" {
					dp.Attributes().PutStr(k, v)
				}
			}
		}
	}
}

// labelKey creates a key from labels excluding a specific label.
func (a *PrometheusAdapter) labelKey(labels map[string]string, exclude string) string {
	var parts []string
	for k, v := range labels {
		if k != exclude {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
