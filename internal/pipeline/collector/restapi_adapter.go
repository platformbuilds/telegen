// REST API collector enables HTTP-based API scraping with JSONPath extraction for Telegen V3.
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// RESTAPIConfig holds REST API collector configuration.
type RESTAPIConfig struct {
	AdapterConfig `yaml:",inline" json:",inline"`

	// Endpoints to scrape.
	Endpoints []RESTEndpointConfig `yaml:"endpoints" json:"endpoints"`

	// MaxConcurrent is the maximum concurrent HTTP requests.
	MaxConcurrent int `yaml:"max_concurrent" json:"max_concurrent"`

	// DefaultTimeout for HTTP requests.
	DefaultTimeout time.Duration `yaml:"default_timeout" json:"default_timeout"`
}

// RESTEndpointConfig holds configuration for a single REST endpoint.
type RESTEndpointConfig struct {
	// Name is the endpoint identifier.
	Name string `yaml:"name" json:"name"`

	// URL is the endpoint URL.
	URL string `yaml:"url" json:"url"`

	// Method is the HTTP method (GET, POST). Default: GET.
	Method string `yaml:"method,omitempty" json:"method,omitempty"`

	// Headers are additional HTTP headers.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// Body is the request body for POST requests.
	Body string `yaml:"body,omitempty" json:"body,omitempty"`

	// Auth holds authentication configuration.
	Auth *RESTAuth `yaml:"auth,omitempty" json:"auth,omitempty"`

	// TLS configuration.
	TLS *RESTTLS `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Metrics defines how to extract metrics from the response.
	Metrics []MetricExtraction `yaml:"metrics" json:"metrics"`

	// Labels are additional labels for all metrics from this endpoint.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// CollectInterval overrides the default collection interval.
	CollectInterval time.Duration `yaml:"collect_interval,omitempty" json:"collect_interval,omitempty"`

	// Timeout overrides the default timeout.
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// RESTAuth holds authentication configuration for REST APIs.
type RESTAuth struct {
	// Type is the auth type: "none", "basic", "bearer", "api_key", "oauth2".
	Type string `yaml:"type" json:"type"`

	// Basic auth credentials.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// Bearer token.
	BearerToken string `yaml:"bearer_token,omitempty" json:"bearer_token,omitempty"`

	// API key authentication.
	APIKey       string `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	APIKeyHeader string `yaml:"api_key_header,omitempty" json:"api_key_header,omitempty"` // Default: X-API-Key

	// OAuth2 configuration.
	OAuth2 *OAuth2Config `yaml:"oauth2,omitempty" json:"oauth2,omitempty"`
}

// OAuth2Config holds OAuth2 authentication configuration.
type OAuth2Config struct {
	// ClientID for OAuth2.
	ClientID string `yaml:"client_id" json:"client_id"`

	// ClientSecret for OAuth2.
	ClientSecret string `yaml:"client_secret" json:"client_secret"`

	// TokenURL is the OAuth2 token endpoint.
	TokenURL string `yaml:"token_url" json:"token_url"`

	// Scopes for OAuth2.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

// RESTTLS holds TLS configuration for REST APIs.
type RESTTLS struct {
	// Enabled controls TLS.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// InsecureSkipVerify skips certificate verification.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`

	// CACert is the CA certificate path.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`

	// ClientCert is the client certificate path.
	ClientCert string `yaml:"client_cert,omitempty" json:"client_cert,omitempty"`

	// ClientKey is the client key path.
	ClientKey string `yaml:"client_key,omitempty" json:"client_key,omitempty"`
}

// MetricExtraction defines how to extract a metric from JSON response.
type MetricExtraction struct {
	// Name is the metric name.
	Name string `yaml:"name" json:"name"`

	// Description is the metric description.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// JSONPath is the JSONPath expression to extract the value.
	// Simple path syntax: $.data.metrics.cpu_usage
	// Array access: $.data.items[0].value
	// Wildcard: $.data.items[*].value (extracts all values)
	JSONPath string `yaml:"json_path" json:"json_path"`

	// Type is the metric type: "gauge" or "counter".
	Type string `yaml:"type" json:"type"`

	// Unit is the metric unit.
	Unit string `yaml:"unit,omitempty" json:"unit,omitempty"`

	// Labels are additional labels for this metric.
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`

	// LabelPaths extracts label values from JSON.
	// Key is the label name, value is the JSONPath.
	LabelPaths map[string]string `yaml:"label_paths,omitempty" json:"label_paths,omitempty"`

	// Multiplier scales the value.
	Multiplier float64 `yaml:"multiplier,omitempty" json:"multiplier,omitempty"`
}

// DefaultRESTAPIConfig returns sensible defaults.
func DefaultRESTAPIConfig() RESTAPIConfig {
	return RESTAPIConfig{
		AdapterConfig:  DefaultAdapterConfig(),
		MaxConcurrent:  10,
		DefaultTimeout: 30 * time.Second,
	}
}

// RESTAPIAdapter collects metrics from REST APIs.
type RESTAPIAdapter struct {
	config RESTAPIConfig
	sink   MetricSink
	client *http.Client
	log    *slog.Logger

	// OAuth2 token cache
	oauth2Tokens sync.Map // endpoint name -> token

	// State
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Stats
	collectionCount atomic.Int64
	errorCount      atomic.Int64
	lastCollection  atomic.Value // time.Time
	lastError       atomic.Value // string
	endpointStatus  sync.Map     // string -> string
}

// NewRESTAPIAdapter creates a new REST API adapter.
func NewRESTAPIAdapter(config RESTAPIConfig, sink MetricSink, log *slog.Logger) (*RESTAPIAdapter, error) {
	if sink == nil {
		return nil, fmt.Errorf("metric sink is required")
	}
	if log == nil {
		log = slog.Default()
	}

	if config.CollectInterval == 0 {
		config.CollectInterval = 60 * time.Second
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 10
	}
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30 * time.Second
	}

	adapter := &RESTAPIAdapter{
		config: config,
		sink:   sink,
		client: &http.Client{
			Timeout: config.DefaultTimeout,
		},
		log: log.With("adapter", "restapi"),
	}
	adapter.lastCollection.Store(time.Time{})
	adapter.lastError.Store("")

	return adapter, nil
}

// Name implements Adapter.
func (a *RESTAPIAdapter) Name() string {
	return "restapi"
}

// Start implements Adapter.
func (a *RESTAPIAdapter) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	if !a.config.Enabled {
		a.log.Info("REST API adapter is disabled")
		return nil
	}

	a.ctx, a.cancel = context.WithCancel(ctx)
	a.running = true

	// Start collection loop
	a.wg.Add(1)
	go a.collectionLoop()

	a.log.Info("started REST API adapter",
		"endpoints", len(a.config.Endpoints),
		"collect_interval", a.config.CollectInterval,
	)

	return nil
}

// Stop implements Adapter.
func (a *RESTAPIAdapter) Stop(ctx context.Context) error {
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
		a.log.Info("stopped REST API adapter")
	case <-ctx.Done():
		a.log.Warn("REST API adapter stop timeout")
	}

	return nil
}

// Health implements Adapter.
func (a *RESTAPIAdapter) Health() AdapterHealth {
	health := AdapterHealth{
		Name:            "restapi",
		Status:          "healthy",
		CollectionCount: a.collectionCount.Load(),
		ErrorCount:      a.errorCount.Load(),
		Targets:         make(map[string]string),
	}

	if lastColl, ok := a.lastCollection.Load().(time.Time); ok && !lastColl.IsZero() {
		health.LastCollection = lastColl
	}

	if lastErr, ok := a.lastError.Load().(string); ok && lastErr != "" {
		health.LastError = lastErr
		health.Status = "degraded"
	}

	// Collect endpoint statuses
	a.endpointStatus.Range(func(key, value interface{}) bool {
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

// collectionLoop runs periodic collection.
func (a *RESTAPIAdapter) collectionLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.CollectInterval)
	defer ticker.Stop()

	// Initial collection
	a.collectAll()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.collectAll()
		}
	}
}

// collectAll collects from all endpoints concurrently.
func (a *RESTAPIAdapter) collectAll() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, a.config.MaxConcurrent)

	for _, endpoint := range a.config.Endpoints {
		wg.Add(1)
		sem <- struct{}{}

		go func(ep RESTEndpointConfig) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := a.collectEndpoint(ep); err != nil {
				a.log.Warn("failed to collect from endpoint",
					"name", ep.Name,
					"url", ep.URL,
					"error", err,
				)
				a.endpointStatus.Store(ep.Name, "unhealthy")
				a.errorCount.Add(1)
				a.lastError.Store(err.Error())
			} else {
				a.endpointStatus.Store(ep.Name, "healthy")
			}
		}(endpoint)
	}

	wg.Wait()
	a.lastCollection.Store(time.Now())
	a.collectionCount.Add(1)
}

// collectEndpoint collects metrics from a single endpoint.
func (a *RESTAPIAdapter) collectEndpoint(endpoint RESTEndpointConfig) error {
	timeout := endpoint.Timeout
	if timeout == 0 {
		timeout = a.config.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()

	// Create request
	method := endpoint.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if endpoint.Body != "" {
		bodyReader = strings.NewReader(endpoint.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.URL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for k, v := range endpoint.Headers {
		req.Header.Set(k, v)
	}

	// Apply authentication
	if err := a.applyAuth(req, endpoint); err != nil {
		return fmt.Errorf("failed to apply auth: %w", err)
	}

	// Send request
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Parse JSON
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Extract metrics
	metrics := a.extractMetrics(endpoint, data)

	// Convert to OTLP and send
	otlpMetrics := a.convertToOTLP(endpoint, metrics)
	if err := a.sink.SendMetrics(ctx, otlpMetrics); err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}

	a.log.Debug("collected REST API metrics",
		"endpoint", endpoint.Name,
		"metric_count", len(metrics),
	)

	return nil
}

// applyAuth applies authentication to the request.
func (a *RESTAPIAdapter) applyAuth(req *http.Request, endpoint RESTEndpointConfig) error {
	if endpoint.Auth == nil {
		return nil
	}

	switch endpoint.Auth.Type {
	case "none", "":
		return nil

	case "basic":
		req.SetBasicAuth(endpoint.Auth.Username, endpoint.Auth.Password)

	case "bearer":
		req.Header.Set("Authorization", "Bearer "+endpoint.Auth.BearerToken)

	case "api_key":
		header := endpoint.Auth.APIKeyHeader
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, endpoint.Auth.APIKey)

	case "oauth2":
		token, err := a.getOAuth2Token(endpoint)
		if err != nil {
			return fmt.Errorf("failed to get OAuth2 token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

	default:
		return fmt.Errorf("unsupported auth type: %s", endpoint.Auth.Type)
	}

	return nil
}

// getOAuth2Token retrieves or refreshes an OAuth2 token.
func (a *RESTAPIAdapter) getOAuth2Token(endpoint RESTEndpointConfig) (string, error) {
	if endpoint.Auth == nil || endpoint.Auth.OAuth2 == nil {
		return "", fmt.Errorf("OAuth2 configuration missing")
	}

	// Check cache first
	if cached, ok := a.oauth2Tokens.Load(endpoint.Name); ok {
		return cached.(string), nil
	}

	oauth := endpoint.Auth.OAuth2

	// Request new token (client credentials flow)
	data := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s",
		oauth.ClientID, oauth.ClientSecret)

	if len(oauth.Scopes) > 0 {
		data += "&scope=" + strings.Join(oauth.Scopes, " ")
	}

	req, err := http.NewRequest("POST", oauth.TokenURL, strings.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	// Cache token
	a.oauth2Tokens.Store(endpoint.Name, tokenResp.AccessToken)

	return tokenResp.AccessToken, nil
}

// extractMetrics extracts metrics from JSON data using configured paths.
func (a *RESTAPIAdapter) extractMetrics(endpoint RESTEndpointConfig, data interface{}) []RESTMetric {
	var metrics []RESTMetric
	now := time.Now()

	for _, extraction := range endpoint.Metrics {
		// Extract main value
		values := a.evaluateJSONPath(data, extraction.JSONPath)

		for i, value := range values {
			v, ok := a.toFloat64(value)
			if !ok {
				continue
			}

			// Apply multiplier
			if extraction.Multiplier != 0 {
				v *= extraction.Multiplier
			}

			// Build labels
			labels := make(map[string]string)
			for k, lv := range endpoint.Labels {
				labels[k] = lv
			}
			for k, lv := range extraction.Labels {
				labels[k] = lv
			}

			// Extract label values from JSON
			for labelName, labelPath := range extraction.LabelPaths {
				labelValues := a.evaluateJSONPath(data, labelPath)
				if i < len(labelValues) {
					if s, ok := labelValues[i].(string); ok {
						labels[labelName] = s
					} else {
						labels[labelName] = fmt.Sprintf("%v", labelValues[i])
					}
				}
			}

			// Add index if multiple values
			if len(values) > 1 {
				labels["index"] = fmt.Sprintf("%d", i)
			}

			metrics = append(metrics, RESTMetric{
				Name:        extraction.Name,
				Description: extraction.Description,
				Value:       v,
				Labels:      labels,
				Timestamp:   now,
				Unit:        extraction.Unit,
				Type:        extraction.Type,
			})
		}
	}

	return metrics
}

// evaluateJSONPath evaluates a simple JSONPath expression.
// Supports: $.key, $.key.nested, $.array[0], $.array[*]
func (a *RESTAPIAdapter) evaluateJSONPath(data interface{}, path string) []interface{} {
	if path == "" {
		return nil
	}

	// Remove leading $.
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, "$")

	if path == "" {
		return []interface{}{data}
	}

	parts := a.splitJSONPath(path)
	results := []interface{}{data}

	for _, part := range parts {
		if part == "" {
			continue
		}

		var newResults []interface{}

		for _, current := range results {
			// Handle array access
			if strings.Contains(part, "[") {
				key, index := a.parseArrayAccess(part)

				// Navigate to key first if present
				if key != "" {
					m, ok := current.(map[string]interface{})
					if !ok {
						continue
					}
					current, ok = m[key]
					if !ok {
						continue
					}
				}

				arr, ok := current.([]interface{})
				if !ok {
					continue
				}

				if index == "*" {
					// Wildcard - get all elements
					newResults = append(newResults, arr...)
				} else {
					// Specific index
					idx, err := strconv.Atoi(index)
					if err != nil || idx < 0 || idx >= len(arr) {
						continue
					}
					newResults = append(newResults, arr[idx])
				}
			} else {
				// Simple key access
				m, ok := current.(map[string]interface{})
				if !ok {
					continue
				}
				if v, exists := m[part]; exists {
					newResults = append(newResults, v)
				}
			}
		}

		results = newResults
	}

	return results
}

// splitJSONPath splits a JSONPath into parts, handling array notation.
func (a *RESTAPIAdapter) splitJSONPath(path string) []string {
	// Split by dots but preserve array notation
	var parts []string
	var current strings.Builder

	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '.' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// parseArrayAccess parses "key[index]" into key and index.
func (a *RESTAPIAdapter) parseArrayAccess(part string) (key, index string) {
	re := regexp.MustCompile(`^([^[]*)\[([^\]]+)\]$`)
	matches := re.FindStringSubmatch(part)
	if len(matches) == 3 {
		return matches[1], matches[2]
	}
	return part, ""
}

// toFloat64 converts a value to float64.
func (a *RESTAPIAdapter) toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		return f, err == nil
	case bool:
		if val {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

// RESTMetric holds an extracted metric.
type RESTMetric struct {
	Name        string
	Description string
	Value       float64
	Labels      map[string]string
	Timestamp   time.Time
	Unit        string
	Type        string
}

// convertToOTLP converts REST metrics to OTLP format.
func (a *RESTAPIAdapter) convertToOTLP(endpoint RESTEndpointConfig, metrics []RESTMetric) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()

	// Set resource attributes
	res := rm.Resource()
	res.Attributes().PutStr("service.name", "restapi")
	res.Attributes().PutStr("restapi.endpoint.name", endpoint.Name)
	res.Attributes().PutStr("restapi.endpoint.url", endpoint.URL)

	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("telegen-restapi-adapter")
	sm.Scope().SetVersion("1.0.0")

	for _, m := range metrics {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName(m.Name)
		metric.SetDescription(m.Description)
		metric.SetUnit(m.Unit)

		switch m.Type {
		case "counter":
			sum := metric.SetEmptySum()
			sum.SetIsMonotonic(true)
			sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
			dp := sum.DataPoints().AppendEmpty()
			dp.SetDoubleValue(m.Value)
			dp.SetTimestamp(pcommon.NewTimestampFromTime(m.Timestamp))
			for k, v := range m.Labels {
				dp.Attributes().PutStr(k, v)
			}
		default: // gauge
			gauge := metric.SetEmptyGauge()
			dp := gauge.DataPoints().AppendEmpty()
			dp.SetDoubleValue(m.Value)
			dp.SetTimestamp(pcommon.NewTimestampFromTime(m.Timestamp))
			for k, v := range m.Labels {
				dp.Attributes().PutStr(k, v)
			}
		}
	}

	return md
}
