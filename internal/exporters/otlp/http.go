// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
)

// HTTPTransport implements OTLP export over HTTP.
type HTTPTransport struct {
	cfg    Config
	log    *slog.Logger
	client *http.Client

	mu      sync.RWMutex
	running bool
}

// NewHTTPTransport creates a new HTTP transport.
func NewHTTPTransport(cfg Config, log *slog.Logger) (*HTTPTransport, error) {
	client, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP client: %w", err)
	}

	t := &HTTPTransport{
		cfg:     cfg,
		log:     log.With("transport", "http"),
		client:  client,
		running: true,
	}

	return t, nil
}

// buildHTTPClient builds the HTTP client with TLS configuration.
func buildHTTPClient(cfg Config) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * cfg.Timeout,
	}

	// Configure TLS
	if cfg.TLS.Enabled {
		tlsConfig, err := buildHTTPTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}, nil
}

// buildHTTPTLSConfig builds the TLS configuration for HTTP.
func buildHTTPTLSConfig(tlsCfg TLSConfig) (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
	}

	if tlsCfg.ServerName != "" {
		cfg.ServerName = tlsCfg.ServerName
	}

	// Load CA certificate
	if tlsCfg.CAFile != "" {
		caCert, err := os.ReadFile(tlsCfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		cfg.RootCAs = caCertPool
	}

	// Load client certificate
	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// Send sends data over HTTP.
func (t *HTTPTransport) Send(ctx context.Context, signal SignalType, data []byte) error {
	t.mu.RLock()
	if !t.running {
		t.mu.RUnlock()
		return fmt.Errorf("HTTP transport not running")
	}
	t.mu.RUnlock()

	// Build request URL
	url := t.buildURL(signal)

	// Prepare request body
	body, contentEncoding, err := t.prepareBody(data)
	if err != nil {
		return fmt.Errorf("failed to prepare request body: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type based on protocol
	contentType := t.getContentType()
	req.Header.Set("Content-Type", contentType)

	// Set content encoding if compressed
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}

	// Add configured headers
	for k, v := range t.cfg.Headers {
		req.Header.Set(k, v)
	}

	// Add signal-specific headers if configured
	signalCfg := t.getSignalConfig(signal)
	for k, v := range signalCfg.Headers {
		req.Header.Set(k, v)
	}

	// Send request
	resp, err := t.client.Do(req)
	if err != nil {
		return &RetryableError{
			Err:       fmt.Errorf("HTTP request failed: %w", err),
			Retryable: true,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle response
	return t.handleResponse(resp)
}

// buildURL builds the URL for the signal type.
func (t *HTTPTransport) buildURL(signal SignalType) string {
	// Check for signal-specific endpoint
	signalCfg := t.getSignalConfig(signal)
	endpoint := t.cfg.Endpoint
	if signalCfg.Endpoint != "" {
		endpoint = signalCfg.Endpoint
	}

	// Ensure endpoint has scheme
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		if t.cfg.TLS.Enabled {
			endpoint = "https://" + endpoint
		} else {
			endpoint = "http://" + endpoint
		}
	}

	// Remove trailing slash
	endpoint = strings.TrimSuffix(endpoint, "/")

	// Add signal path
	path := t.getSignalPath(signal)
	return endpoint + path
}

// getSignalPath returns the URL path for the signal type.
func (t *HTTPTransport) getSignalPath(signal SignalType) string {
	switch signal {
	case SignalTraces:
		return "/v1/traces"
	case SignalMetrics:
		return "/v1/metrics"
	case SignalLogs:
		return "/v1/logs"
	case SignalProfiles:
		return "/v1development/profiles"
	default:
		return ""
	}
}

// getContentType returns the content type based on protocol.
func (t *HTTPTransport) getContentType() string {
	switch t.cfg.Protocol {
	case ProtocolHTTPJSON:
		return "application/json"
	case ProtocolHTTPProtobuf:
		return "application/x-protobuf"
	default:
		return "application/x-protobuf"
	}
}

// getSignalConfig returns the configuration for a signal type.
func (t *HTTPTransport) getSignalConfig(signal SignalType) SignalConfig {
	switch signal {
	case SignalTraces:
		return t.cfg.Traces
	case SignalMetrics:
		return t.cfg.Metrics
	case SignalLogs:
		return t.cfg.Logs
	case SignalProfiles:
		return t.cfg.Profiles
	default:
		return SignalConfig{}
	}
}

// prepareBody prepares the request body with optional compression.
func (t *HTTPTransport) prepareBody(data []byte) ([]byte, string, error) {
	if t.cfg.Compression == CompressionNone {
		return data, "", nil
	}

	if t.cfg.Compression == CompressionGzip {
		compressed, err := compressGzip(data)
		if err != nil {
			return nil, "", err
		}
		return compressed, "gzip", nil
	}

	// For zstd, we would need a zstd implementation
	// For now, return uncompressed
	return data, "", nil
}

// compressGzip compresses data using gzip.
func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	if _, err := gz.Write(data); err != nil {
		return nil, fmt.Errorf("gzip write failed: %w", err)
	}

	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("gzip close failed: %w", err)
	}

	return buf.Bytes(), nil
}

// handleResponse handles the HTTP response.
func (t *HTTPTransport) handleResponse(resp *http.Response) error {
	// Success
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Read response body for error details
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	errMsg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))

	// Determine if retryable based on status code
	switch resp.StatusCode {
	case http.StatusTooManyRequests, // 429
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout,     // 504
		http.StatusBadGateway:         // 502
		return &RetryableError{
			Err:       fmt.Errorf("HTTP error (retryable): %s", errMsg),
			Retryable: true,
		}

	case http.StatusBadRequest, // 400
		http.StatusUnauthorized,          // 401
		http.StatusForbidden,             // 403
		http.StatusNotFound,              // 404
		http.StatusMethodNotAllowed,      // 405
		http.StatusNotAcceptable,         // 406
		http.StatusConflict,              // 409
		http.StatusGone,                  // 410
		http.StatusRequestEntityTooLarge, // 413
		http.StatusUnsupportedMediaType:  // 415
		return &RetryableError{
			Err:       fmt.Errorf("HTTP error (permanent): %s", errMsg),
			Retryable: false,
		}

	default:
		// For 5xx errors not explicitly listed, retry
		if resp.StatusCode >= 500 {
			return &RetryableError{
				Err:       fmt.Errorf("HTTP error (retryable): %s", errMsg),
				Retryable: true,
			}
		}
		return fmt.Errorf("HTTP error: %s", errMsg)
	}
}

// Close closes the HTTP transport.
func (t *HTTPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.running = false
	t.client.CloseIdleConnections()

	t.log.Info("HTTP transport closed")
	return nil
}

// IsRunning returns whether the transport is running.
func (t *HTTPTransport) IsRunning() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}
