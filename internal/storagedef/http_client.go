// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package storagedef

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// HTTPClient is a wrapper around http.Client with common functionality
// for storage API clients
type HTTPClient struct {
	client    *http.Client
	baseURL   string
	headers   map[string]string
	authHook  func(*http.Request) error
	timeout   time.Duration
	verifySSL bool
}

// HTTPClientConfig configures the HTTP client
type HTTPClientConfig struct {
	BaseURL   string
	Timeout   time.Duration
	VerifySSL bool
	TLS       TLSConfig
}

// NewHTTPClient creates a new HTTP client for storage API calls
func NewHTTPClient(cfg HTTPClientConfig) (*HTTPClient, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &HTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
		baseURL:   cfg.BaseURL,
		headers:   make(map[string]string),
		timeout:   cfg.Timeout,
		verifySSL: cfg.VerifySSL,
	}, nil
}

// buildTLSConfig creates a TLS configuration
func buildTLSConfig(cfg HTTPClientConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if !cfg.VerifySSL || cfg.TLS.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.TLS.CAFile != "" {
		caCert, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// SetHeader sets a header that will be included in all requests
func (c *HTTPClient) SetHeader(key, value string) {
	c.headers[key] = value
}

// SetAuthHook sets a function that will be called before each request
// to add authentication
func (c *HTTPClient) SetAuthHook(hook func(*http.Request) error) {
	c.authHook = hook
}

// Get performs an HTTP GET request
func (c *HTTPClient) Get(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodGet, path, nil, result)
}

// Post performs an HTTP POST request
func (c *HTTPClient) Post(ctx context.Context, path string, body interface{}, result interface{}) error {
	return c.doRequest(ctx, http.MethodPost, path, body, result)
}

// Delete performs an HTTP DELETE request
func (c *HTTPClient) Delete(ctx context.Context, path string) error {
	return c.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// doRequest performs an HTTP request
func (c *HTTPClient) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = &bytesReader{data: jsonBody}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Set custom headers
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	// Apply auth hook
	if c.authHook != nil {
		if err := c.authHook(req); err != nil {
			return fmt.Errorf("auth hook failed: %w", err)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
		}
	}

	// Decode response
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// bytesReader is a simple io.Reader for []byte
type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// APIError represents an API error response
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

// IsNotFound returns true if the error is a 404 Not Found
func (e *APIError) IsNotFound() bool {
	return e.StatusCode == http.StatusNotFound
}

// IsUnauthorized returns true if the error is a 401 Unauthorized
func (e *APIError) IsUnauthorized() bool {
	return e.StatusCode == http.StatusUnauthorized
}
