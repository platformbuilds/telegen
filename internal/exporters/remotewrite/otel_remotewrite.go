// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package remotewrite provides Prometheus Remote Write export that is compatible
// with the OTel Collector's prometheusremotewritereceiver.
package remotewrite

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
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"

	"github.com/platformbuilds/telegen/internal/sigdef"
)

// OTelCollectorConfig holds configuration for Remote Write to OTel Collector
type OTelCollectorConfig struct {
	// Endpoint is the OTel Collector prometheusremotewritereceiver endpoint
	// Default: http://localhost:19291/api/v1/push
	Endpoint string

	// TLS configuration (reuses existing TLSConfig from this package)
	TLS TLSConfig

	// Headers to send with requests
	Headers map[string]string

	// Tenant ID for multi-tenant setups (X-Scope-OrgID header)
	TenantID string

	// Compression: "snappy" (default for Prometheus), "gzip", or "none"
	Compression string

	// Timeout for requests
	Timeout time.Duration

	// BatchSize is the maximum number of samples per write request
	BatchSize int

	// FlushInterval is how often to flush buffered samples
	FlushInterval time.Duration

	// MaxRetries is the maximum number of retries on failure
	MaxRetries int

	// RetryBackoff is the initial backoff duration between retries
	RetryBackoff time.Duration

	// IncludeSignalMetadata controls whether to add telegen.* labels
	IncludeSignalMetadata bool
}

// OTelRemoteWriter writes metrics to OTel Collector via Remote Write
type OTelRemoteWriter struct {
	cfg    OTelCollectorConfig
	log    *slog.Logger
	client *http.Client

	// Buffer for batching
	buffer     []*prompb.TimeSeries
	bufferMu   sync.Mutex
	bufferSize int

	// Channels
	flushCh chan struct{}
	doneCh  chan struct{}

	mu      sync.RWMutex
	running bool
}

// DefaultOTelCollectorConfig returns default configuration for OTel Collector
func DefaultOTelCollectorConfig() OTelCollectorConfig {
	return OTelCollectorConfig{
		// Default OTel Collector prometheusremotewritereceiver endpoint
		Endpoint:              "http://localhost:19291/api/v1/push",
		Compression:           "snappy", // Prometheus standard
		Timeout:               30 * time.Second,
		BatchSize:             1000,
		FlushInterval:         15 * time.Second,
		MaxRetries:            3,
		RetryBackoff:          1 * time.Second,
		IncludeSignalMetadata: true,
	}
}

// NewOTelRemoteWriter creates a new Remote Write client for OTel Collector
func NewOTelRemoteWriter(cfg OTelCollectorConfig, log *slog.Logger) (*OTelRemoteWriter, error) {
	if log == nil {
		log = slog.Default()
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	// Configure TLS
	if cfg.TLS.Enable {
		tlsCfg, err := buildOTelTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}

	return &OTelRemoteWriter{
		cfg:     cfg,
		log:     log.With("component", "otel_remote_writer"),
		client:  client,
		buffer:  make([]*prompb.TimeSeries, 0, cfg.BatchSize),
		flushCh: make(chan struct{}, 1),
		doneCh:  make(chan struct{}),
	}, nil
}

func buildOTelTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		tlsCfg.RootCAs = caCertPool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// Start begins the background flush loop
func (w *OTelRemoteWriter) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return nil
	}

	w.log.Info("starting OTel Remote Writer",
		"endpoint", w.cfg.Endpoint,
		"compression", w.cfg.Compression,
		"batch_size", w.cfg.BatchSize,
		"flush_interval", w.cfg.FlushInterval,
	)

	go w.flushLoop(ctx)

	w.running = true
	return nil
}

func (w *OTelRemoteWriter) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown
			w.flush(context.Background())
			close(w.doneCh)
			return

		case <-ticker.C:
			w.flush(ctx)

		case <-w.flushCh:
			w.flush(ctx)
		}
	}
}

// Write adds a write request to the buffer
func (w *OTelRemoteWriter) Write(wr *prompb.WriteRequest) error {
	return w.WriteWithMetadata(wr, nil)
}

// WriteWithMetadata adds a write request with signal metadata
func (w *OTelRemoteWriter) WriteWithMetadata(wr *prompb.WriteRequest, metadata *sigdef.SignalMetadata) error {
	w.bufferMu.Lock()
	defer w.bufferMu.Unlock()

	for _, ts := range wr.Timeseries {
		// Clone the timeseries
		cloned := prompb.TimeSeries{
			Labels:  make([]prompb.Label, len(ts.Labels)),
			Samples: make([]prompb.Sample, len(ts.Samples)),
		}
		copy(cloned.Labels, ts.Labels)
		copy(cloned.Samples, ts.Samples)

		// Add signal metadata labels if configured
		if w.cfg.IncludeSignalMetadata && metadata != nil {
			metaLabels := metadata.ToPrometheusLabels()
			for k, v := range metaLabels {
				cloned.Labels = append(cloned.Labels, prompb.Label{
					Name:  k,
					Value: v,
				})
			}
		}

		w.buffer = append(w.buffer, &cloned)
	}

	w.bufferSize += len(wr.Timeseries)

	// Trigger flush if batch size reached
	if w.bufferSize >= w.cfg.BatchSize {
		select {
		case w.flushCh <- struct{}{}:
		default:
		}
	}

	return nil
}

func (w *OTelRemoteWriter) flush(ctx context.Context) {
	w.bufferMu.Lock()
	if len(w.buffer) == 0 {
		w.bufferMu.Unlock()
		return
	}

	// Take ownership of buffer
	toSend := w.buffer
	w.buffer = make([]*prompb.TimeSeries, 0, w.cfg.BatchSize)
	w.bufferSize = 0
	w.bufferMu.Unlock()

	// Build write request
	wr := &prompb.WriteRequest{
		Timeseries: make([]prompb.TimeSeries, len(toSend)),
	}
	for i, ts := range toSend {
		wr.Timeseries[i] = *ts
	}

	// Send with retries
	var lastErr error
	for attempt := 0; attempt <= w.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := w.cfg.RetryBackoff * time.Duration(1<<(attempt-1))
			time.Sleep(backoff)
		}

		if err := w.send(ctx, wr); err != nil {
			lastErr = err
			w.log.Warn("remote write failed, retrying",
				"attempt", attempt+1,
				"max_retries", w.cfg.MaxRetries,
				"error", err,
			)
			continue
		}

		w.log.Debug("remote write successful",
			"samples", len(wr.Timeseries),
		)
		return
	}

	w.log.Error("remote write failed after retries",
		"samples", len(wr.Timeseries),
		"error", lastErr,
	)
}

func (w *OTelRemoteWriter) send(ctx context.Context, wr *prompb.WriteRequest) error {
	// Marshal the write request
	data, err := wr.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal write request: %w", err)
	}

	// Compress
	var body []byte
	var contentEncoding string

	switch w.cfg.Compression {
	case "snappy":
		body = snappy.Encode(nil, data)
		contentEncoding = "snappy"
	case "gzip":
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			return fmt.Errorf("gzip compression failed: %w", err)
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("gzip close failed: %w", err)
		}
		body = buf.Bytes()
		contentEncoding = "gzip"
	default:
		body = data
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", w.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	if w.cfg.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", w.cfg.TenantID)
	}
	for k, v := range w.cfg.Headers {
		req.Header.Set(k, v)
	}

	// Send request
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode/100 != 2 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remote write returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// Shutdown gracefully shuts down the writer
func (w *OTelRemoteWriter) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = false
	w.mu.Unlock()

	w.log.Info("shutting down OTel Remote Writer")

	select {
	case <-w.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
