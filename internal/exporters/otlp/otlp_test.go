// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Protocol != ProtocolGRPC {
		t.Errorf("expected default protocol to be gRPC, got %v", cfg.Protocol)
	}

	if cfg.Endpoint != "localhost:4317" {
		t.Errorf("expected default endpoint to be localhost:4317, got %s", cfg.Endpoint)
	}

	if cfg.Compression != CompressionGzip {
		t.Errorf("expected default compression to be gzip, got %v", cfg.Compression)
	}

	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected default timeout to be 30s, got %v", cfg.Timeout)
	}
}

func TestConfigFromEnv(t *testing.T) {
	// Save and restore env
	origEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	origProtocol := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	origCompression := os.Getenv("OTEL_EXPORTER_OTLP_COMPRESSION")
	defer func() {
		os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", origEndpoint)
		os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", origProtocol)
		os.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", origCompression)
	}()

	// Set test env
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
	os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	os.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")

	cfg := ConfigFromEnv()

	if cfg.Endpoint != "http://collector:4318" {
		t.Errorf("expected endpoint from env, got %s", cfg.Endpoint)
	}

	if cfg.Protocol != ProtocolHTTPProtobuf {
		t.Errorf("expected HTTP/protobuf protocol, got %v", cfg.Protocol)
	}

	if cfg.Compression != CompressionGzip {
		t.Errorf("expected gzip compression, got %v", cfg.Compression)
	}
}

func TestSignalType(t *testing.T) {
	tests := []struct {
		signal   SignalType
		expected string
	}{
		{SignalTraces, "traces"},
		{SignalMetrics, "metrics"},
		{SignalLogs, "logs"},
		{SignalProfiles, "profiles"},
	}

	for _, tt := range tests {
		if tt.signal.String() != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.signal.String())
		}
	}
}

func TestProtocol(t *testing.T) {
	tests := []struct {
		protocol Protocol
		expected string
	}{
		{ProtocolGRPC, "grpc"},
		{ProtocolHTTPProtobuf, "http/protobuf"},
		{ProtocolHTTPJSON, "http/json"},
	}

	for _, tt := range tests {
		if tt.protocol.String() != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.protocol.String())
		}
	}
}

func TestCompression(t *testing.T) {
	tests := []struct {
		compression Compression
		expected    string
	}{
		{CompressionNone, "none"},
		{CompressionGzip, "gzip"},
		{CompressionZstd, "zstd"},
	}

	for _, tt := range tests {
		if tt.compression.String() != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.compression.String())
		}
	}
}

func TestBatchConfig(t *testing.T) {
	cfg := BatchConfig{
		MaxBatchSize:  100,
		MaxBatchBytes: 1024 * 1024,
		Timeout:       5 * time.Second,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	batcher := NewBatcher(cfg, logger)

	if batcher == nil {
		t.Fatal("expected batcher to be created")
	}

	ctx := context.Background()
	batcher.Start(ctx, func(ctx context.Context, signal SignalType, data []byte) error {
		return nil
	})

	// Test adding items
	data := []byte("test data")
	if err := batcher.Add(ctx, SignalTraces, data); err != nil {
		t.Errorf("failed to add to batch: %v", err)
	}

	if batcher.QueuedItems() != 1 {
		t.Errorf("expected 1 queued item, got %d", batcher.QueuedItems())
	}

	// Flush
	if err := batcher.Flush(ctx); err != nil {
		t.Errorf("failed to flush batch: %v", err)
	}

	// Wait for export goroutine
	time.Sleep(100 * time.Millisecond)

	if batcher.QueuedItems() != 0 {
		t.Errorf("expected 0 queued items after flush, got %d", batcher.QueuedItems())
	}

	// Stop
	if err := batcher.Stop(ctx); err != nil {
		t.Errorf("failed to stop batcher: %v", err)
	}
}

func TestRetryConfig(t *testing.T) {
	cfg := RetryConfig{
		Enabled:             true,
		InitialInterval:     100 * time.Millisecond,
		MaxInterval:         1 * time.Second,
		MaxElapsedTime:      30 * time.Second,
		Multiplier:          2.0,
		RandomizationFactor: 0.1,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	retryer := NewRetryer(cfg, logger)

	if retryer == nil {
		t.Fatal("expected retryer to be created")
	}

	// Test successful retry
	ctx := context.Background()
	attempts := 0
	err := retryer.Do(ctx, func(ctx context.Context, attempt int) error {
		attempts++
		if attempt < 2 {
			return NewRetryableError(context.DeadlineExceeded, true)
		}
		return nil
	})

	if err != nil {
		t.Errorf("expected success after retries, got %v", err)
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetryerNonRetryable(t *testing.T) {
	cfg := RetryConfig{
		Enabled:         true,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      2.0,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	retryer := NewRetryer(cfg, logger)
	ctx := context.Background()
	attempts := 0

	err := retryer.Do(ctx, func(ctx context.Context, attempt int) error {
		attempts++
		return NewRetryableError(context.Canceled, false)
	})

	if err == nil {
		t.Error("expected error for non-retryable")
	}

	if attempts != 1 {
		t.Errorf("expected 1 attempt for non-retryable, got %d", attempts)
	}
}

func TestRetryerDisabled(t *testing.T) {
	cfg := RetryConfig{
		Enabled: false,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	retryer := NewRetryer(cfg, logger)
	ctx := context.Background()
	attempts := 0

	err := retryer.Do(ctx, func(ctx context.Context, attempt int) error {
		attempts++
		return NewRetryableError(context.DeadlineExceeded, true)
	})

	if err == nil {
		t.Error("expected error when retry disabled")
	}

	if attempts != 1 {
		t.Errorf("expected 1 attempt when disabled, got %d", attempts)
	}
}

func TestRetryableError(t *testing.T) {
	// Test retryable error
	err := NewRetryableError(context.DeadlineExceeded, true)
	if !err.Retryable {
		t.Error("expected error to be retryable")
	}

	if err.Error() != context.DeadlineExceeded.Error() {
		t.Errorf("expected error message to match underlying error")
	}

	// Test non-retryable error
	err = NewRetryableError(context.Canceled, false)
	if err.Retryable {
		t.Error("expected error to be non-retryable")
	}

	// Test with retry-after
	err = NewRetryableErrorWithAfter(context.DeadlineExceeded, 5*time.Second)
	if !err.Retryable {
		t.Error("expected error to be retryable")
	}

	if err.RetryAfter != 5*time.Second {
		t.Errorf("expected RetryAfter to be 5s, got %v", err.RetryAfter)
	}
}

func TestTLSConfig(t *testing.T) {
	cfg := TLSConfig{
		Enabled:            true,
		InsecureSkipVerify: false,
		CertFile:           "/path/to/cert.pem",
		KeyFile:            "/path/to/key.pem",
		CAFile:             "/path/to/ca.pem",
	}

	if !cfg.Enabled {
		t.Error("expected TLS to be enabled")
	}

	if cfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false")
	}
}

func TestBatcherMaxBatchSize(t *testing.T) {
	cfg := BatchConfig{
		MaxBatchSize:  3,
		MaxBatchBytes: 1024 * 1024,
		Timeout:       5 * time.Second,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	batcher := NewBatcher(cfg, logger)
	exported := make(chan []byte, 10)
	ctx := context.Background()

	batcher.Start(ctx, func(ctx context.Context, signal SignalType, data []byte) error {
		exported <- data
		return nil
	})

	// Add items up to max batch size, then one more to trigger flush
	for i := 0; i < 4; i++ {
		if err := batcher.Add(ctx, SignalTraces, []byte("data")); err != nil {
			t.Errorf("failed to add item %d: %v", i, err)
		}
	}

	// Wait for auto-flush
	time.Sleep(100 * time.Millisecond)

	select {
	case <-exported:
		// Expected
	case <-time.After(time.Second):
		t.Error("expected batch to be exported when max size reached")
	}

	batcher.Stop(ctx)
}

func TestBatcherTimeout(t *testing.T) {
	cfg := BatchConfig{
		MaxBatchSize:  100, // High limit so timeout triggers
		MaxBatchBytes: 1024 * 1024,
		Timeout:       100 * time.Millisecond,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	batcher := NewBatcher(cfg, logger)
	exported := make(chan []byte, 10)
	ctx := context.Background()

	batcher.Start(ctx, func(ctx context.Context, signal SignalType, data []byte) error {
		exported <- data
		return nil
	})

	// Add single item
	if err := batcher.Add(ctx, SignalTraces, []byte("data")); err != nil {
		t.Errorf("failed to add item: %v", err)
	}

	// Wait for timeout-triggered export
	select {
	case <-exported:
		// Expected
	case <-time.After(500 * time.Millisecond):
		t.Error("expected batch to be exported on timeout")
	}

	batcher.Stop(ctx)
}

// ConfigError represents a configuration error.
type ConfigError struct {
	Field   string
	Message string
}

// Error returns the error message.
func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Message
}

// validateConfig validates the exporter configuration.
func validateConfig(cfg *Config) error {
	if cfg.Endpoint == "" {
		return &ConfigError{Field: "endpoint", Message: "endpoint is required"}
	}

	switch cfg.Protocol {
	case ProtocolGRPC, ProtocolHTTPProtobuf, ProtocolHTTPJSON:
		// Valid
	default:
		return &ConfigError{Field: "protocol", Message: "invalid protocol"}
	}

	return nil
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Endpoint: "localhost:4317",
				Protocol: ProtocolGRPC,
			},
			wantErr: false,
		},
		{
			name: "empty endpoint",
			cfg: Config{
				Protocol: ProtocolGRPC,
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			cfg: Config{
				Endpoint: "localhost:4317",
				Protocol: Protocol("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExponentialBackoffPolicy(t *testing.T) {
	cfg := RetryConfig{
		InitialInterval:     100 * time.Millisecond,
		MaxInterval:         1 * time.Second,
		Multiplier:          2.0,
		RandomizationFactor: 0,
	}

	policy := NewExponentialBackoffPolicy(cfg)

	// Test backoff durations
	expected := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1000 * time.Millisecond, // capped at max
	}

	for i, exp := range expected {
		got := policy.BackoffDuration(i)
		if got != exp {
			t.Errorf("attempt %d: expected %v, got %v", i, exp, got)
		}
	}
}

func TestLinearBackoffPolicy(t *testing.T) {
	policy := &LinearBackoffPolicy{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		Increment:       100 * time.Millisecond,
	}

	// Test backoff durations
	expected := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		300 * time.Millisecond,
		400 * time.Millisecond,
		500 * time.Millisecond, // capped at max
	}

	for i, exp := range expected {
		got := policy.BackoffDuration(i)
		if got != exp {
			t.Errorf("attempt %d: expected %v, got %v", i, exp, got)
		}
	}
}
