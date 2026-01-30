// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCTransport implements OTLP export over gRPC.
type GRPCTransport struct {
	cfg Config
	log *slog.Logger

	conn *grpc.ClientConn

	mu      sync.RWMutex
	running bool
}

// NewGRPCTransport creates a new gRPC transport.
func NewGRPCTransport(cfg Config, log *slog.Logger) (*GRPCTransport, error) {
	return &GRPCTransport{
		cfg: cfg,
		log: log.With("transport", "grpc"),
	}, nil
}

// Connect establishes the gRPC connection.
func (t *GRPCTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return nil
	}

	t.log.Info("connecting to OTLP endpoint", "endpoint", t.cfg.Endpoint)

	opts, err := t.buildDialOptions()
	if err != nil {
		return fmt.Errorf("failed to build dial options: %w", err)
	}

	// Create connection with timeout
	dialCtx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, t.cfg.Endpoint, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial endpoint: %w", err)
	}

	t.conn = conn
	t.running = true

	t.log.Info("connected to OTLP endpoint")
	return nil
}

// buildDialOptions builds the gRPC dial options.
func (t *GRPCTransport) buildDialOptions() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	// Set block dial to ensure connection is established
	opts = append(opts, grpc.WithBlock())

	// Configure TLS
	if t.cfg.TLS.Enabled {
		tlsConfig, err := t.buildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Configure compression
	if t.cfg.Compression == CompressionGzip {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
	}

	// Configure keepalive
	opts = append(opts, grpc.WithKeepaliveParams(grpcKeepaliveParams()))

	// Configure default timeout
	opts = append(opts, grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(16*1024*1024), // 16MB
		grpc.MaxCallSendMsgSize(16*1024*1024), // 16MB
	))

	return opts, nil
}

// buildTLSConfig builds the TLS configuration.
func (t *GRPCTransport) buildTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: t.cfg.TLS.InsecureSkipVerify,
	}

	if t.cfg.TLS.ServerName != "" {
		cfg.ServerName = t.cfg.TLS.ServerName
	}

	// Load CA certificate
	if t.cfg.TLS.CAFile != "" {
		caCert, err := os.ReadFile(t.cfg.TLS.CAFile)
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
	if t.cfg.TLS.CertFile != "" && t.cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.cfg.TLS.CertFile, t.cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// Send sends data over gRPC.
func (t *GRPCTransport) Send(ctx context.Context, signal SignalType, data []byte) error {
	t.mu.RLock()
	conn := t.conn
	running := t.running
	t.mu.RUnlock()

	if !running || conn == nil {
		return fmt.Errorf("gRPC transport not connected")
	}

	// Add headers to context
	if len(t.cfg.Headers) > 0 {
		md := metadata.New(t.cfg.Headers)
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	// Get the appropriate service method
	method := t.getServiceMethod(signal)

	// Apply timeout
	if t.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.cfg.Timeout)
		defer cancel()
	}

	// Make the gRPC call
	var response []byte
	err := conn.Invoke(ctx, method, data, &response)
	if err != nil {
		return t.handleError(err)
	}

	return nil
}

// getServiceMethod returns the gRPC service method for the signal type.
func (t *GRPCTransport) getServiceMethod(signal SignalType) string {
	switch signal {
	case SignalTraces:
		return "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
	case SignalMetrics:
		return "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
	case SignalLogs:
		return "/opentelemetry.proto.collector.logs.v1.LogsService/Export"
	case SignalProfiles:
		return "/opentelemetry.proto.collector.profiles.v1experimental.ProfilesService/Export"
	default:
		return ""
	}
}

// handleError handles gRPC errors and determines if they are retryable.
func (t *GRPCTransport) handleError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	code := st.Code()
	msg := st.Message()

	// Determine if error is retryable
	switch code {
	case codes.OK:
		return nil

	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable, codes.ResourceExhausted:
		return &RetryableError{
			Err:       fmt.Errorf("gRPC error (retryable): %s - %s", code, msg),
			Retryable: true,
		}

	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists,
		codes.PermissionDenied, codes.FailedPrecondition, codes.Aborted,
		codes.OutOfRange, codes.Unimplemented, codes.Internal,
		codes.DataLoss, codes.Unauthenticated:
		return &RetryableError{
			Err:       fmt.Errorf("gRPC error (permanent): %s - %s", code, msg),
			Retryable: false,
		}

	default:
		return fmt.Errorf("gRPC error: %s - %s", code, msg)
	}
}

// Close closes the gRPC connection.
func (t *GRPCTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}

	t.running = false

	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			return fmt.Errorf("failed to close gRPC connection: %w", err)
		}
		t.conn = nil
	}

	t.log.Info("gRPC connection closed")
	return nil
}

// IsConnected returns whether the transport is connected.
func (t *GRPCTransport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running && t.conn != nil
}

// isRetryableGRPCError returns whether the gRPC error is retryable.
func isRetryableGRPCError(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}

// grpcKeepaliveParams returns the gRPC keepalive parameters.
func grpcKeepaliveParams() keepalive.ClientParameters {
	// Return default keepalive params
	return keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             3 * time.Second,
		PermitWithoutStream: true,
	}
}

// grpcReconnectBackoff returns the reconnect backoff configuration.
func grpcReconnectBackoff() time.Duration {
	return 1 * time.Second
}
