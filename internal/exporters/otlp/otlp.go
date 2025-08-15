package otlp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"time"

	// Traces
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	// Logs (official, not contrib)
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"google.golang.org/grpc/credentials"
)

// TraceOpts carries configuration for both traces and logs via OTLP.
type TraceOpts struct {
	Mode string
	TLS  struct {
		Enable                    bool
		CAFile, CertFile, KeyFile string
		InsecureSkipVerify        bool
	}
	GRPC struct {
		Enabled  bool
		Endpoint string
		Insecure bool
		Gzip     bool
		Headers  map[string]string
		Timeout  time.Duration
	}
	HTTP struct {
		Enabled    bool
		Endpoint   string // full base URL, e.g. "http://collector:4318" or "https://collector:4318"
		TracesPath string // e.g. "/v1/traces"
		LogsPath   string // e.g. "/v1/logs"
		Headers    map[string]string
		Gzip       bool
		Timeout    time.Duration
	}
}

type Clients struct {
	Trace *sdktrace.TracerProvider
	Log   *sdklog.LoggerProvider
	close func(context.Context) error
}

// New builds Tracer/Logger providers based on the supplied options.
// It prefers gRPC when enabled, and falls back to HTTP if needed.
func New(ctx context.Context, o TraceOpts) (*Clients, error) {
	// ---- TRACES ----
	var tp *sdktrace.TracerProvider

	// Try gRPC first (if enabled)
	if o.GRPC.Enabled {
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(o.GRPC.Endpoint),
		}
		if o.TLS.Enable && !o.GRPC.Insecure {
			creds, err := buildTLS(o.TLS.CAFile, o.TLS.CertFile, o.TLS.KeyFile, o.TLS.InsecureSkipVerify)
			if err != nil {
				return nil, err
			}
			opts = append(opts, otlptracegrpc.WithTLSCredentials(creds))
		} else {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if o.GRPC.Timeout > 0 {
			opts = append(opts, otlptracegrpc.WithTimeout(o.GRPC.Timeout))
		}
		if len(o.GRPC.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(o.GRPC.Headers))
		}
		exp, err := otlptracegrpc.New(ctx, opts...)
		if err == nil {
			tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
		}
	}

	// Fall back to HTTP if needed (use EndpointURL so tests can pass srv.URL)
	if tp == nil && o.HTTP.Enabled {
		url := o.HTTP.Endpoint + o.HTTP.TracesPath
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpointURL(url), // full URL, e.g. http://host:4318/v1/traces
		}
		if len(o.HTTP.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(o.HTTP.Headers))
		}
		if o.HTTP.Timeout > 0 {
			opts = append(opts, otlptracehttp.WithTimeout(o.HTTP.Timeout))
		}
		if o.HTTP.Gzip {
			opts = append(opts, otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
		}
		exp, err := otlptracehttp.New(ctx, opts...)
		if err == nil {
			tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
		}
	}

	if tp == nil {
		return nil, errors.New("no OTLP trace endpoint usable (check GRPC/HTTP settings)")
	}

	// ---- LOGS ----
	var lp *sdklog.LoggerProvider

	// Try gRPC first (if enabled)
	if o.GRPC.Enabled {
		lopts := []otlploggrpc.Option{
			otlploggrpc.WithEndpoint(o.GRPC.Endpoint),
		}
		if o.TLS.Enable && !o.GRPC.Insecure {
			creds, err := buildTLS(o.TLS.CAFile, o.TLS.CertFile, o.TLS.KeyFile, o.TLS.InsecureSkipVerify)
			if err == nil {
				lopts = append(lopts, otlploggrpc.WithTLSCredentials(creds))
			} else {
				lopts = append(lopts, otlploggrpc.WithInsecure())
			}
		} else {
			lopts = append(lopts, otlploggrpc.WithInsecure())
		}
		if o.GRPC.Timeout > 0 {
			lopts = append(lopts, otlploggrpc.WithTimeout(o.GRPC.Timeout))
		}
		if len(o.GRPC.Headers) > 0 {
			lopts = append(lopts, otlploggrpc.WithHeaders(o.GRPC.Headers))
		}
		lexp, err := otlploggrpc.New(ctx, lopts...)
		if err == nil {
			lp = sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp)))
		}
	}

	// Fall back to HTTP if needed (use EndpointURL so tests can pass srv.URL)
	if lp == nil && o.HTTP.Enabled {
		url := o.HTTP.Endpoint + o.HTTP.LogsPath
		lh := []otlploghttp.Option{
			otlploghttp.WithEndpointURL(url), // full URL, e.g. http://host:4318/v1/logs
		}
		if len(o.HTTP.Headers) > 0 {
			lh = append(lh, otlploghttp.WithHeaders(o.HTTP.Headers))
		}
		if o.HTTP.Timeout > 0 {
			lh = append(lh, otlploghttp.WithTimeout(o.HTTP.Timeout))
		}
		if o.HTTP.Gzip {
			lh = append(lh, otlploghttp.WithCompression(otlploghttp.GzipCompression))
		}
		lexp, err := otlploghttp.New(ctx, lh...)
		if err == nil {
			lp = sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp)))
		}
	}

	if lp == nil {
		return nil, errors.New("no OTLP log endpoint usable (check GRPC/HTTP settings)")
	}

	return &Clients{
		Trace: tp,
		Log:   lp,
		close: func(ctx context.Context) error {
			var e1, e2 error
			if lp != nil {
				e1 = lp.Shutdown(ctx)
			}
			if tp != nil {
				e2 = tp.Shutdown(ctx)
			}
			if e1 != nil {
				return e1
			}
			return e2
		},
	}, nil
}

// buildTLS creates gRPC TransportCredentials for mTLS / custom CAs.
func buildTLS(ca, cert, key string, insecure bool) (credentials.TransportCredentials, error) {
	cfg := &tls.Config{InsecureSkipVerify: insecure}

	if ca != "" {
		b, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("bad ca")
		}
		cfg.RootCAs = pool
	}
	if cert != "" && key != "" {
		crt, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{crt}
	}
	return credentials.NewTLS(cfg), nil
}
