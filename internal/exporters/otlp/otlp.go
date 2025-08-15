package otlp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc/credentials"
)

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
		Enabled   bool
		Endpoint  string
		TracesURL string
		LogsURL   string
		Headers   map[string]string
		Gzip      bool
		Timeout   time.Duration
	}
}

type Clients struct {
	Trace *sdktrace.TracerProvider
	Log   *sdklog.LoggerProvider
	close func(context.Context) error
}

func New(ctx context.Context, o TraceOpts) (*Clients, error) {
	var tp *sdktrace.TracerProvider
	if o.GRPC.Enabled {
		opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(o.GRPC.Endpoint)}
		if o.TLS.Enable && !o.GRPC.Insecure {
			creds, err := buildTLS(o.TLS.CAFile, o.TLS.CertFile, o.TLS.KeyFile, o.TLS.InsecureSkipVerify)
			if err != nil {
				return nil, err
			}
			opts = append(opts, otlptracegrpc.WithTLSCredentials(creds))
		} else {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		exp, err := otlptracegrpc.New(ctx, opts...)
		if err == nil {
			tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
		}
	}
	if tp == nil && o.HTTP.Enabled {
		exp, err := otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(o.HTTP.Endpoint),
			otlptracehttp.WithTracesURL(o.HTTP.TracesURL),
			otlptracehttp.WithHeaders(o.HTTP.Headers),
		)
		if err == nil {
			tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
		}
	}
	if tp == nil {
		return nil, errors.New("no OTLP trace endpoint usable")
	}

	var lp *sdklog.LoggerProvider
	if o.GRPC.Enabled {
		lopts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(o.GRPC.Endpoint)}
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
		lexp, err := otlploggrpc.New(ctx, lopts...)
		if err == nil {
			lp = sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp)))
		}
	}
	if lp == nil && o.HTTP.Enabled {
		lexp, err := otlploghttp.New(ctx,
			otlploghttp.WithEndpoint(o.HTTP.Endpoint),
			otlploghttp.WithLogsURL(o.HTTP.LogsURL),
			otlploghttp.WithHeaders(o.HTTP.Headers),
		)
		if err == nil {
			lp = sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp)))
		}
	}
	if lp == nil {
		return nil, errors.New("no OTLP log endpoint usable")
	}

	return &Clients{Trace: tp, Log: lp, close: func(ctx context.Context) error {
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
	}}, nil
}

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
