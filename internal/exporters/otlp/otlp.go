package otlp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
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
		Insecure  bool
		TracesURL string
		LogsURL   string
		Headers   map[string]string
		Gzip      bool
		Timeout   time.Duration
	}
}

// Clients contains the OTLP exporters for all signal types.
// This is the unified exporter that should be used by all telegen components.
//
// For traces, we provide both:
//   - Trace (*sdktrace.TracerProvider): SDK-based tracer for application instrumentation
//   - CollectorTraces (exporter.Traces): Collector-compatible exporter for eBPF/agent use cases
//
// The CollectorTraces exporter follows the OpenTelemetry Collector standard and is the
// recommended interface for agents that forward telemetry data (like eBPF traces).
type Clients struct {
	// Trace is the SDK TracerProvider for application instrumentation (kube_metrics, etc.)
	Trace *sdktrace.TracerProvider
	// CollectorTraces is the Collector-compatible exporter for eBPF/agent traces.
	// This follows the OpenTelemetry Collector standard (exporter.Traces interface).
	CollectorTraces exporter.Traces
	Log             *sdklog.LoggerProvider
	Metrics         sdkmetric.Exporter
	close           func(context.Context) error
}

func New(ctx context.Context, o TraceOpts, res *resource.Resource) (*Clients, error) {
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
			if res != nil {
				tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
			} else {
				tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
			}
		}
	}
	if tp == nil && o.HTTP.Enabled {
		httpTraceOpts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(o.HTTP.Endpoint),
			otlptracehttp.WithURLPath(o.HTTP.TracesURL),
			otlptracehttp.WithHeaders(o.HTTP.Headers),
		}
		if !o.TLS.Enable || o.HTTP.Insecure {
			httpTraceOpts = append(httpTraceOpts, otlptracehttp.WithInsecure())
		}
		exp, err := otlptracehttp.New(ctx, httpTraceOpts...)
		if err == nil {
			if res != nil {
				tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
			} else {
				tp = sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
			}
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
			if res != nil {
				lp = sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp)))
			} else {
				lp = sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp)))
			}
		}
	}
	if lp == nil && o.HTTP.Enabled {
		httpLogOpts := []otlploghttp.Option{
			otlploghttp.WithEndpoint(o.HTTP.Endpoint),
			otlploghttp.WithURLPath(o.HTTP.LogsURL),
			otlploghttp.WithHeaders(o.HTTP.Headers),
		}
		if !o.TLS.Enable || o.HTTP.Insecure {
			httpLogOpts = append(httpLogOpts, otlploghttp.WithInsecure())
		}
		lexp, err := otlploghttp.New(ctx, httpLogOpts...)
		if err == nil {
			if res != nil {
				lp = sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp)))
			} else {
				lp = sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp)))
			}
		}
	}
	if lp == nil {
		return nil, errors.New("no OTLP log endpoint usable")
	}

	// Create metrics exporter for kube_metrics, node_exporter, etc.
	var mexp sdkmetric.Exporter
	if o.GRPC.Enabled {
		mopts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(o.GRPC.Endpoint)}
		if o.TLS.Enable && !o.GRPC.Insecure {
			creds, err := buildTLS(o.TLS.CAFile, o.TLS.CertFile, o.TLS.KeyFile, o.TLS.InsecureSkipVerify)
			if err == nil {
				mopts = append(mopts, otlpmetricgrpc.WithTLSCredentials(creds))
			} else {
				mopts = append(mopts, otlpmetricgrpc.WithInsecure())
			}
		} else {
			mopts = append(mopts, otlpmetricgrpc.WithInsecure())
		}
		mexp, _ = otlpmetricgrpc.New(ctx, mopts...)
	}
	if mexp == nil && o.HTTP.Enabled {
		httpMetricOpts := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpoint(o.HTTP.Endpoint),
			otlpmetrichttp.WithHeaders(o.HTTP.Headers),
		}
		if !o.TLS.Enable || o.HTTP.Insecure {
			httpMetricOpts = append(httpMetricOpts, otlpmetrichttp.WithInsecure())
		}
		mexp, _ = otlpmetrichttp.New(ctx, httpMetricOpts...)
	}
	// Note: mexp can be nil - metrics export is optional, traces and logs are required

	// Create Collector-compatible traces exporter for eBPF/agent use cases.
	// This follows the OpenTelemetry Collector standard (exporter.Traces interface).
	collectorTraces, err := createCollectorTracesExporter(ctx, o)
	if err != nil {
		slog.Warn("failed to create collector traces exporter", "error", err)
		// Non-fatal: eBPF can fall back to creating its own exporter
	}

	return &Clients{
		Trace:           tp,
		CollectorTraces: collectorTraces,
		Log:             lp,
		Metrics:         mexp,
		close: func(ctx context.Context) error {
			var errs []error
			if collectorTraces != nil {
				if err := collectorTraces.Shutdown(ctx); err != nil {
					errs = append(errs, err)
				}
			}
			if mexp != nil {
				if err := mexp.Shutdown(ctx); err != nil {
					errs = append(errs, err)
				}
			}
			if lp != nil {
				if err := lp.Shutdown(ctx); err != nil {
					errs = append(errs, err)
				}
			}
			if tp != nil {
				if err := tp.Shutdown(ctx); err != nil {
					errs = append(errs, err)
				}
			}
			if len(errs) > 0 {
				return errs[0]
			}
			return nil
		},
	}, nil
}

func buildTLS(ca, cert, key string, insecure bool) (credentials.TransportCredentials, error) {
	cfg := &tls.Config{InsecureSkipVerify: insecure}
	if ca != "" {
		b, err := os.ReadFile(ca)
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

// createCollectorTracesExporter creates an OpenTelemetry Collector-compatible traces exporter.
// This follows the OTLP Collector standard and is the recommended interface for agents
// that forward telemetry data (like eBPF traces).
func createCollectorTracesExporter(ctx context.Context, o TraceOpts) (exporter.Traces, error) {
	if o.GRPC.Enabled {
		return createGRPCCollectorTracesExporter(ctx, o)
	}
	if o.HTTP.Enabled {
		return createHTTPCollectorTracesExporter(ctx, o)
	}
	return nil, errors.New("no OTLP endpoint configured for collector traces exporter")
}

// createGRPCCollectorTracesExporter creates a gRPC-based Collector traces exporter
func createGRPCCollectorTracesExporter(ctx context.Context, o TraceOpts) (exporter.Traces, error) {
	factory := otlpexporter.NewFactory()
	config := factory.CreateDefaultConfig().(*otlpexporter.Config)

	config.RetryConfig = configretry.NewDefaultBackOffConfig()
	config.ClientConfig = configgrpc.ClientConfig{
		Endpoint: o.GRPC.Endpoint,
		TLS: configtls.ClientConfig{
			Insecure:           o.GRPC.Insecure || !o.TLS.Enable,
			InsecureSkipVerify: o.TLS.InsecureSkipVerify,
		},
		Headers: convertHeadersToOpaque(o.GRPC.Headers),
	}

	// Add TLS config if enabled
	if o.TLS.Enable && !o.GRPC.Insecure {
		config.ClientConfig.TLS = configtls.ClientConfig{
			Config: configtls.Config{
				CAFile:   o.TLS.CAFile,
				CertFile: o.TLS.CertFile,
				KeyFile:  o.TLS.KeyFile,
			},
			InsecureSkipVerify: o.TLS.InsecureSkipVerify,
		}
	}

	set := getCollectorSettings(factory.Type())
	exp, err := factory.CreateTraces(ctx, set, config)
	if err != nil {
		return nil, err
	}

	// Start the exporter
	if err := exp.Start(ctx, emptyHost{}); err != nil {
		return nil, err
	}

	slog.Info("created unified collector traces exporter", "protocol", "grpc", "endpoint", o.GRPC.Endpoint)
	return exp, nil
}

// createHTTPCollectorTracesExporter creates an HTTP-based Collector traces exporter
func createHTTPCollectorTracesExporter(ctx context.Context, o TraceOpts) (exporter.Traces, error) {
	factory := otlphttpexporter.NewFactory()
	config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)

	config.RetryConfig = configretry.NewDefaultBackOffConfig()

	// Build endpoint URL
	scheme := "https"
	if o.HTTP.Insecure || !o.TLS.Enable {
		scheme = "http"
	}
	endpoint := scheme + "://" + o.HTTP.Endpoint
	if o.HTTP.TracesURL != "" {
		endpoint = endpoint + o.HTTP.TracesURL
	}

	config.ClientConfig = confighttp.ClientConfig{
		Endpoint: endpoint,
		TLS: configtls.ClientConfig{
			Insecure:           o.HTTP.Insecure || !o.TLS.Enable,
			InsecureSkipVerify: o.TLS.InsecureSkipVerify,
		},
		Headers: convertHeadersToOpaque(o.HTTP.Headers),
	}

	// Add TLS config if enabled
	if o.TLS.Enable && !o.HTTP.Insecure {
		config.ClientConfig.TLS = configtls.ClientConfig{
			Config: configtls.Config{
				CAFile:   o.TLS.CAFile,
				CertFile: o.TLS.CertFile,
				KeyFile:  o.TLS.KeyFile,
			},
			InsecureSkipVerify: o.TLS.InsecureSkipVerify,
		}
	}

	set := getCollectorSettings(factory.Type())
	exp, err := factory.CreateTraces(ctx, set, config)
	if err != nil {
		return nil, err
	}

	// Wrap with queue/retry using exporterhelper
	exp, err = exporterhelper.NewTraces(ctx, set, config,
		exp.ConsumeTraces,
		exporterhelper.WithStart(exp.Start),
		exporterhelper.WithShutdown(exp.Shutdown),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
		exporterhelper.WithRetry(config.RetryConfig),
	)
	if err != nil {
		return nil, err
	}

	// Start the exporter
	if err := exp.Start(ctx, emptyHost{}); err != nil {
		return nil, err
	}

	slog.Info("created unified collector traces exporter", "protocol", "http", "endpoint", endpoint)
	return exp, nil
}

// getCollectorSettings creates exporter.Settings for Collector exporters
func getCollectorSettings(dataType component.Type) exporter.Settings {
	return exporter.Settings{
		ID: component.NewIDWithName(dataType, "unified"),
		TelemetrySettings: component.TelemetrySettings{
			Logger:         zap.NewNop(),
			MeterProvider:  sdkmetric.NewMeterProvider(),
			TracerProvider: tracenoop.NewTracerProvider(),
			Resource:       pcommon.NewResource(),
		},
	}
}

// convertHeadersToOpaque converts string headers to configopaque format
func convertHeadersToOpaque(headers map[string]string) configopaque.MapList {
	if headers == nil {
		return nil
	}
	opaqueHeaders := make(configopaque.MapList, 0, len(headers))
	for key, value := range headers {
		opaqueHeaders = append(opaqueHeaders, configopaque.Pair{Name: key, Value: configopaque.String(value)})
	}
	return opaqueHeaders
}

// emptyHost implements component.Host for exporter.Start
type emptyHost struct{}

func (emptyHost) GetExtensions() map[component.ID]component.Component {
	return nil
}
