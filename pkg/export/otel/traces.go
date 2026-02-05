// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "github.com/platformbuilds/telegen/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/platformbuilds/telegen/internal/appolly/app/request"
	"github.com/platformbuilds/telegen/internal/appolly/app/svc"
	"github.com/platformbuilds/telegen/pkg/export/attributes"
	attr "github.com/platformbuilds/telegen/pkg/export/attributes/names"
	"github.com/platformbuilds/telegen/pkg/export/imetrics"
	"github.com/platformbuilds/telegen/pkg/export/instrumentations"
	"github.com/platformbuilds/telegen/pkg/export/otel/otelcfg"
	"github.com/platformbuilds/telegen/pkg/export/otel/tracesgen"
	"github.com/platformbuilds/telegen/pkg/pipe/global"
	"github.com/platformbuilds/telegen/pkg/pipe/msg"
	"github.com/platformbuilds/telegen/pkg/pipe/swarm"
	"github.com/platformbuilds/telegen/pkg/pipe/swarm/swarms"
)

const reporterName = "go.opentelemetry.io/obi"

func otlog() *slog.Logger {
	return slog.With("component", "otel.TracesReceiver")
}

func makeTracesReceiver(
	cfg otelcfg.TracesConfig,
	spanMetricsEnabled bool,
	ctxInfo *global.ContextInfo,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) *tracesOTELReceiver {
	// Use the shared traces exporter from the unified OTLP pipeline if available
	if ctxInfo.OTELTracesExporter != nil && cfg.SharedTracesExporter == nil {
		cfg.SharedTracesExporter = ctxInfo.OTELTracesExporter
	}

	return &tracesOTELReceiver{
		cfg:                cfg,
		ctxInfo:            ctxInfo,
		selectorCfg:        selectorCfg,
		is:                 instrumentations.NewInstrumentationSelection(cfg.Instrumentations),
		spanMetricsEnabled: spanMetricsEnabled,
		input:              input.Subscribe(msg.SubscriberName("otel.TracesReceiver")),
		attributeCache:     expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),
	}
}

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
func TracesReceiver(
	ctxInfo *global.ContextInfo,
	cfg otelcfg.TracesConfig,
	spanMetricsEnabled bool,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		tr := makeTracesReceiver(cfg, spanMetricsEnabled, ctxInfo, selectorCfg, input)
		return tr.provideLoop, nil
	}
}

type tracesOTELReceiver struct {
	cfg                otelcfg.TracesConfig
	ctxInfo            *global.ContextInfo
	selectorCfg        *attributes.SelectorConfig
	is                 instrumentations.InstrumentationSelection
	spanMetricsEnabled bool
	attributeCache     *expirable2.LRU[svc.UID, []attribute.KeyValue]
	input              <-chan []request.Span
}

func (tr *tracesOTELReceiver) getConstantAttributes() (map[attr.Name]struct{}, error) {
	traceAttrs, err := tracesgen.UserSelectedAttributes(tr.selectorCfg)
	if err != nil {
		return nil, err
	}

	if tr.spanMetricsEnabled {
		traceAttrs[attr.SkipSpanMetrics] = struct{}{}
	}
	return traceAttrs, nil
}

func (tr *tracesOTELReceiver) processSpans(ctx context.Context, exp exporter.Traces, spans []request.Span, traceAttrs map[attr.Name]struct{}, sampler trace.Sampler) {
	spanGroups := tracesgen.GroupSpans(ctx, spans, traceAttrs, sampler, tr.is)

	for _, spanGroup := range spanGroups {
		if len(spanGroup) > 0 {
			sample := spanGroup[0]

			if !sample.Span.Service.ExportModes.CanExportTraces() {
				continue
			}

			envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
			if tr.spanMetricsEnabled {
				envResourceAttrs = append(envResourceAttrs, attribute.Bool(string(attr.SkipSpanMetrics.OTEL()), true))
			}
			traces := tracesgen.GenerateTracesWithAttributes(tr.attributeCache, &sample.Span.Service, envResourceAttrs, tr.ctxInfo.HostID, spanGroup, reporterName, tr.ctxInfo.ExtraResourceAttributes...)
			err := exp.ConsumeTraces(ctx, traces)
			if err != nil {
				// We can't do if errors.Is(err, queue.ErrQueueIsFull), since the queue package is internal
				if err.Error() == "sending queue is full" {
					// TODO: set this condition case to Warn once we make sure that
					// queueConfig.BlockOnOverflow = true works as expected
					slog.Debug("error sending trace to consumer", "error", err)
				} else {
					slog.Warn("error sending trace to consumer", "error", err)
				}
			}
		}
	}
}

// emptyHost prevents nil pointer dereference after invoking exp.Start below
type emptyHost struct{}

func (emptyHost) GetExtensions() map[component.ID]component.Component {
	return nil
}

func (tr *tracesOTELReceiver) provideLoop(ctx context.Context) {
	exp, err := getTracesExporter(ctx, tr.cfg, tr.ctxInfo.Metrics)
	if err != nil {
		slog.Error("error creating traces exporter", "error", err)
		return
	}

	// Only manage lifecycle if NOT using the shared exporter
	// The shared exporter's lifecycle is managed by the unified OTLP pipeline
	usingSharedExporter := tr.cfg.SharedTracesExporter != nil
	if !usingSharedExporter {
		defer func() {
			err := exp.Shutdown(ctx)
			if err != nil {
				slog.Error("error shutting down traces exporter", "error", err)
			}
		}()
		err = exp.Start(ctx, emptyHost{})
		if err != nil {
			slog.Error("error starting traces exporter", "error", err)
			return
		}
	}

	traceAttrs, err := tr.getConstantAttributes()
	if err != nil {
		slog.Error("error selecting user trace attributes", "error", err)
		return
	}

	sampler := tr.cfg.SamplerConfig.Implementation()
	swarms.ForEachInput(ctx, tr.input, otlog().Debug, func(spans []request.Span) {
		tr.processSpans(ctx, exp, spans, traceAttrs, sampler)
	})
}

// instrumentTracesExporter checks whether the context is configured to report internal metrics and,
// in this case, wraps the passed metrics exporter inside an instrumented exporter
func instrumentTracesExporter(internalMetrics imetrics.Reporter, in exporter.Traces) exporter.Traces {
	// avoid wrapping the instrumented exporter if we don't have
	// internal instrumentation (NoopReporter)
	if _, ok := internalMetrics.(imetrics.NoopReporter); ok || internalMetrics == nil {
		return in
	}
	return &instrumentedTracesExporter{
		Traces:   in,
		internal: internalMetrics,
	}
}

//nolint:cyclop
func getTracesExporter(ctx context.Context, cfg otelcfg.TracesConfig, im imetrics.Reporter) (exporter.Traces, error) {
	// SharedTracesExporter from the unified OTLP pipeline is required
	// This follows the OpenTelemetry Collector standard
	if cfg.SharedTracesExporter != nil {
		slog.Info("using shared collector traces exporter from unified OTLP pipeline")
		return instrumentTracesExporter(im, cfg.SharedTracesExporter), nil
	}

	// TracesConsumer is allowed for testing/vendored mode
	if cfg.TracesConsumer != nil {
		slog.Debug("instantiating Consumer TracesReporter (testing/vendored mode)")
		newType, err := component.NewType("traces")
		if err != nil {
			return nil, err
		}
		set := getTraceSettings(newType, cfg.SDKLogLevel)
		exp, err := exporterhelper.NewTraces(ctx, set, cfg,
			cfg.TracesConsumer.ConsumeTraces,
			exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
		)
		if err != nil {
			return nil, err
		}
		return instrumentTracesExporter(im, exp), nil
	}

	// No fallback - shared exporter is required
	return nil, fmt.Errorf("SharedTracesExporter is required: telegen requires all signals to use the unified OTLP exporter. " +
		"Ensure the unified OTLP pipeline is initialized before starting eBPF instrumentation")
}

func getQueueConfig(cfg otelcfg.TracesConfig) configoptional.Optional[exporterhelper.QueueBatchConfig] {
	// enable batching only if the queue config is enabled
	if cfg.MaxQueueSize <= 0 && cfg.BatchTimeout <= 0 {
		return configoptional.None[exporterhelper.QueueBatchConfig]()
	}
	queueConfig := exporterhelper.NewDefaultQueueConfig()
	queueConfig.Sizer = exporterhelper.RequestSizerTypeItems
	// Avoid continuously seeing "sending queue is full" errors in the standard output
	queueConfig.BlockOnOverflow = true
	batchCfg := exporterhelper.BatchConfig{
		Sizer: queueConfig.Sizer,
	}
	batchSet := false
	if cfg.MaxQueueSize > 0 {
		batchSet = true
		batchCfg.MaxSize = int64(cfg.MaxQueueSize)
	}
	if cfg.BatchTimeout > 0 {
		batchSet = true
		batchCfg.FlushTimeout = cfg.BatchTimeout
		batchCfg.MinSize = int64(cfg.MaxQueueSize)
	}
	if batchSet {
		queueConfig.Batch = configoptional.Some(batchCfg)
	}
	return configoptional.Some(queueConfig)
}

func createZapLoggerDev(sdkLogLevel string) *zap.Logger {
	if sdkLogLevel == "" {
		return zap.NewNop()
	}

	var level zapcore.Level
	if err := level.UnmarshalText([]byte(sdkLogLevel)); err != nil {
		slog.Error("unsupported trace exporter logger level", "error", err, "level", sdkLogLevel)
		return zap.NewNop()
	}

	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(level)

	logger, err := config.Build()
	if err != nil {
		slog.Error("unable to create trace exporter logger", "error", err)
		return zap.NewNop()
	}

	return logger
}

func getTraceSettings(dataType component.Type, sdkLogLevel string) exporter.Settings {
	traceProvider := tracenoop.NewTracerProvider()
	meterProvider := metric.NewMeterProvider()

	telemetrySettings := component.TelemetrySettings{
		Logger:         createZapLoggerDev(sdkLogLevel),
		MeterProvider:  meterProvider,
		TracerProvider: traceProvider,
		Resource:       pcommon.NewResource(),
	}

	return exporter.Settings{
		ID:                component.NewIDWithName(dataType, "obi"),
		TelemetrySettings: telemetrySettings,
	}
}

func getRetrySettings(cfg otelcfg.TracesConfig) configretry.BackOffConfig {
	backOffCfg := configretry.NewDefaultBackOffConfig()
	if cfg.BackOffInitialInterval > 0 {
		backOffCfg.InitialInterval = cfg.BackOffInitialInterval
	}
	if cfg.BackOffMaxInterval > 0 {
		backOffCfg.MaxInterval = cfg.BackOffMaxInterval
	}
	if cfg.BackOffMaxElapsedTime > 0 {
		backOffCfg.MaxElapsedTime = cfg.BackOffMaxElapsedTime
	}
	return backOffCfg
}

func convertHeaders(headers map[string]string) configopaque.MapList {
	opaqueHeaders := make(configopaque.MapList, 0, len(headers))
	for key, value := range headers {
		opaqueHeaders = append(opaqueHeaders, configopaque.Pair{Name: key, Value: configopaque.String(value)})
	}
	return opaqueHeaders
}
