// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumenter

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/obi"
	"github.com/mirastacklabs-ai/telegen/internal/transform"
	"github.com/mirastacklabs-ai/telegen/pkg/export/connector"
	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/global"
)

func TestServiceNameTemplate(t *testing.T) {
	cfg := &obi.Config{
		Attributes: obi.Attributes{
			Kubernetes: transform.KubernetesDecorator{
				ServiceNameTemplate: "{{asdf}}",
			},
		},
	}

	temp, err := buildServiceNameTemplate(cfg)
	assert.Nil(t, temp)
	if assert.Error(t, err) {
		assert.Equal(t, `unable to parse service name template: template: serviceNameTemplate:1: function "asdf" not defined`, err.Error())
	}

	cfg.Attributes.Kubernetes.ServiceNameTemplate = `{{- if eq .Meta.Pod nil }}{{.Meta.Name}}{{ else }}{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}{{ if .ContainerName }}/{{ .ContainerName -}}{{ end -}}{{ end -}}`
	temp, err = buildServiceNameTemplate(cfg)

	require.NoError(t, err)
	assert.NotNil(t, temp)

	cfg.Attributes.Kubernetes.ServiceNameTemplate = ""
	temp, err = buildServiceNameTemplate(cfg)
	require.NoError(t, err)
	assert.Nil(t, temp)
}

func TestInternalMetricsReporterSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		configure   func(*obi.Config)
		assertion   func(t *testing.T, reporter imetrics.Reporter, cfg *obi.Config)
		description string
	}{
		{
			name: "uses shared registry when prometheus exporter has zero port",
			configure: func(cfg *obi.Config) {
				cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
				cfg.InternalMetrics.Prometheus.Port = 0
				cfg.InternalMetrics.Registry = prometheus.NewRegistry()
			},
			assertion: func(t *testing.T, reporter imetrics.Reporter, cfg *obi.Config) {
				t.Helper()
				_, ok := reporter.(*imetrics.PrometheusReporter)
				require.True(t, ok, "expected Prometheus reporter in registry mode")

				metricFamilies, err := cfg.InternalMetrics.Registry.Gather()
				require.NoError(t, err)
				require.NotEmpty(t, metricFamilies, "expected shared registry to contain internal metrics")
			},
		},
		{
			name: "uses manager-backed reporter when explicit prometheus port is set",
			configure: func(cfg *obi.Config) {
				cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
				cfg.InternalMetrics.Prometheus.Port = 29091
				cfg.InternalMetrics.Prometheus.Path = "/internal/metrics"
				cfg.InternalMetrics.Registry = nil
			},
			assertion: func(t *testing.T, reporter imetrics.Reporter, _ *obi.Config) {
				t.Helper()
				_, ok := reporter.(*imetrics.PrometheusReporter)
				require.True(t, ok, "expected Prometheus reporter for explicit listener mode")
			},
		},
		{
			name: "keeps disabled exporter as noop even when registry is injected",
			configure: func(cfg *obi.Config) {
				cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterDisabled
				cfg.InternalMetrics.Prometheus.Port = 0
				cfg.InternalMetrics.Registry = prometheus.NewRegistry()
			},
			assertion: func(t *testing.T, reporter imetrics.Reporter, _ *obi.Config) {
				t.Helper()
				_, ok := reporter.(imetrics.NoopReporter)
				require.True(t, ok, "expected noop reporter when exporter is disabled")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &obi.Config{}
			tc.configure(cfg)

			reporter, err := internalMetrics(
				context.Background(),
				cfg,
				&global.ContextInfo{},
				&connector.PrometheusManager{},
			)
			require.NoError(t, err)

			tc.assertion(t, reporter, cfg)
		})
	}
}
