// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package llmtracer

import (
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/obi"
	config "github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/pkg/export/instrumentations"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/otelcfg"
)

func TestShouldSuppressLLMProviderSpan_DedupEnabled(t *testing.T) {
	tr := &Tracer{
		cfg: &obi.Config{
			Traces: otelcfg.TracesConfig{
				Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationGenAI},
			},
			EBPF: config.EBPFTracer{
				PayloadExtraction: config.PayloadExtraction{
					HTTP: config.HTTPConfig{
						GenAI: config.GenAIConfig{
							OpenAI: config.OpenAIConfig{Enabled: true},
						},
					},
				},
			},
		},
	}

	if !tr.shouldSuppressLLMProviderSpan() {
		t.Fatalf("expected llmtracer spans to be suppressed when GenAI HTTP parsing is enabled")
	}
}

func TestShouldSuppressLLMProviderSpan_DedupDisabled(t *testing.T) {
	tr := &Tracer{
		cfg: &obi.Config{
			Traces: otelcfg.TracesConfig{
				Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
			},
			EBPF: config.EBPFTracer{},
		},
	}

	if tr.shouldSuppressLLMProviderSpan() {
		t.Fatalf("did not expect llmtracer suppression when GenAI instrumentation is disabled")
	}
}
