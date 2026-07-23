// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	config "github.com/mirastacklabs-ai/telegen/internal/obiconfig"
)

func TestOpenAISpan_ParseFixture(t *testing.T) {
	base := &request.Span{Type: request.EventTypeHTTPClient}
	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", strings.NewReader(`{
		"model":"gpt-4o-mini",
		"messages":[{"role":"user","content":"hello world"}]
	}`))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Openai-Version": []string{"2020-10-01"},
			"Content-Type":   []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"id":"chatcmpl-1",
			"model":"gpt-4o-mini",
			"choices":[{"message":{"content":"hi there"}}],
			"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}
		}`)),
	}

	span, ok := OpenAISpan(base, req, resp)
	require.True(t, ok)
	require.Equal(t, request.HTTPSubtypeOpenAI, span.SubType)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.OpenAI)
	require.Equal(t, "gpt-4o-mini", span.GenAI.OpenAI.ResponseModel)
	require.Equal(t, request.ChatOperationName, span.GenAI.OpenAI.OperationName)
}

func TestAnthropicSpan_ParseFixture(t *testing.T) {
	base := &request.Span{Type: request.EventTypeHTTPClient}
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(`{
		"model":"claude-3-5-sonnet",
		"messages":[{"role":"user","content":"summarize this"}]
	}`))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Anthropic-Organization-Id": []string{"org_123"},
			"Content-Type":              []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"id":"msg_123",
			"model":"claude-3-5-sonnet",
			"role":"assistant",
			"content":[{"type":"text","text":"summary"}],
			"usage":{"input_tokens":12,"output_tokens":5}
		}`)),
	}

	span, ok := AnthropicSpan(base, req, resp)
	require.True(t, ok)
	require.Equal(t, request.HTTPSubtypeAnthropic, span.SubType)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Anthropic)
	require.Equal(t, "claude-3-5-sonnet", span.GenAI.Anthropic.Output.Model)
}

func TestGeminiSpan_ParseFixture(t *testing.T) {
	base := &request.Span{Type: request.EventTypeHTTPClient}
	req := httptest.NewRequest(
		http.MethodPost,
		"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
		strings.NewReader(`{"contents":[{"role":"user","parts":[{"text":"say hi"}]}]}`),
	)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{
			"modelVersion":"gemini-1.5-pro",
			"candidates":[{"finishReason":"STOP","content":{"parts":[{"text":"hello"}]}}]
		}`)),
	}

	span, ok := GeminiSpan(base, req, resp)
	require.True(t, ok)
	require.Equal(t, request.HTTPSubtypeGemini, span.SubType)
	require.NotNil(t, span.GenAI)
	require.NotNil(t, span.GenAI.Gemini)
	require.Equal(t, "gemini-1.5-pro", span.GenAI.Gemini.Model)
	require.Equal(t, "generate_content", span.GenAI.Gemini.Operation)
}

func TestHTTPEnrichment_ObfuscatesPromptByDefaultRule(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: mustJSONPaths(t, "$.messages[*].content"),
				},
			},
		},
	}
	enricher := NewHTTPEnricher(cfg)

	span := &request.Span{
		Method: http.MethodPost,
		Path:   "/v1/chat/completions",
	}
	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", strings.NewReader(`{
		"messages":[{"role":"user","content":"my very secret prompt"}]
	}`))
	req.Header.Set("Content-Type", "application/json")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}

	ok := enricher.Enrich(span, req, resp)
	require.True(t, ok)
	require.Contains(t, span.RequestBodyContent, "***")
	require.NotContains(t, span.RequestBodyContent, "my very secret prompt")
}

func mustJSONPaths(t *testing.T, paths ...string) []config.JSONPathExpr {
	t.Helper()
	out := make([]config.JSONPathExpr, 0, len(paths))
	for _, p := range paths {
		expr, err := config.NewJSONPathExpr(p)
		require.NoError(t, err)
		out = append(out, expr)
	}
	return out
}
