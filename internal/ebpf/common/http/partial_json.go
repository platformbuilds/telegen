// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
)

func looksLikeJSON(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

func readHTTPRequestBody(component string, req *http.Request, baseSpan *request.Span, emptyLogAttrs ...any) ([]byte, bool) {
	if req == nil || req.Body == nil {
		slog.Debug(component+": missing request body", emptyLogAttrs...)
		return nil, false
	}
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		slog.Debug(component+": failed reading request body", "err", err, "path", baseSpan.Path)
		return nil, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, true
}

func readHTTPResponseBody(component string, resp *http.Response, baseSpan *request.Span, emptyLogAttrs ...any) ([]byte, bool) {
	if resp == nil || resp.Body == nil {
		slog.Debug(component+": missing response body", emptyLogAttrs...)
		return nil, false
	}
	body, err := getResponseBody(resp)
	if err != nil {
		slog.Debug(component+": failed reading response body", "err", err, "path", baseSpan.Path)
		return nil, false
	}
	return body, true
}

func parseOpenAIInput(body []byte) request.OpenAIInput {
	var parsed request.OpenAIInput
	_ = json.Unmarshal(body, &parsed)
	return parsed
}

func parseVendorOpenAI(body []byte) request.VendorOpenAI {
	var parsed request.VendorOpenAI
	_ = json.Unmarshal(body, &parsed)
	return parsed
}

func parseAnthropicRequest(body []byte) request.AnthropicRequest {
	var parsed request.AnthropicRequest
	_ = json.Unmarshal(body, &parsed)
	return parsed
}

func parseAnthropicResponse(body []byte) request.AnthropicResponse {
	var parsed request.AnthropicResponse
	_ = json.Unmarshal(body, &parsed)
	return parsed
}

func parseEmbeddingRequest(body []byte) request.EmbeddingRequest {
	var parsed request.EmbeddingRequest
	_ = json.Unmarshal(body, &parsed)
	return parsed
}
