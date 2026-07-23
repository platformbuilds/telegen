// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common/http"

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
)

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

func extractOpenAIToolCalls(choices json.RawMessage) []request.ToolCall {
	if len(choices) == 0 {
		return nil
	}
	var parsed []struct {
		Message struct {
			ToolCalls []openAIToolCall `json:"tool_calls"`
		} `json:"message"`
	}
	if err := json.Unmarshal(choices, &parsed); err != nil {
		return nil
	}

	var out []request.ToolCall
	for _, choice := range parsed {
		for _, tc := range choice.Message.ToolCalls {
			if tc.Function.Name == "" {
				continue
			}
			out = append(out, request.ToolCall{ID: tc.ID, Name: tc.Function.Name})
		}
	}
	return out
}

func parseOpenAICompatibleResponse(respB []byte) (*request.VendorOpenAI, []request.ToolCall) {
	resp := parseVendorOpenAI(respB)
	return &resp, extractOpenAIToolCalls(resp.Choices)
}

func OpenAISpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}

	host := strings.ToLower(req.Host)
	if !strings.Contains(host, "openai.com") && resp.Header.Get("Openai-Version") == "" {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("OpenAISpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}
	respB, ok := readHTTPResponseBody("OpenAISpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	parsedRequest := parseOpenAIInput(reqB)
	parsedResponse, toolCalls := parseOpenAICompatibleResponse(respB)
	parsedResponse.Request = parsedRequest
	parsedResponse.ToolCalls = toolCalls
	if parsedResponse.ResponseModel == "" {
		parsedResponse.ResponseModel = parsedRequest.Model
	}

	path := strings.TrimSuffix(requestPath(req), "/")
	switch path {
	case "/v1/chat/completions":
		parsedResponse.OperationName = request.ChatOperationName
	case "/v1/embeddings":
		parsedResponse.OperationName = request.EmbeddingOperationName
	default:
		parsedResponse.OperationName = request.ChatOperationName
	}

	baseSpan.SubType = request.HTTPSubtypeOpenAI
	baseSpan.GenAI = &request.GenAI{OpenAI: parsedResponse}
	return *baseSpan, true
}

func AnthropicSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}
	host := strings.ToLower(req.Host)
	if !strings.Contains(host, "anthropic.com") && resp.Header.Get("Anthropic-Organization-Id") == "" {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("AnthropicSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}
	respB, ok := readHTTPResponseBody("AnthropicSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	parsedRequest := parseAnthropicRequest(reqB)
	parsedResponse := parseAnthropicResponse(respB)

	baseSpan.SubType = request.HTTPSubtypeAnthropic
	baseSpan.GenAI = &request.GenAI{
		Anthropic: &request.VendorAnthropic{
			Input:  parsedRequest,
			Output: parsedResponse,
		},
	}
	return *baseSpan, true
}

func GeminiSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}
	host := strings.ToLower(req.Host)
	if !strings.Contains(host, "generativelanguage.googleapis.com") && !strings.Contains(host, "googleapis.com") {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("GeminiSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}
	respB, ok := readHTTPResponseBody("GeminiSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	var in request.GeminiRequest
	var out request.GeminiResponse
	_ = json.Unmarshal(reqB, &in)
	_ = json.Unmarshal(respB, &out)

	model := modelFromGeminiPath(requestPath(req))
	baseSpan.SubType = request.HTTPSubtypeGemini
	baseSpan.GenAI = &request.GenAI{
		Gemini: &request.VendorGemini{
			Input:     in,
			Output:    out,
			Model:     model,
			Operation: geminiOperationFromPath(requestPath(req)),
			IsStream:  strings.Contains(requestPath(req), "streamGenerateContent"),
		},
	}
	return *baseSpan, true
}

func modelFromGeminiPath(path string) string {
	const marker = "/models/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return ""
	}
	path = path[idx+len(marker):]
	if slash := strings.IndexByte(path, ':'); slash >= 0 {
		return path[:slash]
	}
	if slash := strings.IndexByte(path, '/'); slash >= 0 {
		return path[:slash]
	}
	return path
}

func geminiOperationFromPath(path string) string {
	switch {
	case strings.Contains(path, "streamGenerateContent"):
		return "stream_generate_content"
	case strings.Contains(path, "generateContent"):
		return "generate_content"
	default:
		return request.DefaultGeminiOperation
	}
}

func BedrockSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}
	host := strings.ToLower(req.Host)
	if !strings.Contains(host, "bedrock") {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("BedrockSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}
	respB, ok := readHTTPResponseBody("BedrockSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	var in request.BedrockRequest
	var out request.BedrockResponse
	_ = json.Unmarshal(reqB, &in)
	_ = json.Unmarshal(respB, &out)

	out.InputTokens = atoiHeader(resp.Header.Get("x-amzn-bedrock-input-token-count"))
	out.OutputTokens = atoiHeader(resp.Header.Get("x-amzn-bedrock-output-token-count"))

	baseSpan.SubType = request.HTTPSubtypeAWSBedrock
	baseSpan.GenAI = &request.GenAI{
		Bedrock: &request.VendorBedrock{
			Input:       in,
			Output:      out,
			Model:       modelFromBedrockPath(requestPath(req)),
			IsStream:    strings.Contains(requestPath(req), "invoke-with-response-stream"),
			GuardrailID: resp.Header.Get("x-amzn-bedrock-guardrail-identifier"),
		},
	}
	return *baseSpan, true
}

func modelFromBedrockPath(path string) string {
	parts := strings.Split(path, "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "model" && parts[i+1] != "" {
			return parts[i+1]
		}
	}
	return ""
}

func QwenSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}
	host := strings.ToLower(req.Host)
	if !strings.Contains(host, "dashscope") && !strings.Contains(host, "qwen") {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("QwenSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}
	respB, ok := readHTTPResponseBody("QwenSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	in := parseOpenAIInput(reqB)
	out, toolCalls := parseOpenAICompatibleResponse(respB)
	out.Request = in
	out.ToolCalls = toolCalls
	out.OperationName = qwenOperationName(requestPath(req))

	baseSpan.SubType = request.HTTPSubtypeQwen
	baseSpan.GenAI = &request.GenAI{Qwen: out}
	return *baseSpan, true
}

func qwenOperationName(path string) string {
	switch {
	case strings.Contains(path, "/chat/completions"):
		return request.ChatOperationName
	case strings.Contains(path, "/completions"):
		return request.CompletionOperationName
	case strings.Contains(path, "/embeddings"):
		return request.EmbeddingOperationName
	default:
		return request.GenerationOperationName
	}
}

func EmbeddingSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}
	path := strings.ToLower(requestPath(req))
	if !strings.Contains(path, "embed") && !strings.Contains(path, "embeddings") {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("EmbeddingSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}
	respB, ok := readHTTPResponseBody("EmbeddingSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	var out request.EmbeddingResponse
	_ = json.Unmarshal(respB, &out)
	in := parseEmbeddingRequest(reqB)

	baseSpan.SubType = request.HTTPSubtypeEmbedding
	baseSpan.GenAI = &request.GenAI{
		Embedding: &request.VendorEmbedding{
			Provider: strings.ToLower(req.Host),
			Model:    in.Model,
			Input:    in,
			Output:   out,
		},
	}
	return *baseSpan, true
}

func RerankSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}
	path := strings.ToLower(requestPath(req))
	if !strings.Contains(path, "rerank") {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("RerankSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}
	respB, ok := readHTTPResponseBody("RerankSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	var in request.RerankRequest
	var out request.RerankResponse
	_ = json.Unmarshal(reqB, &in)
	_ = json.Unmarshal(respB, &out)

	baseSpan.SubType = request.HTTPSubtypeRerank
	baseSpan.GenAI = &request.GenAI{
		Rerank: &request.VendorRerank{
			Provider: strings.ToLower(req.Host),
			Input:    in,
			Output:   out,
		},
	}
	return *baseSpan, true
}

func RetrievalSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}
	path := strings.ToLower(requestPath(req))
	if !strings.Contains(path, "query") && !strings.Contains(path, "search") && !strings.Contains(path, "retrieve") {
		return *baseSpan, false
	}

	reqB, ok := readHTTPRequestBody("RetrievalSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}
	respB, ok := readHTTPResponseBody("RetrievalSpan", resp, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	var in request.RetrievalRequest
	var out request.RetrievalResponse
	_ = json.Unmarshal(reqB, &in)
	_ = json.Unmarshal(respB, &out)

	baseSpan.SubType = request.HTTPSubtypeRetrieval
	baseSpan.GenAI = &request.GenAI{
		Retrieval: &request.VendorRetrieval{
			Provider: strings.ToLower(req.Host),
			Input:    in,
			Output:   out,
		},
	}
	return *baseSpan, true
}

func MCPSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req == nil || resp == nil {
		return *baseSpan, false
	}
	reqB, ok := readHTTPRequestBody("MCPSpan", req, baseSpan)
	if !ok {
		return *baseSpan, false
	}

	var rpcReq struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(reqB, &rpcReq); err != nil || rpcReq.JSONRPC != "2.0" || rpcReq.Method == "" {
		return *baseSpan, false
	}

	result := &request.MCPCall{
		Method:    rpcReq.Method,
		SessionID: req.Header.Get("Mcp-Session-Id"),
	}
	if len(rpcReq.ID) > 0 && string(rpcReq.ID) != "null" {
		result.RequestID = strings.Trim(string(rpcReq.ID), "\"")
	}

	respB, ok := readHTTPResponseBody("MCPSpan", resp, baseSpan)
	if ok {
		var rpcResp struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(respB, &rpcResp) == nil && rpcResp.Error != nil {
			result.ErrorCode = rpcResp.Error.Code
			result.ErrorMessage = rpcResp.Error.Message
		}
	}

	baseSpan.SubType = request.HTTPSubtypeMCP
	baseSpan.GenAI = &request.GenAI{MCP: result}
	return *baseSpan, true
}

func atoiHeader(v string) int {
	i, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0
	}
	return i
}
