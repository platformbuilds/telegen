// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"

import "encoding/json"

// GenAI operation name constants aligned with OTel semantic conventions.
const (
	ChatOperationName        = "chat"
	CompletionOperationName  = "text_completion"
	GenerationOperationName  = "generation"
	InvokeModelOperationName = "invoke_model"
	EmbeddingOperationName   = "embeddings"
	RetrievalOperationName   = "retrieval"
	DefaultGeminiOperation   = "generate_content"
)

type GenAI struct {
	OpenAI    *VendorOpenAI
	Anthropic *VendorAnthropic
	Gemini    *VendorGemini
	Qwen      *VendorOpenAI
	Bedrock   *VendorBedrock
	MCP       *MCPCall
	Embedding *VendorEmbedding
	Rerank    *VendorRerank
	Retrieval *VendorRetrieval
}

// ToolCall represents a tool invocation requested by an LLM.
type ToolCall struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type OpenAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

type OpenAICompletionDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

type OpenAIPromptTokensDetails struct {
	CachedTokens        int `json:"cached_tokens,omitempty"`
	CacheCreationTokens int `json:"cache_creation_tokens,omitempty"`
}

type OpenAIUsage struct {
	InputTokens         int                        `json:"input_tokens"`
	OutputTokens        int                        `json:"output_tokens"`
	TotalTokens         int                        `json:"total_tokens"`
	PromptTokens        int                        `json:"prompt_tokens"`
	CompletionTokens    int                        `json:"completion_tokens"`
	CompletionDetails   *OpenAICompletionDetails   `json:"completion_tokens_details,omitempty"`
	PromptTokensDetails *OpenAIPromptTokensDetails `json:"prompt_tokens_details,omitempty"`
}

type OpenAIInput struct {
	Input          string          `json:"input"`
	Prompt         string          `json:"prompt"`
	Model          string          `json:"model"`
	Instructions   string          `json:"instructions"`
	Messages       json.RawMessage `json:"messages"`
	Items          json.RawMessage `json:"items"`
	Temperature    float64         `json:"temperature"`
	Dimensions     int             `json:"dimensions,omitempty"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	Stop           json.RawMessage `json:"stop,omitempty"`
	Stream         bool            `json:"stream,omitempty"`
	EncodingFormat string          `json:"encoding_format,omitempty"`
}

type VendorOpenAI struct {
	OperationName     string          `json:"object"`
	ResponseModel     string          `json:"model"`
	Error             OpenAIError     `json:"error"`
	ID                string          `json:"id"`
	Temperature       float64         `json:"temperature"`
	TopP              float64         `json:"top_p"`
	Usage             OpenAIUsage     `json:"usage"`
	Output            json.RawMessage `json:"output"`
	Request           OpenAIInput
	Choices           json.RawMessage `json:"choices"`
	Items             json.RawMessage `json:"items"`
	Metadata          json.RawMessage `json:"metadata"`
	Data              json.RawMessage `json:"data"`
	ServiceTier       string          `json:"service_tier,omitempty"`
	SystemFingerprint string          `json:"system_fingerprint,omitempty"`
	APIType           string          `json:"-"`
	ToolCalls         []ToolCall      `json:"-"`
}

type VendorAnthropic struct {
	Input     AnthropicRequest
	Output    AnthropicResponse
	ToolCalls []ToolCall `json:"-"`
}

type AnthropicRequest struct {
	MaxTokens     int             `json:"max_tokens"`
	Messages      json.RawMessage `json:"messages"`
	Model         string          `json:"model"`
	Stream        bool            `json:"stream"`
	System        string          `json:"system"`
	Tools         json.RawMessage `json:"tools"`
	Temperature   *float64        `json:"temperature,omitempty"`
	TopP          *float64        `json:"top_p,omitempty"`
	TopK          int             `json:"top_k,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
}

type AnthropicUsage struct {
	InputTokens              int    `json:"input_tokens"`
	OutputTokens             int    `json:"output_tokens"`
	CacheCreationInputTokens int    `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int    `json:"cache_read_input_tokens,omitempty"`
	ReasoningOutputTokens    int    `json:"reasoning_output_tokens,omitempty"`
	ServiceTier              string `json:"service_tier"`
	InferenceGeo             string `json:"inference_geo"`
}

type AnthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type AnthropicResponse struct {
	Model        string          `json:"model"`
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Role         string          `json:"role"`
	Content      json.RawMessage `json:"content"`
	StopReason   string          `json:"stop_reason"`
	StopSequence *string         `json:"stop_sequence"`
	Usage        AnthropicUsage  `json:"usage"`
	Error        *AnthropicError `json:"error,omitempty"`
	RequestID    string          `json:"request_id"`
}

type VendorGemini struct {
	Input     GeminiRequest
	Output    GeminiResponse
	Model     string
	Operation string
	IsStream  bool
	ToolCalls []ToolCall `json:"-"`
}

type GeminiRequest struct {
	Contents          json.RawMessage `json:"contents"`
	SystemInstruction *GeminiContent  `json:"systemInstruction,omitempty"`
	Tools             json.RawMessage `json:"tools,omitempty"`
	GenerationConfig  *GeminiGenCfg   `json:"generationConfig,omitempty"`
}

type GeminiContent struct {
	Parts json.RawMessage `json:"parts"`
	Role  string          `json:"role"`
}

type GeminiGenCfg struct {
	Temperature      float64  `json:"temperature"`
	TopP             float64  `json:"topP"`
	TopK             int      `json:"topK"`
	MaxOutputTokens  int      `json:"maxOutputTokens"`
	FrequencyPenalty float64  `json:"frequencyPenalty"`
	PresencePenalty  float64  `json:"presencePenalty"`
	StopSequences    []string `json:"stopSequences,omitempty"`
	CandidateCount   int      `json:"candidateCount"`
	ResponseMimeType string   `json:"responseMimeType,omitempty"`
}

type GeminiCandidate struct {
	Content      *GeminiContent `json:"content"`
	FinishReason string         `json:"finishReason"`
}

type GeminiUsage struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

type GeminiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

type GeminiResponse struct {
	Candidates    []GeminiCandidate `json:"candidates"`
	UsageMetadata GeminiUsage       `json:"usageMetadata"`
	ModelVersion  string            `json:"modelVersion"`
	ResponseID    string            `json:"responseId"`
	Error         *GeminiError      `json:"error,omitempty"`
}

type VendorBedrock struct {
	Input       BedrockRequest
	Output      BedrockResponse
	Model       string
	IsStream    bool
	GuardrailID string
}

type BedrockRequest struct {
	Messages    json.RawMessage `json:"messages,omitempty"`
	System      string          `json:"system,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
	TopP        float64         `json:"top_p,omitempty"`
	TopK        int             `json:"top_k,omitempty"`
	InputText   string          `json:"inputText,omitempty"`
	Prompt      string          `json:"prompt,omitempty"`
	Tools       json.RawMessage `json:"tools,omitempty"`
}

type BedrockUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type BedrockResponse struct {
	Content              json.RawMessage `json:"content,omitempty"`
	StopReason           string          `json:"stop_reason,omitempty"`
	Usage                *BedrockUsage   `json:"usage,omitempty"`
	Generation           string          `json:"generation,omitempty"`
	PromptTokenCount     int             `json:"prompt_token_count,omitempty"`
	GenerationTokenCount int             `json:"generation_token_count,omitempty"`
	ErrorType            string          `json:"__type,omitempty"`
	ErrorMessage         string          `json:"message,omitempty"`
	InputTokens          int             `json:"-"`
	OutputTokens         int             `json:"-"`
}

type MCPCall struct {
	Method            string `json:"method"`
	ToolName          string `json:"toolName,omitempty"`
	ToolType          string `json:"toolType,omitempty"`
	ToolCallArguments string `json:"toolCallArguments,omitempty"`
	ToolCallResult    string `json:"toolCallResult,omitempty"`
	ResourceURI       string `json:"resourceUri,omitempty"`
	PromptName        string `json:"promptName,omitempty"`
	SessionID         string `json:"sessionId,omitempty"`
	ProtocolVer       string `json:"protocolVer,omitempty"`
	RequestID         string `json:"requestId,omitempty"`
	ErrorCode         int    `json:"errorCode,omitempty"`
	ErrorMessage      string `json:"errorMessage,omitempty"`
}

type VendorEmbedding struct {
	Provider string
	Model    string
	Input    EmbeddingRequest
	Output   EmbeddingResponse
}

type EmbeddingRequest struct {
	Model      string          `json:"model"`
	Input      json.RawMessage `json:"input"`
	Dimensions int             `json:"dimensions,omitempty"`
	Texts      json.RawMessage `json:"texts,omitempty"`
}

type EmbeddingUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

type EmbeddingResponse struct {
	Model string         `json:"model"`
	Usage EmbeddingUsage `json:"usage"`
}

type VendorRerank struct {
	Input    RerankRequest
	Output   RerankResponse
	Provider string
}

type RerankRequest struct {
	Model     string          `json:"model"`
	Query     string          `json:"query"`
	TopN      int             `json:"top_n"`
	Documents json.RawMessage `json:"documents"`
}

type RerankUsage struct {
	TotalTokens  int `json:"total_tokens"`
	PromptTokens int `json:"prompt_tokens"`
	SearchUnits  int `json:"search_units"`
}

type RerankResponse struct {
	ID      string          `json:"id"`
	Model   string          `json:"model"`
	Results json.RawMessage `json:"results"`
	Usage   RerankUsage     `json:"usage"`
}

type VendorRetrieval struct {
	Provider string
	Input    RetrievalRequest
	Output   RetrievalResponse
}

type RetrievalRequest struct {
	Model           string `json:"model,omitempty"`
	Collection      string `json:"collection,omitempty"`
	CollectionName  string `json:"collectionName,omitempty"`
	CollectionSnake string `json:"collection_name,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	TopK            int    `json:"topK,omitempty"`
	TopKSnake       int    `json:"top_k,omitempty"`
	Limit           int    `json:"limit,omitempty"`
}

type RetrievalUsage struct {
	TotalTokens  int `json:"total_tokens,omitempty"`
	PromptTokens int `json:"prompt_tokens,omitempty"`
}

type RetrievalResponse struct {
	ID    string         `json:"id,omitempty"`
	Model string         `json:"model,omitempty"`
	Usage RetrievalUsage `json:"usage,omitempty"`
}
